import { NormalizedEvent, AttackGraphData, GraphNode, GraphEdge } from '../types';

function isPrivateIp(ipStr: string): boolean {
  const ip = ipStr.trim();
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.')) return true;
  if (ip.startsWith('172.')) {
    const parts = ip.split('.');
    const second = Number(parts[1]);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

/**
 * Builds nodes and directional relationship edges for Cytoscape / Canvas rendering (Stage 7).
 *
 * B2 fix: IP-to-host merging is purely evidence-derived — no hardcoded subnet maps.
 * B3 fix: adversary vs victim classification is based on is_attack_path AND
 *         whether the node is a source (adversary) or target (victim/compromised).
 *         External addresses that merely appear in normal traffic are NOT marked adversary.
 */
export function buildGraphFromEvents(events: NormalizedEvent[]): AttackGraphData {
  const nodeMap = new Map<string, GraphNode>();
  const edgeMap = new Map<string, GraphEdge>();
  // B2: evidence-derived IP-to-host mapping only
  const ipToHost = new Map<string, string>();

  if (!Array.isArray(events) || events.length === 0) {
    return { nodes: [], edges: [] };
  }

  // B3: Track which external IPs are sources of attack events (adversary infra)
  // and which internal hosts are targets (compromised)
  const adversaryIps = new Set<string>();
  const compromisedHosts = new Set<string>();

  // B2 Pass 1: Build IP-to-host mapping from evidence (no pre-seeded data)
  for (const evt of events) {
    const h = evt.host && evt.host !== 'unknown_host' ? evt.host : null;
    if (h && evt.src_ip && isPrivateIp(evt.src_ip)) {
      ipToHost.set(evt.src_ip, h);
    }
  }

  // B3 Pass: Classify adversary vs compromised from attack-path events
  for (const evt of events) {
    if (!evt.is_attack_path) continue;
    // External source of attack → adversary infrastructure
    if (evt.src_ip && !isPrivateIp(evt.src_ip)) {
      adversaryIps.add(evt.src_ip);
    }
    // Internal host that is a target → compromised
    const effectiveHost = evt.host && evt.host !== 'unknown_host' ? evt.host : null;
    if (effectiveHost) {
      // The host is the victim/target, NOT the attacker
      const hostIsAttacker = evt.src_ip === effectiveHost;
      if (!hostIsAttacker) {
        compromisedHosts.add(effectiveHost);
      }
    }
    // External destination of C2/exfil → adversary infra
    if (evt.dst_ip && !isPrivateIp(evt.dst_ip) &&
        (evt.mitre_tactic === 'Command and Control' || evt.mitre_tactic === 'Exfiltration' || evt.mitre_tactic === 'Impact')) {
      adversaryIps.add(evt.dst_ip);
    }
  }

  // Pass 2: Build graph entities
  for (const evt of events) {
    if (!evt) continue;

    const isAttack = Boolean(evt.is_attack_path || evt.severity === 'critical' || evt.severity === 'high');

    let effectiveHost = evt.host && evt.host !== 'unknown_host' ? evt.host : null;
    if (!effectiveHost && evt.src_ip && ipToHost.has(evt.src_ip)) {
      effectiveHost = ipToHost.get(evt.src_ip)!;
    }

    // 1. Host Node
    if (effectiveHost) {
      const hostId = `host-${effectiveHost}`;
      const isComp = compromisedHosts.has(effectiveHost);
      if (!nodeMap.has(hostId)) {
        nodeMap.set(hostId, {
          id: hostId,
          label: effectiveHost,
          type: 'host',
          role: isComp ? 'compromised_host' : 'internal_host',
          is_compromised: isComp,
          is_attack_path: isAttack,
          event_count: 1,
          first_seen: evt.timestamp,
          last_seen: evt.timestamp,
          events: [evt.id]
        });
      } else {
        const node = nodeMap.get(hostId)!;
        node.event_count++;
        if (isComp) { node.is_compromised = true; node.role = 'compromised_host'; }
        if (isAttack) node.is_attack_path = true;
        node.last_seen = evt.timestamp;
      }
    }

    // 2. User Node
    if (evt.user && evt.user !== 'unknown' && evt.user !== 'SYSTEM' && evt.user !== '-') {
      const userId = `user-${evt.user}`;
      if (!nodeMap.has(userId)) {
        nodeMap.set(userId, {
          id: userId,
          label: `user: ${evt.user}`,
          type: 'user',
          role: isAttack ? 'compromised_account' : 'user_account',
          is_compromised: isAttack,
          is_attack_path: isAttack,
          event_count: 1,
          first_seen: evt.timestamp,
          last_seen: evt.timestamp,
          events: [evt.id]
        });
      } else {
        const node = nodeMap.get(userId)!;
        node.event_count++;
        if (isAttack) { node.is_compromised = true; node.is_attack_path = true; }
        node.last_seen = evt.timestamp;
      }

      if (effectiveHost) {
        const hostId = `host-${effectiveHost}`;
        const edgeId = `edge-${userId}-${hostId}`;
        if (!edgeMap.has(edgeId)) {
          edgeMap.set(edgeId, {
            id: edgeId, source: userId, target: hostId,
            label: 'Logon / Activity', timestamp: evt.timestamp,
            count: 1, is_attack_path: isAttack, severity: evt.severity || 'low', event_ids: [evt.id]
          });
        } else {
          const edge = edgeMap.get(edgeId)!;
          edge.count++;
          edge.label = `Logon x${edge.count}`;
          if (isAttack) edge.is_attack_path = true;
        }
      }
    }

    // 3. Source IP
    let srcNodeId: string | null = null;
    if (evt.src_ip) {
      if (ipToHost.has(evt.src_ip)) {
        srcNodeId = `host-${ipToHost.get(evt.src_ip)}`;
      } else {
        const isPriv = isPrivateIp(evt.src_ip);
        const isAdversary = adversaryIps.has(evt.src_ip);
        srcNodeId = `ip-${evt.src_ip}`;
        if (!nodeMap.has(srcNodeId)) {
          nodeMap.set(srcNodeId, {
            id: srcNodeId,
            label: evt.src_ip,
            type: isPriv ? 'host' : 'ip',
            role: isAdversary ? 'adversary_infrastructure' : (isPriv ? 'internal_host' : 'external_ip'),
            is_compromised: isAdversary,
            is_attack_path: isAttack,
            event_count: 1,
            first_seen: evt.timestamp,
            last_seen: evt.timestamp,
            events: [evt.id]
          });
        } else {
          const node = nodeMap.get(srcNodeId)!;
          node.event_count++;
          if (isAdversary) { node.is_compromised = true; node.role = 'adversary_infrastructure'; }
          if (isAttack) node.is_attack_path = true;
        }
      }
    }

    // 4. Destination IP
    let dstNodeId: string | null = null;
    if (evt.dst_ip) {
      if (ipToHost.has(evt.dst_ip)) {
        dstNodeId = `host-${ipToHost.get(evt.dst_ip)}`;
      } else {
        const isPriv = isPrivateIp(evt.dst_ip);
        const isAdversaryDst = adversaryIps.has(evt.dst_ip);
        dstNodeId = `ip-${evt.dst_ip}`;
        if (!nodeMap.has(dstNodeId)) {
          nodeMap.set(dstNodeId, {
            id: dstNodeId,
            label: evt.dst_ip,
            type: isPriv ? 'host' : 'ip',
            role: isAdversaryDst ? 'adversary_infrastructure' : (isPriv ? 'internal_host' : 'external_ip'),
            is_compromised: isAdversaryDst,
            is_attack_path: isAttack,
            event_count: 1,
            first_seen: evt.timestamp,
            last_seen: evt.timestamp,
            events: [evt.id]
          });
        } else {
          const node = nodeMap.get(dstNodeId)!;
          node.event_count++;
          if (isAdversaryDst) { node.is_compromised = true; node.role = 'adversary_infrastructure'; }
          if (isAttack) node.is_attack_path = true;
        }
      }
    }

    // Connect Source -> Destination (aggregated)
    if (srcNodeId && dstNodeId && srcNodeId !== dstNodeId) {
      const edgeId = `edge-${srcNodeId}-${dstNodeId}`;
      const protoPort = `${evt.protocol || 'TCP'}/${evt.dst_port || 443}`;
      if (!edgeMap.has(edgeId)) {
        edgeMap.set(edgeId, {
          id: edgeId, source: srcNodeId, target: dstNodeId,
          label: protoPort, protocol: evt.protocol,
          timestamp: evt.timestamp, count: 1,
          is_attack_path: isAttack, severity: evt.severity || 'low', event_ids: [evt.id]
        });
      } else {
        const edge = edgeMap.get(edgeId)!;
        edge.count++;
        // B3: aggregate label: "TCP/443 x25"
        edge.label = `${protoPort} x${edge.count}`;
        if (isAttack) edge.is_attack_path = true;
      }
    }
  }

  return {
    nodes: Array.from(nodeMap.values()),
    edges: Array.from(edgeMap.values())
  };
}
