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
 * Merges IP and Host when known, distinguishes internal vs external roles, and aggregates edges.
 */
export function buildGraphFromEvents(events: NormalizedEvent[]): AttackGraphData {
  const nodeMap = new Map<string, GraphNode>();
  const edgeMap = new Map<string, GraphEdge>();
  const ipToHost = new Map<string, string>();

  if (!Array.isArray(events) || events.length === 0) {
    return { nodes: [], edges: [] };
  }

  // Pre-seed known subnet host mappings
  const subnetMap: Record<string, string> = {
    '10.20.1.12': 'WS-HR-12',
    '10.20.2.2': 'DC-01',
    '10.20.2.5': 'SRV-FS-02',
    '10.20.2.20': 'SRV-BKP-01',
    '10.20.2.30': 'WS-ACC-03',
  };
  Object.entries(subnetMap).forEach(([ip, h]) => ipToHost.set(ip, h));

  // Pass 1: Build IP-to-host mapping from records with both
  for (const evt of events) {
    const h = evt.host && evt.host !== 'unknown_host' ? evt.host : null;
    if (h && evt.src_ip && isPrivateIp(evt.src_ip)) {
      ipToHost.set(evt.src_ip, h);
    }
  }

  // Pass 2: Build graph entities and aggregated edges
  for (const evt of events) {
    if (!evt) continue;

    const isAttack = Boolean(
      evt.is_attack_path ||
      evt.severity === 'critical' ||
      evt.severity === 'high' ||
      /fail|error|attack|malware|shell|sudo|privilege|brute|inject|drop|unauthorized|cvlk|rclone|psexec|lsass|comsvcs/i.test(
        String(evt.action || '') + ' ' + String(evt.mitre_technique || '')
      )
    );

    // Resolve effective host (merge private IP if known)
    let effectiveHost = evt.host && evt.host !== 'unknown_host' ? evt.host : null;
    if (!effectiveHost && evt.src_ip && ipToHost.has(evt.src_ip)) {
      effectiveHost = ipToHost.get(evt.src_ip)!;
    }

    // 1. Host Node
    if (effectiveHost) {
      const hostId = `host-${effectiveHost}`;
      if (!nodeMap.has(hostId)) {
        nodeMap.set(hostId, {
          id: hostId,
          label: effectiveHost,
          type: 'host',
          is_compromised: isAttack,
          is_attack_path: isAttack,
          event_count: 1,
          first_seen: evt.timestamp,
          last_seen: evt.timestamp,
          events: [evt.id]
        });
      } else {
        const node = nodeMap.get(hostId)!;
        node.event_count++;
        if (isAttack) {
          node.is_compromised = true;
          node.is_attack_path = true;
        }
        node.last_seen = evt.timestamp;
      }
    }

    // 2. User Node (only from actual user accounts)
    if (evt.user && evt.user !== 'unknown' && evt.user !== 'SYSTEM' && evt.user !== '-') {
      const userId = `user-${evt.user}`;
      if (!nodeMap.has(userId)) {
        nodeMap.set(userId, {
          id: userId,
          label: `user: ${evt.user}`,
          type: 'user',
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
        if (isAttack) {
          node.is_compromised = true;
          node.is_attack_path = true;
        }
        node.last_seen = evt.timestamp;
      }

      // Edge: user -> host
      if (effectiveHost) {
        const hostId = `host-${effectiveHost}`;
        const edgeId = `edge-${userId}-${hostId}`;
        if (!edgeMap.has(edgeId)) {
          edgeMap.set(edgeId, {
            id: edgeId,
            source: userId,
            target: hostId,
            label: 'Logon / Activity',
            timestamp: evt.timestamp,
            count: 1,
            is_attack_path: isAttack,
            severity: evt.severity || 'low',
            event_ids: [evt.id]
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
        srcNodeId = `ip-${evt.src_ip}`;
        if (!nodeMap.has(srcNodeId)) {
          nodeMap.set(srcNodeId, {
            id: srcNodeId,
            label: evt.src_ip,
            type: isPriv ? 'host' : 'ip',
            is_compromised: isAttack,
            is_attack_path: isAttack,
            event_count: 1,
            first_seen: evt.timestamp,
            last_seen: evt.timestamp,
            events: [evt.id]
          });
        } else {
          const node = nodeMap.get(srcNodeId)!;
          node.event_count++;
          if (isAttack) {
            node.is_compromised = true;
            node.is_attack_path = true;
          }
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
        dstNodeId = `ip-${evt.dst_ip}`;
        if (!nodeMap.has(dstNodeId)) {
          nodeMap.set(dstNodeId, {
            id: dstNodeId,
            label: evt.dst_ip,
            type: isPriv ? 'host' : 'ip',
            is_compromised: isAttack && !isPriv,
            is_attack_path: isAttack,
            event_count: 1,
            first_seen: evt.timestamp,
            last_seen: evt.timestamp,
            events: [evt.id]
          });
        } else {
          const node = nodeMap.get(dstNodeId)!;
          node.event_count++;
          if (isAttack) node.is_attack_path = true;
        }
      }
    }

    // Connect Source -> Destination (Aggregate Network Flow)
    if (srcNodeId && dstNodeId && srcNodeId !== dstNodeId) {
      const edgeId = `edge-${srcNodeId}-${dstNodeId}`;
      const protoPort = `${evt.protocol || 'TCP'}/${evt.dst_port || 443}`;
      if (!edgeMap.has(edgeId)) {
        edgeMap.set(edgeId, {
          id: edgeId,
          source: srcNodeId,
          target: dstNodeId,
          label: protoPort,
          protocol: evt.protocol,
          timestamp: evt.timestamp,
          count: 1,
          is_attack_path: isAttack,
          severity: evt.severity || 'low',
          event_ids: [evt.id]
        });
      } else {
        const edge = edgeMap.get(edgeId)!;
        edge.count++;
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

