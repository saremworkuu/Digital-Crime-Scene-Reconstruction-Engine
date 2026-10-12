import { NormalizedEvent, AttackGraphData, GraphNode, GraphEdge } from '../types';

/**
 * Builds nodes and directional relationship edges for Cytoscape / Canvas rendering (FR-GRAPH-1 to FR-GRAPH-6)
 */
export function buildGraphFromEvents(events: NormalizedEvent[]): AttackGraphData {
  const nodeMap = new Map<string, GraphNode>();
  const edgeMap = new Map<string, GraphEdge>();

  for (const evt of events) {
    const isAttack = Boolean(evt.is_attack_path || evt.severity === 'critical' || evt.severity === 'high');

    // Host node
    if (evt.host) {
      const hostId = `host-${evt.host}`;
      if (!nodeMap.has(hostId)) {
        nodeMap.set(hostId, {
          id: hostId,
          label: evt.host,
          type: 'host',
          is_compromised: isAttack,
          is_attack_path: isAttack,
          event_count: 1,
          first_seen: evt.timestamp,
          last_seen: evt.timestamp
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

    // User node
    if (evt.user && evt.user !== 'unknown' && evt.user !== 'SYSTEM') {
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
          last_seen: evt.timestamp
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

      // Edge between user and host
      if (evt.host) {
        const hostId = `host-${evt.host}`;
        const edgeId = `edge-${userId}-${hostId}`;
        if (!edgeMap.has(edgeId)) {
          edgeMap.set(edgeId, {
            id: edgeId,
            source: userId,
            target: hostId,
            label: evt.action.length > 25 ? evt.action.slice(0, 25) + '...' : evt.action,
            timestamp: evt.timestamp,
            count: 1,
            is_attack_path: isAttack,
            severity: evt.severity
          });
        } else {
          edgeMap.get(edgeId)!.count++;
        }
      }
    }

    // IP nodes (external or internal)
    if (evt.src_ip) {
      const ipId = `ip-${evt.src_ip}`;
      if (!nodeMap.has(ipId)) {
        nodeMap.set(ipId, {
          id: ipId,
          label: evt.src_ip,
          type: 'ip',
          is_compromised: isAttack,
          is_attack_path: isAttack,
          event_count: 1,
          first_seen: evt.timestamp,
          last_seen: evt.timestamp
        });
      } else {
        const node = nodeMap.get(ipId)!;
        node.event_count++;
        if (isAttack) {
          node.is_compromised = true;
          node.is_attack_path = true;
        }
      }

      // Edge between src_ip and host or dst_ip
      if (evt.dst_ip) {
        const dstId = `ip-${evt.dst_ip}`;
        if (!nodeMap.has(dstId)) {
          nodeMap.set(dstId, {
            id: dstId,
            label: evt.dst_ip,
            type: 'ip',
            is_compromised: isAttack,
            is_attack_path: isAttack,
            event_count: 1
          });
        }
        const edgeId = `edge-${ipId}-${dstId}`;
        if (!edgeMap.has(edgeId)) {
          edgeMap.set(edgeId, {
            id: edgeId,
            source: ipId,
            target: dstId,
            label: evt.protocol ? `${evt.protocol}/${evt.dst_port || ''}` : evt.action,
            protocol: evt.protocol,
            timestamp: evt.timestamp,
            count: 1,
            is_attack_path: isAttack,
            severity: evt.severity
          });
        } else {
          edgeMap.get(edgeId)!.count++;
        }
      } else if (evt.host) {
        const hostId = `host-${evt.host}`;
        const edgeId = `edge-${ipId}-${hostId}`;
        if (!edgeMap.has(edgeId)) {
          edgeMap.set(edgeId, {
            id: edgeId,
            source: ipId,
            target: hostId,
            label: evt.action.length > 20 ? evt.action.slice(0, 20) + '...' : evt.action,
            timestamp: evt.timestamp,
            count: 1,
            is_attack_path: isAttack,
            severity: evt.severity
          });
        } else {
          edgeMap.get(edgeId)!.count++;
        }
      }
    }
  }

  return {
    nodes: Array.from(nodeMap.values()),
    edges: Array.from(edgeMap.values())
  };
}
