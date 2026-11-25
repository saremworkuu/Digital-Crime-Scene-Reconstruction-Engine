import { DetectionResult, GraphEdge, GraphNode, NormalizedEvent } from '../types';

export type VisualNodeRole =
  | 'victim_host'
  | 'internal_host'
  | 'user'
  | 'attacker_c2'
  | 'payload_host'
  | 'exfil_destination'
  | 'mining_pool'
  | 'benign_external'
  | 'benign_external_group';

export const BENIGN_EXTERNAL_GROUP_ID = 'group-benign-external';

const PRIVATE_IP_RE = /^(?:10\.|192\.168\.|127\.|::1$|fc|fd|fe80:)/i;
const RFC1918_172_RE = /^172\.(1[6-9]|2\d|3[01])\./;
const IPV4_URL_HOST_RE = /https?:\/\/([a-zA-Z0-9.-]+)(?::\d+)?/g;

export function isPrivateIpAddress(value: string): boolean {
  const s = value.trim();
  return PRIVATE_IP_RE.test(s) || RFC1918_172_RE.test(s);
}

export function isBenignExternalNode(node: GraphNode): boolean {
  if (node.id === BENIGN_EXTERNAL_GROUP_ID || node.role === 'benign_external_group') return false;
  if (node.type !== 'ip') return false;
  if (isPrivateIpAddress(node.label)) return false;
  if (node.is_compromised || node.is_attack_path) return false;
  return node.role !== 'adversary_infrastructure';
}

export interface NodeRoleIndex {
  attackerIps: Set<string>;
  payloadHosts: Set<string>;
  exfilDestinations: Set<string>;
  miningPools: Set<string>;
}

export function buildNodeRoleIndex(
  detections: DetectionResult[],
  events: NormalizedEvent[]
): NodeRoleIndex {
  const attackerIps = new Set<string>();
  const payloadHosts = new Set<string>();
  const exfilDestinations = new Set<string>();
  const miningPools = new Set<string>();

  for (const d of detections) {
    const tactic = String(d.mitre_tactic || '').toLowerCase();
    const ruleId = String(d.rule_id || '').toLowerCase();
    const ri = d.rule_information || {};

    if (tactic === 'impact' || ruleId.includes('miner') || d.mitre_technique === 'T1496') {
      const poolList: string[] = [
        ...(Array.isArray(ri.destination_ips) ? ri.destination_ips : []),
        ...(ri.dst_ip ? [String(ri.dst_ip)] : []),
        ...(ri.destination_ip ? [String(ri.destination_ip)] : []),
      ];
      for (const ip of poolList) {
        if (ip && !isPrivateIpAddress(String(ip))) miningPools.add(String(ip));
      }
      continue;
    }

    const srcList: string[] = [
      ...(d.source_ips || []),
      ...(Array.isArray(ri.source_ips) ? ri.source_ips : []),
      ...(Array.isArray(ri.src_ips) ? ri.src_ips : []),
      ...(d.src_ip ? [d.src_ip] : []),
    ];
    for (const ip of srcList) {
      if (ip && !isPrivateIpAddress(String(ip))) attackerIps.add(String(ip));
    }

    if (tactic === 'exfiltration' || ruleId.includes('exfil') || ruleId.includes('scp-transfer') || ruleId.includes('rclone')) {
      const dstList: string[] = [
        ...(Array.isArray(ri.destination_ips) ? ri.destination_ips : []),
        ...(ri.dst_ip ? [String(ri.dst_ip)] : []),
      ];
      for (const ip of dstList) {
        if (ip && !isPrivateIpAddress(String(ip))) exfilDestinations.add(String(ip));
      }
    }

    if (
      d.mitre_technique === 'T1105' ||
      ruleId.includes('tmp-download') ||
      tactic === 'command and control'
    ) {
      const desc = String(d.description || '');
      let m: RegExpExecArray | null;
      IPV4_URL_HOST_RE.lastIndex = 0;
      while ((m = IPV4_URL_HOST_RE.exec(desc)) !== null) {
        payloadHosts.add(m[1]);
      }
      const dstList: string[] = [
        ...(Array.isArray(ri.destination_ips) ? ri.destination_ips : []),
        ...(ri.dst_ip ? [String(ri.dst_ip)] : []),
      ];
      for (const ip of dstList) {
        if (ip && !isPrivateIpAddress(String(ip))) payloadHosts.add(String(ip));
      }
    }
  }

  for (const evt of events) {
    const cmd = String(evt.command_line || evt.action || '');
    if (/\b(?:wget|curl)\b/i.test(cmd)) {
      IPV4_URL_HOST_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = IPV4_URL_HOST_RE.exec(cmd)) !== null) {
        if (!isPrivateIpAddress(m[1])) payloadHosts.add(m[1]);
      }
    }
    if (evt.dst_port === 4444) {
      if (evt.dst_ip && !isPrivateIpAddress(evt.dst_ip)) {
        attackerIps.add(evt.dst_ip);
      }
    }
    if (evt.dst_port === 3333) {
      if (evt.dst_ip && !isPrivateIpAddress(evt.dst_ip)) {
        miningPools.add(evt.dst_ip);
      }
    }
  }

  return { attackerIps, payloadHosts, exfilDestinations, miningPools };
}

export function classifyVisualNodeRole(
  node: GraphNode,
  roleIndex: NodeRoleIndex
): VisualNodeRole {
  if (node.id === BENIGN_EXTERNAL_GROUP_ID || node.role === 'benign_external_group') {
    return 'benign_external_group';
  }
  if (node.type === 'user') return 'user';
  if (node.type === 'host') {
    return node.is_compromised || node.is_attack_path || node.role === 'compromised_host'
      ? 'victim_host'
      : 'internal_host';
  }

  if (node.role === 'mining_pool') return 'mining_pool';
  if (node.role === 'payload_host') return 'payload_host';
  if (node.role === 'exfil_destination') return 'exfil_destination';
  if (node.role === 'c2') return 'attacker_c2';

  const label = String(node.label || '').trim();
  const isMiningPool = roleIndex.miningPools.has(label);
  const isPayload = roleIndex.payloadHosts.has(label);
  const isExfil = roleIndex.exfilDestinations.has(label);
  const isAttacker =
    node.role === 'adversary_infrastructure' ||
    roleIndex.attackerIps.has(label) ||
    Boolean(node.is_compromised);

  if (isMiningPool) return 'mining_pool';
  if (isPayload && !isAttacker) return 'payload_host';
  if (isExfil && !isAttacker) return 'exfil_destination';
  if (isAttacker) return 'attacker_c2';
  if (isPayload) return 'payload_host';
  if (isExfil) return 'exfil_destination';

  if (node.type === 'ip' && isPrivateIpAddress(label)) {
    return node.is_attack_path ? 'victim_host' : 'internal_host';
  }
  return node.is_attack_path ? 'attacker_c2' : 'benign_external';
}

export interface RolePalette {
  label: string;
  badge: string;
  stroke: string;
  fillDark: string;
  fillLight: string;
  textDark: string;
  textLight: string;
  swatchClass: string;
}

export const ROLE_PALETTE: Record<VisualNodeRole, RolePalette> = {
  victim_host: {
    label: 'Victim Host',
    badge: 'VICTIM',
    stroke: '#f95721',
    fillDark: '#2e140d',
    fillLight: '#ffedd5',
    textDark: '#fb923c',
    textLight: '#c2410c',
    swatchClass: 'bg-[#f95721] border-[#ea580c]',
  },
  internal_host: {
    label: 'Internal Host',
    badge: 'HOST',
    stroke: '#38bdf8',
    fillDark: '#082f49',
    fillLight: '#f0f9ff',
    textDark: '#38bdf8',
    textLight: '#0369a1',
    swatchClass: 'bg-[#38bdf8] border-[#0284c7]',
  },
  user: {
    label: 'User',
    badge: 'USER',
    stroke: '#10b981',
    fillDark: '#064e3b',
    fillLight: '#ecfdf5',
    textDark: '#34d399',
    textLight: '#047857',
    swatchClass: 'bg-[#10b981] border-[#059669]',
  },
  attacker_c2: {
    label: 'Attacker / C2',
    badge: 'C2 / ATK',
    stroke: '#ef4444',
    fillDark: '#3b0d0d',
    fillLight: '#fee2e2',
    textDark: '#f87171',
    textLight: '#b91c1c',
    swatchClass: 'bg-[#ef4444] border-[#dc2626]',
  },
  payload_host: {
    label: 'Payload Host',
    badge: 'PAYLOAD',
    stroke: '#f59e0b',
    fillDark: '#2d1b06',
    fillLight: '#fef3c7',
    textDark: '#fbbf24',
    textLight: '#b45309',
    swatchClass: 'bg-[#f59e0b] border-[#d97706]',
  },
  exfil_destination: {
    label: 'Exfil Destination',
    badge: 'EXFIL',
    stroke: '#a855f7',
    fillDark: '#2e1065',
    fillLight: '#f5f3ff',
    textDark: '#c084fc',
    textLight: '#6d28d9',
    swatchClass: 'bg-[#a855f7] border-[#7c3aed]',
  },
  mining_pool: {
    label: 'Mining pool',
    badge: 'POOL',
    stroke: '#06b6d4',
    fillDark: '#083344',
    fillLight: '#ecfeff',
    textDark: '#22d3ee',
    textLight: '#0e7490',
    swatchClass: 'bg-[#06b6d4] border-[#0891b2]',
  },
  benign_external: {
    label: 'Benign External',
    badge: 'BENIGN',
    stroke: '#64748b',
    fillDark: '#1e293b',
    fillLight: '#f1f5f9',
    textDark: '#94a3b8',
    textLight: '#475569',
    swatchClass: 'bg-[#64748b] border-[#475569]',
  },
  benign_external_group: {
    label: 'Benign External Group',
    badge: 'GROUP',
    stroke: '#64748b',
    fillDark: '#1e293b',
    fillLight: '#f1f5f9',
    textDark: '#cbd5e1',
    textLight: '#334155',
    swatchClass: 'bg-[#64748b] border-[#475569]',
  },
};

export function groupBenignExternalGraph(
  nodes: GraphNode[],
  edges: GraphEdge[],
  expandGroup: boolean
): { nodes: GraphNode[]; edges: GraphEdge[]; benignCount: number } {
  const benignNodes = nodes.filter(isBenignExternalNode);
  const benignCount = benignNodes.length;
  if (expandGroup || benignCount <= 1) {
    return { nodes, edges, benignCount };
  }

  const benignIds = new Set(benignNodes.map(n => n.id));
  const totalBenignEvents = benignNodes.reduce((sum, n) => sum + (n.event_count || 0), 0);

  const groupNode: GraphNode = {
    id: BENIGN_EXTERNAL_GROUP_ID,
    label: `Benign External IPs (${benignCount})`,
    type: 'ip',
    role: 'benign_external_group',
    is_compromised: false,
    is_attack_path: false,
    event_count: totalBenignEvents,
    details: {
      grouped_count: benignCount,
      sample_ips: benignNodes.slice(0, 8).map(n => n.label),
    },
  };

  const keptNodes = [...nodes.filter(n => !benignIds.has(n.id)), groupNode];

  const collapsedEdges = new Map<string, GraphEdge>();
  for (const edge of edges) {
    const src = benignIds.has(edge.source) ? BENIGN_EXTERNAL_GROUP_ID : edge.source;
    const tgt = benignIds.has(edge.target) ? BENIGN_EXTERNAL_GROUP_ID : edge.target;
    if (src === tgt) continue;
    const key = `${src}->${tgt}`;
    const existing = collapsedEdges.get(key);
    if (!existing) {
      collapsedEdges.set(key, { ...edge, id: `edge-${src}-${tgt}`, source: src, target: tgt });
    } else {
      const nextCount = (existing.count || 1) + (edge.count || 1);
      collapsedEdges.set(key, {
        ...existing,
        count: nextCount,
        label: `${existing.protocol || 'Traffic'} (${benignCount} external IPs, x${nextCount})`,
        is_attack_path: Boolean(existing.is_attack_path || edge.is_attack_path),
      });
    }
  }

  return {
    nodes: keptNodes,
    edges: Array.from(collapsedEdges.values()),
    benignCount,
  };
}
