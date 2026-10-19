export type EntityType = 'host' | 'user' | 'ip' | 'process' | 'domain' | 'file';

export interface GraphNode {
  id: string;
  label: string;
  type: EntityType;
  isCompromised?: boolean;
  is_compromised?: boolean;
  isAttackPath?: boolean;
  is_attack_path?: boolean;
  metadata?: Record<string, any>;
  eventCount?: number;
  event_count: number;
  first_seen?: string;
  firstSeen?: string;
  last_seen?: string;
  lastSeen?: string;
  details?: any;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  count: number;
  isAttackPath?: boolean;
  is_attack_path?: boolean;
  severity: string;
  timestamp?: string;
  protocol?: string;
}

export interface AttackGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}
