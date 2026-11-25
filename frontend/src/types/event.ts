export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low';

export interface ForensicEvent {
  id: string;
  caseId: string;
  evidenceId: string;
  timestamp: string; // ISO 8601 UTC
  sourceType: string;
  host: string;
  user: string;
  srcIp?: string;
  dstIp?: string;
  srcPort?: number;
  dstPort?: number;
  protocol?: string;
  packets?: number;
  bytes?: number;
  flags?: string;
  payload_preview?: string;
  payload_untrusted?: boolean;
  process?: string;
  action: string;
  outcome: 'success' | 'failure';
  severity: SeverityLevel;
  raw: string;
  mitreTechnique?: string;
  mitreTactic?: string;
  isAttackPath?: boolean;
  attackPhase?: string;
  metadata?: Record<string, any>;
}

export interface AttackChain {
  id: string;
  name: string;
  events: string[];
  entities: string[];
  startTime: string;
  endTime: string;
  confidenceScore: number;
  highestSeverity: SeverityLevel;
}
