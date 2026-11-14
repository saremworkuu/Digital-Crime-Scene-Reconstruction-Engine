export * from './user';
export * from './case';
export * from './evidence';
export * from './event';
export * from './detection';
export * from './graph';
export * from './report';

// Backward compatibility & Unified Types
export type ParserType = 'linux_auth' | 'web_server' | 'windows_evtx' | 'pcap_summary' | 'generic' | 'generic_json_csv';
export type EventSeverity = 'low' | 'medium' | 'high' | 'critical';
export type EventOutcome = 'success' | 'failure' | 'unknown';

export interface NormalizedEvent {
  id: string;
  case_id: string;
  evidence_id: string;
  timestamp: string;
  timestamp_timezone_known?: boolean;
  source_type: string;
  host: string;
  user: string;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  bytes?: number;
  process?: string;
  parent_process?: string;
  command_line?: string;
  service_name?: string;
  target_file?: string;
  host_inferred?: boolean;
  source_file?: string;
  source_record_id?: any;
  event_id?: any;
  action: string;
  outcome: EventOutcome;
  severity: EventSeverity;
  raw: string;
  mitre_technique?: string;
  mitre_tactic?: string;
  is_attack_path?: boolean;
  attack_phase?: string;
  metadata?: Record<string, any>;
  extra?: Record<string, any>;

  // CamelCase accessors
  caseId?: string;
  evidenceId?: string;
  sourceType?: string;
  srcIp?: string;
  dstIp?: string;
  srcPort?: number;
  dstPort?: number;
  mitreTechnique?: string;
  mitreTactic?: string;
  isAttackPath?: boolean;
  attackPhase?: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  severity: EventSeverity;
  mitre_technique: string;
  mitre_tactic: string;
  description: string;
  source_types?: ParserType[];
  author?: string;
  status?: string;
  tags?: string[];
  yaml_content?: string;
  yamlContent?: string;
  match_fn?: (events: NormalizedEvent[]) => {
    matched_event_ids: string[];
    description: string;
    entities: {
      hosts?: string[];
      users?: string[];
      ips?: string[];
    };
  } | null;
}

export interface DetectionResult {
  id: string;
  case_id?: string;
  caseId?: string;
  rule_id: string;
  rule_name: string;
  severity: EventSeverity;
  mitre_technique: string;
  mitre_techniques_all?: string[];
  mitre_tactic: string;
  timestamp: string;
  description: string;
  matched_event_ids: string[];
  false_positive: boolean;
  false_positive_reason?: string;
  false_positive_marked_by?: string;
  host?: string;
  user?: string;
  source?: string;
  source_file?: string;
  source_record_references?: any[];
  rule_information?: Record<string, any>;
  entities_involved: {
    hosts?: string[];
    users?: string[];
    ips?: string[];
  };
}
