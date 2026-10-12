export interface ForensicReport {
  id: string;
  caseId?: string;
  case_id?: string;
  caseName?: string;
  case_name?: string;
  generatedAt?: string;
  generated_at?: string;
  generatorName?: string;
  generator_name?: string;
  generatorRole?: string;
  generator_role?: string;
  version?: string;
  classification?: string;
  executiveSummary?: string;
  executive_summary?: string;
  evidenceInventory?: any[];
  evidence_inventory?: any[];
  mitreCoverage?: any[];
  mitre_coverage?: any[];
  attackTimelineSummary?: any[];
  attack_timeline_summary?: any[];
  compromisedAssets?: any;
  compromised_assets?: any;
  recommendations?: string[];
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  userId?: string;
  user_id?: string;
  userName?: string;
  user_name?: string;
  userRole?: string;
  user_role?: string;
  caseId?: string;
  case_id?: string;
  action: string;
  targetType?: string;
  target_type?: string;
  targetId?: string;
  target_id?: string;
  ipAddress?: string;
  ip_address?: string;
  userAgent?: string;
  user_agent?: string;
  details?: Record<string, any>;
  details_json?: Record<string, any>;
}
