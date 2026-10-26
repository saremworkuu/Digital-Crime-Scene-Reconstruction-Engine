/**
 * Admin Frontend Type Definitions
 * Digital Crime Scene Reconstruction Engine (DCSRE / አሻራ)
 */

export type AdminRole = 'admin' | 'investigator' | 'auditor';
export type UserStatus = 'active' | 'disabled' | 'suspended';
export type CaseStatus = 'open' | 'under_review' | 'closed';
export type ParsingStatus = 'completed' | 'failed' | 'processing' | 'pending';
export type RuleSeverity = 'critical' | 'high' | 'medium' | 'low';
export type MessageStatus = 'new' | 'in_review' | 'replied' | 'spam' | 'archived';
export type MessagePriority = 'critical' | 'high' | 'medium' | 'low';
export type MessageCategory =
  | 'Incident Report'
  | 'Telemetry Query'
  | 'Chain of Custody'
  | 'General Inquiry'
  | 'Support';

export interface AdminUserSession {
  id: string;
  device: string;
  ip: string;
  last_active: string;
}

export interface AdminUser {
  id: string;
  name: string;
  email: string;
  role: AdminRole;
  status: UserStatus;
  last_login: string;
  department: string;
  created_at: string;
  two_factor_enabled: boolean;
  failed_login_attempts: number;
  sessions: AdminUserSession[];
}

export interface AdminCase {
  id: string;
  title: string;
  status: CaseStatus;
  owner: string;
  created_date: string;
  assigned_investigators: string[];
  is_archived: boolean;
  legal_hold: boolean; // Disables evidence deletion when true
  evidence_count: number;
  description: string;
}

export interface AdminEvidence {
  id: string;
  case_id: string;
  file_name: string;
  type: 'EVTX' | 'PCAP' | 'LOG' | 'CSV' | 'JSON' | 'XML' | 'PDF' | 'TXT';
  size_bytes: number;
  uploader: string;
  uploaded_at: string;
  sha256: string;
  expected_sha256: string;
  parsing_status: ParsingStatus;
  error_text?: string;
  verified?: boolean | null;
}

export interface AdminSigmaRule {
  id: string;
  name: string;
  severity: RuleSeverity;
  mitre_id: string;
  enabled: boolean;
  times_triggered: number;
  description: string;
  query: string;
  created_at: string;
}

export interface AdminReplyMessage {
  id: string;
  author: string;
  role: string;
  message: string;
  timestamp: string;
}

export interface AdminContactMessage {
  id: string;
  reference: string;
  sender_name: string;
  sender_email: string;
  sender_phone: string;
  subject: string;
  category: MessageCategory;
  status: MessageStatus;
  priority: MessagePriority;
  assignee: string | null;
  date: string;
  is_read: boolean;
  body: string;
  reply_thread: AdminReplyMessage[];
}

export interface AdminAuditEntry {
  id: string;
  timestamp: string;
  user_id: string;
  user_name: string;
  role: string;
  action: string;
  case_id?: string;
  target_type: string;
  target_id: string;
  details: Record<string, any>;
  ip_address: string;
}

export interface AdminParserStatus {
  type: string;
  status: 'online' | 'degraded' | 'offline';
  success_rate: string;
  avg_latency: string;
  files_processed: number;
}

export interface AdminQueueJob {
  id: string;
  file_name: string;
  parser_type: string;
  status: 'processing' | 'failed' | 'completed';
  started_at: string;
  error?: string;
}

export interface AdminSystemHealth {
  parsers: AdminParserStatus[];
  queue: AdminQueueJob[];
  storage_used_bytes: number;
  storage_total_bytes: number;
  failed_logins_24h: number;
  recent_errors: Array<{ timestamp: string; component: string; message: string }>;
}

export interface AdminSettings {
  time_zone: string;
  org_name: string;
  retention_days: number;
  min_password_length: number;
  two_factor_enforced: boolean;
  failed_login_lockout_limit: number;
}
