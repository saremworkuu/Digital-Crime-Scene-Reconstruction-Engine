import { AuditLogEntry } from '../types';

const PARSER_NAME_MAP: Record<string, string> = {
  authlogparser: 'auth_log',
  linux_auth: 'auth_log',
  auth_log: 'auth_log',
  auth: 'auth_log',
  webaccessparser: 'web_access',
  apacheaccessparser: 'web_access',
  web_server: 'web_access',
  web_access: 'web_access',
  apache_access: 'web_access',
  auditdparser: 'auditd',
  auditd: 'auditd',
  mysqlgenerallogparser: 'mysql_general',
  mysql_general: 'mysql_general',
  mysql: 'mysql_general',
  genericcsvjsonparser: 'generic_csv_json',
  generic_json_csv: 'generic_csv_json',
  generic_csv_json: 'generic_csv_json',
  generic: 'generic_csv_json',
  windowsevtxparser: 'windows_evtx',
  windows_evtx: 'windows_evtx',
  evtx: 'windows_evtx',
  vulnscanparser: 'vuln_scan',
  vuln_scan: 'vuln_scan',
  pcapparser: 'pcap',
  pcap_summary: 'pcap',
  pcap: 'pcap',
  pcapngparser: 'pcapng',
  pcapng: 'pcapng',
  logfileparser: 'log_parser',
  log_parser: 'log_parser',
  syslog: 'log_parser',
  textfileparser: 'txt_parser',
  txt_parser: 'txt_parser',
  text: 'txt_parser',
};

const ACTION_MAP: Record<string, string> = {
  EVIDENCE_UPLOADED: 'evidence.uploaded',
  EVIDENCE_PARSED: 'evidence.parsed',
  EVIDENCE_DOWNLOADED: 'evidence.downloaded',
  EVIDENCE_DELETED: 'evidence.deleted',
  EVIDENCE_DELETE: 'evidence.deleted',
  EVIDENCE_VERIFY: 'evidence.verified',
  EVIDENCE_VERIFIED: 'evidence.verified',
  CASE_CREATED: 'case.created',
  CASE_UPDATED: 'case.updated',
  CASE_STATUS_CHANGED: 'case.status_changed',
  CASE_STATUS_UPDATE: 'case.status_changed',
  CASE_DELETED: 'case.deleted',
  CASE_ASSIGNMENT: 'case.assigned',
  CASE_ASSIGNED: 'case.assigned',
  CASE_LEGAL_HOLD_SET: 'case.legal_hold_set',
  CASE_LEGAL_HOLD_REMOVED: 'case.legal_hold_removed',
  CASE_ARCHIVE: 'case.archived',
  CASE_UNARCHIVE: 'case.unarchived',
  REPORT_GENERATED: 'report.generated',
  REPORT_VIEWED: 'report.viewed',
  REPORT_DOWNLOADED: 'report.downloaded',
  SAVED_REPORT_DOWNLOADED: 'report.downloaded',
  REPORT_EXPORTED: 'report.exported',
  DETECTION_FP_TOGGLED: 'detection.false_positive_toggled',
  DETECTION_RULE_ADDED: 'detection.rule_added',
  TIMELINE_EXPORTED: 'timeline.exported',
  USER_REGISTERED: 'user.registered',
  USER_LOGIN: 'user.login',
  USER_LOGOUT: 'user.logout',
  USER_CREATE: 'user.created',
  USER_UPDATE: 'user.updated',
  USER_UPDATED: 'user.updated',
  USER_DELETE: 'user.deleted',
  USER_PASSWORD_RESET: 'user.password_reset',
  SESSION_TERMINATED: 'session.terminated',
  MESSAGE_STATUS_UPDATE: 'message.status_updated',
  MESSAGE_PRIORITY_UPDATE: 'message.priority_updated',
  MESSAGE_ASSIGNED: 'message.assigned',
  MESSAGE_REPLY_SENT: 'message.reply_sent',
  MESSAGE_MARK_SPAM: 'message.marked_spam',
  MESSAGE_SOFT_DELETE: 'message.deleted',
  SIGMA_RULE_CREATE: 'sigma_rule.created',
  SIGMA_RULE_UPDATE: 'sigma_rule.updated',
  SIGMA_RULE_ENABLE: 'sigma_rule.enabled',
  SIGMA_RULE_DISABLE: 'sigma_rule.disabled',
  SIGMA_RULE_DELETE: 'sigma_rule.deleted',
  SIGMA_RULES_IMPORTED: 'sigma_rule.imported',
  INGESTION_JOB_RETRY: 'ingestion.retried',
  SYSTEM_SETTINGS_UPDATE: 'system.settings_updated',
  DEMO_DATA_RESET: 'system.demo_data_reset',
};

export function canonicalParserName(value?: string | null): string | null {
  if (!value) return null;
  const raw = String(value).trim();
  if (!raw) return null;
  const compact = raw.replace(/[\s-]+/g, '_').toLowerCase();
  if (PARSER_NAME_MAP[compact]) return PARSER_NAME_MAP[compact];
  const noUnderscores = compact.replace(/_/g, '');
  if (PARSER_NAME_MAP[noUnderscores]) return PARSER_NAME_MAP[noUnderscores];
  const stripped = raw.endsWith('Parser') ? raw.slice(0, -6) : raw;
  return stripped.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase() || compact;
}

export function normalizeAuditAction(action?: string | null): string {
  const raw = String(action || '').trim();
  if (!raw) return 'system.event';
  const upper = raw.toUpperCase();
  if (ACTION_MAP[upper]) return ACTION_MAP[upper];
  if (raw.includes('.')) return raw.toLowerCase();
  const idx = raw.indexOf('_');
  if (idx > 0) {
    return `${raw.slice(0, idx).toLowerCase()}.${raw.slice(idx + 1).toLowerCase()}`;
  }
  return raw.toLowerCase();
}

export function normalizeAuditDetailsForDisplay(
  action: string,
  details?: Record<string, any> | null
): Record<string, any> {
  if (!details || typeof details !== 'object' || Array.isArray(details)) {
    return {};
  }
  const out: Record<string, any> = { ...details };
  const isEvidence =
    action.startsWith('evidence.') ||
    ['sha256', 'sha256_hash', 'file_name', 'filename', 'size_bytes', 'file_size', 'parser', 'parser_used', 'events_extracted'].some(
      k => k in out
    );
  if (!isEvidence) return out;

  const filename = out.filename ?? out.file_name ?? null;
  const file_size = out.file_size ?? out.size_bytes ?? null;
  const file_type = out.file_type ?? null;
  const sha256_hash = out.sha256_hash ?? out.sha256 ?? null;
  const parser = canonicalParserName(out.parser ?? out.parser_used ?? null);
  const events_extracted = out.events_extracted ?? null;

  delete out.file_name;
  delete out.size_bytes;
  delete out.sha256;
  delete out.parser_used;

  return {
    filename,
    file_size,
    file_type,
    sha256_hash,
    parser,
    events_extracted,
    ...out,
  };
}

export function parseAuditUtcTimestampMs(ts?: string | null): number {
  if (!ts) return 0;
  const trimmed = String(ts).trim();
  if (!trimmed) return 0;
  const iso = trimmed.includes('T') ? trimmed : trimmed.replace(' ', 'T');
  const withTz = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(iso) ? iso : `${iso}Z`;
  const ms = Date.parse(withTz);
  return Number.isNaN(ms) ? 0 : ms;
}

export function normalizeAuditLogForDisplay(entry: AuditLogEntry): AuditLogEntry {
  const action = normalizeAuditAction(entry.action);
  return {
    ...entry,
    action,
    details: normalizeAuditDetailsForDisplay(action, entry.details),
  };
}

export function sortAuditLogsChronological(entries: AuditLogEntry[]): AuditLogEntry[] {
  return entries
    .map((entry, idx) => ({ entry: normalizeAuditLogForDisplay(entry), idx }))
    .sort((a, b) => {
      const diff =
        parseAuditUtcTimestampMs(b.entry.timestamp) -
        parseAuditUtcTimestampMs(a.entry.timestamp);
      return diff !== 0 ? diff : a.idx - b.idx;
    })
    .map(item => item.entry);
}
