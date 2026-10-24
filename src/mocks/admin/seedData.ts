/**
 * Reference Mock Seed Data for Admin Frontend
 * Digital Crime Scene Reconstruction Engine (DCSRE / አሻራ)
 * Maintained with one reference mock record for each category for reference & comparison.
 */

import {
  AdminUser,
  AdminCase,
  AdminEvidence,
  AdminSigmaRule,
  AdminContactMessage,
  AdminAuditEntry,
  AdminSystemHealth,
  AdminSettings
} from '../../admin/types';

export const SEED_USERS: AdminUser[] = [
  {
    id: 'usr-admin',
    name: 'Sarem Worku',
    email: 'saremworkuu@gmail.com',
    role: 'admin',
    status: 'active',
    last_login: '2026-10-23T06:14:22Z',
    department: 'Digital Forensic Incident Response (DFIR) Command',
    created_at: '2026-01-15T00:00:00Z',
    two_factor_enabled: true,
    failed_login_attempts: 0,
    sessions: [
      { id: 'sess-01', device: 'Chrome 122 on macOS (Arm64)', ip: '192.168.1.104', last_active: 'Just now' }
    ]
  },
  {
    id: 'usr-inv-01',
    name: 'Marcus Vance',
    email: 'm.vance@dcsre.net',
    role: 'investigator',
    status: 'active',
    last_login: '2026-10-22T19:40:10Z',
    department: 'Cyber Threat Intelligence & Reverse Engineering',
    created_at: '2026-02-01T08:00:00Z',
    two_factor_enabled: true,
    failed_login_attempts: 0,
    sessions: [
      { id: 'sess-03', device: 'Firefox Developer Edition on Linux', ip: '10.0.4.22', last_active: 'Yesterday' }
    ]
  }
];

export const SEED_CASES: AdminCase[] = [
  {
    id: 'case-cobalt-shadow',
    title: 'Operation Cobalt Shadow - APT29 Exfiltration',
    status: 'open',
    owner: 'Sarem Worku',
    created_date: '2026-10-18T14:32:00Z',
    assigned_investigators: ['Sarem Worku', 'Marcus Vance'],
    is_archived: false,
    legal_hold: false,
    evidence_count: 1,
    description: 'Investigation into active multi-stage intrusion involving domain compromise, LSASS dumping, and cloud storage exfiltration.'
  }
];

export const SEED_EVIDENCE: AdminEvidence[] = [
  {
    id: 'ev-01',
    case_id: 'case-cobalt-shadow',
    file_name: 'Security_DC01_auth.evtx',
    type: 'EVTX',
    size_bytes: 14889728,
    uploader: 'Sarem Worku',
    uploaded_at: '2026-10-18T15:02:10Z',
    sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    expected_sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    parsing_status: 'completed',
    verified: true
  }
];

export const SEED_SIGMA_RULES: AdminSigmaRule[] = [
  {
    id: 'sig-01',
    name: 'LSASS Memory Dump via Taskmgr or ProcDump',
    severity: 'critical',
    mitre_id: 'T1003.001',
    enabled: true,
    times_triggered: 14,
    description: 'Detects processes targeting lsass.exe for credential harvesting and in-memory ticket extraction.',
    query: 'process_name in ("procdump.exe", "procdump64.exe", "taskmgr.exe") and target_process = "lsass.exe"',
    created_at: '2026-01-20T00:00:00Z'
  }
];

export const SEED_MESSAGES: AdminContactMessage[] = [
  {
    id: 'msg-01',
    reference: 'አሻራ-748921',
    sender_name: 'Marcus Sterling',
    sender_email: 'm.sterling@techcorp.io',
    sender_phone: '+1 (555) 392-1084',
    subject: 'Urgent: Ransomware IOC Verification Request',
    category: 'Incident Report',
    status: 'new',
    priority: 'high',
    assignee: null,
    date: '2026-10-23T05:30:00Z',
    is_read: false,
    body: 'We detected DarkLock binary artifacts across two backup controllers at 04:15 UTC. We need urgent validation whether the SHA-256 hashes match your current intelligence database.',
    reply_thread: []
  }
];

export const SEED_AUDIT_LOGS: AdminAuditEntry[] = [
  {
    id: 'aud-01',
    timestamp: '2026-10-23T06:14:22Z',
    user_id: 'usr-admin',
    user_name: 'Sarem Worku',
    role: 'admin',
    action: 'USER_LOGIN',
    target_type: 'AUTH',
    target_id: 'sess-01',
    details: { method: 'PASSWORD_AND_2FA', ip: '192.168.1.104' },
    ip_address: '192.168.1.104'
  }
];

export const SEED_SYSTEM_HEALTH: AdminSystemHealth = {
  parsers: [
    { type: 'EVTX', status: 'online', success_rate: '99.4%', avg_latency: '420 ms', files_processed: 240 }
  ],
  queue: [
    { id: 'job-01', file_name: 'ad_replication_audit.evtx', parser_type: 'EVTX', status: 'completed', started_at: '2026-10-23T06:59:01Z' }
  ],
  storage_used_bytes: 51754352640,
  storage_total_bytes: 268435456000,
  failed_logins_24h: 0,
  recent_errors: [
    { timestamp: '2026-10-23T06:45:00Z', component: 'TXT Parser', message: 'Parser diagnostic trace recorded.' }
  ]
};

export const SEED_SETTINGS: AdminSettings = {
  time_zone: 'UTC',
  org_name: 'አሻራ Cyber Forensic Command',
  retention_days: 90,
  min_password_length: 12,
  two_factor_enforced: false,
  failed_login_lockout_limit: 5
};
