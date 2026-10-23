/**
 * Mock Seed Data for Admin Frontend
 * Digital Crime Scene Reconstruction Engine (DCSRE / አሻራ)
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
      { id: 'sess-01', device: 'Chrome 122 on macOS (Arm64)', ip: '192.168.1.104', last_active: 'Just now' },
      { id: 'sess-02', device: 'Forensic Lab Workstation 01', ip: '10.0.4.15', last_active: '2 hours ago' }
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
  },
  {
    id: 'usr-inv-02',
    name: 'Elena Rostova',
    email: 'e.rostova@dcsre.net',
    role: 'investigator',
    status: 'active',
    last_login: '2026-10-23T04:22:00Z',
    department: 'Memory Forensics & Network Packet Inspection',
    created_at: '2026-02-15T09:30:00Z',
    two_factor_enabled: false,
    failed_login_attempts: 1,
    sessions: [
      { id: 'sess-04', device: 'Chrome on Windows 11 Enterprise', ip: '10.0.4.38', last_active: '3 hours ago' }
    ]
  },
  {
    id: 'usr-aud-01',
    name: 'David Kim',
    email: 'd.kim@dcsre.audit',
    role: 'auditor',
    status: 'active',
    last_login: '2026-10-21T11:05:43Z',
    department: 'Forensic Oversight & Compliance Assurance',
    created_at: '2026-03-01T10:00:00Z',
    two_factor_enabled: true,
    failed_login_attempts: 0,
    sessions: [
      { id: 'sess-05', device: 'Safari on macOS Sequoia', ip: '172.16.0.5', last_active: '2 days ago' }
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
    evidence_count: 5,
    description: 'Investigation into active multi-stage intrusion involving domain compromise, LSASS dumping, and cloud storage exfiltration.'
  },
  {
    id: 'case-darklock',
    title: 'Financial Core Breach - DarkLock Extortion',
    status: 'under_review',
    owner: 'Marcus Vance',
    created_date: '2026-10-14T09:15:00Z',
    assigned_investigators: ['Marcus Vance', 'Elena Rostova'],
    is_archived: false,
    legal_hold: true, // Disables evidence deletion
    evidence_count: 3,
    description: 'Ransomware deployment investigation targeting SWIFT payment gateway and backup infrastructure. Preserved under strict legal hold.'
  }
];

export const SEED_EVIDENCE: AdminEvidence[] = [
  {
    id: 'ev-01',
    case_id: 'case-cobalt-shadow',
    file_name: 'Security_DC01_auth.evtx',
    type: 'EVTX',
    size_bytes: 14889728, // 14.2 MB
    uploader: 'Sarem Worku',
    uploaded_at: '2026-10-18T15:02:10Z',
    sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    expected_sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    parsing_status: 'completed',
    verified: true
  },
  {
    id: 'ev-02',
    case_id: 'case-cobalt-shadow',
    file_name: 'edge_firewall_traffic.pcap',
    type: 'PCAP',
    size_bytes: 51065600, // 48.7 MB
    uploader: 'Elena Rostova',
    uploaded_at: '2026-10-18T16:20:45Z',
    sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    expected_sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    parsing_status: 'completed',
    verified: true
  },
  {
    id: 'ev-03',
    case_id: 'case-cobalt-shadow',
    file_name: 'nginx_access_dmz.log',
    type: 'LOG',
    size_bytes: 3984588, // 3.8 MB
    uploader: 'Marcus Vance',
    uploaded_at: '2026-10-19T08:12:00Z',
    sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    expected_sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    parsing_status: 'completed',
    verified: true
  },
  {
    id: 'ev-04',
    case_id: 'case-cobalt-shadow',
    file_name: 'compromised_hosts_audit.csv',
    type: 'CSV',
    size_bytes: 430080, // 420 KB
    uploader: 'Marcus Vance',
    uploaded_at: '2026-10-19T11:45:19Z',
    sha256: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
    expected_sha256: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
    parsing_status: 'completed',
    verified: true
  },
  {
    id: 'ev-05',
    case_id: 'case-cobalt-shadow',
    file_name: 'ad_schema_telemetry.json',
    type: 'JSON',
    size_bytes: 1258291, // 1.2 MB
    uploader: 'Sarem Worku',
    uploaded_at: '2026-10-19T14:10:00Z',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    expected_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    parsing_status: 'completed',
    verified: true
  },
  {
    id: 'ev-06',
    case_id: 'case-darklock',
    file_name: 'syslog_event_stream.xml',
    type: 'XML',
    size_bytes: 2202009, // 2.1 MB
    uploader: 'Elena Rostova',
    uploaded_at: '2026-10-15T10:04:18Z',
    sha256: '8799c903f7e1b9b6574f1f58b0f9f31a28a36fa33c2a8f8d22d2b568e0d68bb1',
    expected_sha256: '8799c903f7e1b9b6574f1f58b0f9f31a28a36fa33c2a8f8d22d2b568e0d68bb1',
    parsing_status: 'completed',
    verified: true
  },
  {
    id: 'ev-07',
    case_id: 'case-darklock',
    file_name: 'malware_triage_preliminary.pdf',
    type: 'PDF',
    size_bytes: 696320, // 680 KB
    uploader: 'Marcus Vance',
    uploaded_at: '2026-10-15T13:40:00Z',
    sha256: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
    expected_sha256: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
    parsing_status: 'completed',
    verified: true
  },
  {
    id: 'ev-08',
    case_id: 'case-darklock',
    file_name: 'corrupted_memory_dump_notes.txt',
    type: 'TXT',
    size_bytes: 12288, // 12 KB
    uploader: 'Elena Rostova',
    uploaded_at: '2026-10-16T17:15:30Z',
    sha256: 'fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9',
    expected_sha256: 'fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9',
    parsing_status: 'failed',
    error_text: 'Unexpected EOF at byte 12048: header magic mismatch [0x00000000]. Segment requires raw hex repair.',
    verified: false
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
  },
  {
    id: 'sig-02',
    name: 'Suspicious PowerShell Base64 Encoded Command Execution',
    severity: 'high',
    mitre_id: 'T1059.001',
    enabled: true,
    times_triggered: 28,
    description: 'Identifies PowerShell command lines utilizing encoded commands (-e, -enc, -encodedcommand) to evade inspection.',
    query: 'process_name = "powershell.exe" and command_line regex "(-e|-enc|-encodedcommand)\\s+[A-Za-z0-9+/=]{20,}"',
    created_at: '2026-02-10T00:00:00Z'
  },
  {
    id: 'sig-03',
    name: 'Ransomware Shadow Copy Deletion via Vssadmin',
    severity: 'critical',
    mitre_id: 'T1490',
    enabled: true,
    times_triggered: 4,
    description: 'Flags destructive backup elimination commands executed prior to file encryption.',
    query: 'process_name = "vssadmin.exe" and command_line contains "delete shadows" and command_line contains "/all"',
    created_at: '2026-02-18T00:00:00Z'
  },
  {
    id: 'sig-04',
    name: 'Lateral Movement via Pass-The-Hash or WMI Exec',
    severity: 'high',
    mitre_id: 'T1047',
    enabled: true,
    times_triggered: 9,
    description: 'Monitors inbound WMI execution creating remote processes on internal targets.',
    query: 'parent_process = "wmiprvse.exe" and process_name in ("cmd.exe", "powershell.exe", "rundll32.exe")',
    created_at: '2026-03-02T00:00:00Z'
  },
  {
    id: 'sig-05',
    name: 'Active Directory Reconnaissance using AdFind or BloodHound',
    severity: 'medium',
    mitre_id: 'T1087.002',
    enabled: true,
    times_triggered: 42,
    description: 'Discovers LDAP queries enumerating domain trusts, admin accounts, and Kerberos SPNs.',
    query: 'process_name in ("adfind.exe", "sharpad.exe") or command_line contains "objectcategory=person"',
    created_at: '2026-03-15T00:00:00Z'
  },
  {
    id: 'sig-06',
    name: 'DNS Tunneling or Data Exfiltration via TXT Queries',
    severity: 'high',
    mitre_id: 'T1048.003',
    enabled: false,
    times_triggered: 0,
    description: 'Detects high frequency of unusually long DNS TXT query payloads sent to non-standard nameservers.',
    query: 'protocol = "DNS" and query_type = "TXT" and query_length > 180 and request_rate > 25_per_minute',
    created_at: '2026-04-01T00:00:00Z'
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
  },
  {
    id: 'msg-02',
    reference: 'አሻራ-632194',
    sender_name: 'Dr. Aris Thorne',
    sender_email: 'thorne@biohealth-labs.org',
    sender_phone: '+1 (555) 802-9112',
    subject: 'Suspected Domain Controller Compromise & Data Exfiltration',
    category: 'Incident Report',
    status: 'new',
    priority: 'critical',
    assignee: 'Sarem Worku',
    date: '2026-10-23T04:12:00Z',
    is_read: false,
    body: 'Our EDR flagged mass Kerberoasting and credential dumping. We have isolated DC02 and request an emergency investigation docket under DCSRE protocol.',
    reply_thread: []
  },
  {
    id: 'msg-03',
    reference: 'አሻራ-519823',
    sender_name: 'Sarah Jenkins',
    sender_email: 'sjenkins@defenselegal.com',
    sender_phone: '+1 (555) 441-2900',
    subject: 'Inquiry about Forensic Chain of Custody Standards (Court Admissibility)',
    category: 'Chain of Custody',
    status: 'in_review',
    priority: 'medium',
    assignee: 'David Kim',
    date: '2026-10-22T18:20:00Z',
    is_read: true,
    body: 'Could you provide the audit documentation proving the SHA-256 ledger complies with Federal Rule of Evidence 902(14) for self-authenticating digital records?',
    reply_thread: [
      {
        id: 'rep-01',
        author: 'David Kim (Auditor)',
        role: 'Auditor',
        message: 'Reviewing statutory compliance documentation. Our cryptographic hashes utilize RFC-6962 transparency logs.',
        timestamp: '2026-10-22T20:10:00Z'
      }
    ]
  },
  {
    id: 'msg-04',
    reference: 'አሻራ-401928',
    sender_name: 'Kofi Mensah',
    sender_email: 'kmensah@cloudguard.systems',
    sender_phone: '+44 20 7946 0912',
    subject: 'API Access for Enterprise SIEM Integration (Splunk & Sentinel)',
    category: 'General Inquiry',
    status: 'replied',
    priority: 'low',
    assignee: 'Sarem Worku',
    date: '2026-10-22T14:05:00Z',
    is_read: true,
    body: 'Does your platform support automated ingestion webhooks to forward reconstructed 3D attack paths directly into our central SIEM instance?',
    reply_thread: [
      {
        id: 'rep-02',
        author: 'Sarem Worku (Admin)',
        role: 'Administrator',
        message: 'Yes, DCSRE supports webhook dispatch and STIX/TAXII 2.1 feeds. Documentation has been shared.',
        timestamp: '2026-10-22T15:30:00Z'
      }
    ]
  },
  {
    id: 'msg-05',
    reference: 'አሻራ-382910',
    sender_name: 'Rachel Adams',
    sender_email: 'rachel.a@finsec-audit.gov',
    sender_phone: '+1 (555) 710-3329',
    subject: 'Tamper-Evident Ledger Verification Question',
    category: 'Telemetry Query',
    status: 'new',
    priority: 'medium',
    assignee: null,
    date: '2026-10-22T11:45:00Z',
    is_read: false,
    body: 'We are conducting an annual audit on financial telemetry. Please explain the cryptographic mechanism used to ensure audit records cannot be retroactively altered by administrators.',
    reply_thread: []
  },
  {
    id: 'msg-06',
    reference: 'አሻራ-291048',
    sender_name: 'PromoteFast Marketing',
    sender_email: 'contact@boost-searches-quick.biz',
    sender_phone: '+1 (800) 555-0199',
    subject: 'Rank #1 on Google with our SEO Backlink Package',
    category: 'Support',
    status: 'spam',
    priority: 'low',
    assignee: null,
    date: '2026-10-21T09:12:00Z',
    is_read: true,
    body: 'Hello Webmaster, We noticed your website could use 5,000 monthly backlinks to increase search visibility for digital forensics terms. Special discount today!',
    reply_thread: []
  },
  {
    id: 'msg-07',
    reference: 'አሻራ-184920',
    sender_name: 'Tariq Al-Mansoor',
    sender_email: 'tariq.ops@cyberhub.ae',
    sender_phone: '+971 4 312 8844',
    subject: 'Host Hop Telemetry Missing in EVTX Ingestion',
    category: 'Telemetry Query',
    status: 'in_review',
    priority: 'high',
    assignee: 'Marcus Vance',
    date: '2026-10-21T07:40:00Z',
    is_read: true,
    body: 'During ingestion of Windows Event ID 4624 (Logon Type 10 / RDP), certain workstation source IPs are not auto-mapping into the 3D correlation graph.',
    reply_thread: [
      {
        id: 'rep-03',
        author: 'Marcus Vance',
        role: 'Investigator',
        message: 'Examining parsing logic for IPv6 mapped source addresses in Windows Server 2022.',
        timestamp: '2026-10-21T10:15:00Z'
      }
    ]
  },
  {
    id: 'msg-08',
    reference: 'አሻራ-109283',
    sender_name: 'Elena Rostova',
    sender_email: 'e.rostova@dcsre.net',
    sender_phone: '+1 (555) 919-4821',
    subject: 'Requesting Case Reopen for Ticket #2026-CS (New Evidence Surfaced)',
    category: 'Incident Report',
    status: 'replied',
    priority: 'medium',
    assignee: 'Sarem Worku',
    date: '2026-10-20T16:00:00Z',
    is_read: true,
    body: 'A secondary external firewall dump from the branch office contains correlated C2 beacons matching Cobalt Shadow timeline. Requesting status update to Open.',
    reply_thread: [
      {
        id: 'rep-04',
        author: 'Sarem Worku (Admin)',
        role: 'Administrator',
        message: 'Approved and reopened. Case status transitioned to Open and assigned to Marcus & Elena.',
        timestamp: '2026-10-20T17:30:00Z'
      }
    ]
  }
];

export const SEED_AUDIT_LOGS: AdminAuditEntry[] = [
  { id: 'aud-01', timestamp: '2026-10-23T06:14:22Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'USER_LOGIN', target_type: 'AUTH', target_id: 'sess-01', details: { method: 'PASSWORD_AND_2FA', ip: '192.168.1.104' }, ip_address: '192.168.1.104' },
  { id: 'aud-02', timestamp: '2026-10-23T05:48:10Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'EVIDENCE_VERIFY', case_id: 'case-cobalt-shadow', target_type: 'EVIDENCE', target_id: 'ev-01', details: { result: 'MATCH', hash: '9f86d081884c...' }, ip_address: '192.168.1.104' },
  { id: 'aud-03', timestamp: '2026-10-23T05:22:15Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'MESSAGE_STATUS_UPDATE', target_type: 'MESSAGE', target_id: 'msg-01', details: { from: 'unread', to: 'in_review' }, ip_address: '192.168.1.104' },
  { id: 'aud-04', timestamp: '2026-10-23T04:22:00Z', user_id: 'usr-inv-02', user_name: 'Elena Rostova', role: 'investigator', action: 'USER_LOGIN', target_type: 'AUTH', target_id: 'sess-04', details: { method: 'PASSWORD', ip: '10.0.4.38' }, ip_address: '10.0.4.38' },
  { id: 'aud-05', timestamp: '2026-10-23T03:50:11Z', user_id: 'usr-inv-02', user_name: 'Elena Rostova', role: 'investigator', action: 'TIMELINE_QUERY', case_id: 'case-darklock', target_type: 'TIMELINE', target_id: 'case-darklock', details: { span: '48h', filter: 'RDP_LOGON' }, ip_address: '10.0.4.38' },
  { id: 'aud-06', timestamp: '2026-10-23T02:18:40Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'SIGMA_RULE_ENABLE', target_type: 'RULE', target_id: 'sig-01', details: { rule: 'LSASS Memory Dump' }, ip_address: '192.168.1.104' },
  { id: 'aud-07', timestamp: '2026-10-23T01:05:00Z', user_id: 'system', user_name: 'SYSTEM_DAEMON', role: 'system', action: 'PARSER_QUEUE_SWEEP', target_type: 'SYSTEM', target_id: 'queue-sweep', details: { files_checked: 8, queue_clean: true }, ip_address: '127.0.0.1' },
  { id: 'aud-08', timestamp: '2026-10-22T23:40:19Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'CASE_LEGAL_HOLD_SET', case_id: 'case-darklock', target_type: 'CASE', target_id: 'case-darklock', details: { status: true, reason: 'Subpoena 2026-CV-889' }, ip_address: '192.168.1.104' },
  { id: 'aud-09', timestamp: '2026-10-22T22:15:30Z', user_id: 'usr-aud-01', user_name: 'David Kim', role: 'auditor', action: 'AUDIT_EXPORT_CSV', target_type: 'AUDIT', target_id: 'export-csv', details: { count: 38, format: 'RFC-4180' }, ip_address: '172.16.0.5' },
  { id: 'aud-10', timestamp: '2026-10-22T20:10:00Z', user_id: 'usr-aud-01', user_name: 'David Kim', role: 'auditor', action: 'MESSAGE_REPLY', target_type: 'MESSAGE', target_id: 'msg-03', details: { text_length: 124 }, ip_address: '172.16.0.5' },
  { id: 'aud-11', timestamp: '2026-10-22T19:40:10Z', user_id: 'usr-inv-01', user_name: 'Marcus Vance', role: 'investigator', action: 'USER_LOGIN', target_type: 'AUTH', target_id: 'sess-03', details: { method: 'PASSWORD_AND_2FA', ip: '10.0.4.22' }, ip_address: '10.0.4.22' },
  { id: 'aud-12', timestamp: '2026-10-22T18:12:00Z', user_id: 'usr-inv-01', user_name: 'Marcus Vance', role: 'investigator', action: 'CASE_ASSIGNMENT', case_id: 'case-cobalt-shadow', target_type: 'CASE', target_id: 'case-cobalt-shadow', details: { assignee: 'Marcus Vance' }, ip_address: '10.0.4.22' },
  { id: 'aud-13', timestamp: '2026-10-22T17:05:44Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'USER_UPDATE_ROLE', target_type: 'USER', target_id: 'usr-inv-02', details: { role: 'investigator' }, ip_address: '192.168.1.104' },
  { id: 'aud-14', timestamp: '2026-10-22T15:30:00Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'MESSAGE_REPLY', target_type: 'MESSAGE', target_id: 'msg-04', details: { text_length: 98 }, ip_address: '192.168.1.104' },
  { id: 'aud-15', timestamp: '2026-10-22T14:15:20Z', user_id: 'usr-inv-01', user_name: 'Marcus Vance', role: 'investigator', action: 'EVIDENCE_UPLOAD', case_id: 'case-cobalt-shadow', target_type: 'EVIDENCE', target_id: 'ev-04', details: { filename: 'compromised_hosts_audit.csv' }, ip_address: '10.0.4.22' },
  { id: 'aud-16', timestamp: '2026-10-22T12:08:00Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'SECURITY_CONFIG_UPDATE', target_type: 'SETTINGS', target_id: 'security', details: { min_password_length: 12, lockout_limit: 5 }, ip_address: '192.168.1.104' },
  { id: 'aud-17', timestamp: '2026-10-22T10:45:00Z', user_id: 'system', user_name: 'SYSTEM_DAEMON', role: 'system', action: 'PARSER_FAILURE_LOGGED', target_type: 'EVIDENCE', target_id: 'ev-08', details: { error: 'header magic mismatch' }, ip_address: '127.0.0.1' },
  { id: 'aud-18', timestamp: '2026-10-22T09:30:00Z', user_id: 'usr-inv-02', user_name: 'Elena Rostova', role: 'investigator', action: 'ATTACK_GRAPH_GENERATE', case_id: 'case-darklock', target_type: 'GRAPH', target_id: 'graph-02', details: { nodes: 18, edges: 24 }, ip_address: '10.0.4.38' },
  { id: 'aud-19', timestamp: '2026-10-22T08:15:10Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'SESSION_TERMINATED', target_type: 'USER', target_id: 'usr-inv-01', details: { session_id: 'old-sess-99', reason: 'Admin Force Logout' }, ip_address: '192.168.1.104' },
  { id: 'aud-20', timestamp: '2026-10-22T06:55:00Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'MESSAGE_MARK_SPAM', target_type: 'MESSAGE', target_id: 'msg-06', details: { sender: 'contact@boost-searches-quick.biz' }, ip_address: '192.168.1.104' },
  { id: 'aud-21', timestamp: '2026-10-21T22:10:40Z', user_id: 'usr-aud-01', user_name: 'David Kim', role: 'auditor', action: 'USER_LOGIN', target_type: 'AUTH', target_id: 'sess-05', details: { method: 'PASSWORD_AND_2FA', ip: '172.16.0.5' }, ip_address: '172.16.0.5' },
  { id: 'aud-22', timestamp: '2026-10-21T21:05:00Z', user_id: 'usr-aud-01', user_name: 'David Kim', role: 'auditor', action: 'CHAIN_OF_CUSTODY_VERIFY', case_id: 'case-cobalt-shadow', target_type: 'LEDGER', target_id: 'ledger-root', details: { verified_hashes: 5, status: 'PASS' }, ip_address: '172.16.0.5' },
  { id: 'aud-23', timestamp: '2026-10-21T18:44:12Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'SIGMA_RULE_CREATE', target_type: 'RULE', target_id: 'sig-06', details: { name: 'DNS Tunneling' }, ip_address: '192.168.1.104' },
  { id: 'aud-24', timestamp: '2026-10-21T16:15:00Z', user_id: 'usr-inv-01', user_name: 'Marcus Vance', role: 'investigator', action: 'EVIDENCE_UPLOAD', case_id: 'case-cobalt-shadow', target_type: 'EVIDENCE', target_id: 'ev-03', details: { filename: 'nginx_access_dmz.log' }, ip_address: '10.0.4.22' },
  { id: 'aud-25', timestamp: '2026-10-21T14:30:00Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'CASE_STATUS_UPDATE', case_id: 'case-darklock', target_type: 'CASE', target_id: 'case-darklock', details: { from: 'open', to: 'under_review' }, ip_address: '192.168.1.104' },
  { id: 'aud-26', timestamp: '2026-10-21T11:20:00Z', user_id: 'system', user_name: 'AUTH_GATEWAY', role: 'system', action: 'FAILED_LOGIN_ATTEMPT', target_type: 'AUTH', target_id: 'unknown-user', details: { username: 'root', ip: '185.220.101.5', reason: 'Invalid user' }, ip_address: '185.220.101.5' },
  { id: 'aud-27', timestamp: '2026-10-21T11:21:05Z', user_id: 'system', user_name: 'AUTH_GATEWAY', role: 'system', action: 'FAILED_LOGIN_ATTEMPT', target_type: 'AUTH', target_id: 'unknown-user', details: { username: 'administrator', ip: '185.220.101.5', reason: 'Invalid password' }, ip_address: '185.220.101.5' },
  { id: 'aud-28', timestamp: '2026-10-21T10:15:00Z', user_id: 'usr-inv-01', user_name: 'Marcus Vance', role: 'investigator', action: 'MESSAGE_REPLY', target_type: 'MESSAGE', target_id: 'msg-07', details: { text_length: 87 }, ip_address: '10.0.4.22' },
  { id: 'aud-29', timestamp: '2026-10-21T08:00:00Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'CASE_CREATE', case_id: 'case-cobalt-shadow', target_type: 'CASE', target_id: 'case-cobalt-shadow', details: { title: 'Operation Cobalt Shadow' }, ip_address: '192.168.1.104' },
  { id: 'aud-30', timestamp: '2026-10-20T17:30:00Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'MESSAGE_REPLY', target_type: 'MESSAGE', target_id: 'msg-08', details: { text_length: 82 }, ip_address: '192.168.1.104' },
  { id: 'aud-31', timestamp: '2026-10-20T15:10:00Z', user_id: 'usr-inv-02', user_name: 'Elena Rostova', role: 'investigator', action: 'EVIDENCE_UPLOAD', case_id: 'case-darklock', target_type: 'EVIDENCE', target_id: 'ev-08', details: { filename: 'corrupted_memory_dump_notes.txt' }, ip_address: '10.0.4.38' },
  { id: 'aud-32', timestamp: '2026-10-20T13:45:00Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'USER_CREATE', target_type: 'USER', target_id: 'usr-inv-02', details: { email: 'e.rostova@dcsre.net', role: 'investigator' }, ip_address: '192.168.1.104' },
  { id: 'aud-33', timestamp: '2026-10-20T11:20:18Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'SETTINGS_BRANDING_UPDATE', target_type: 'SETTINGS', target_id: 'branding', details: { org_name: 'አሻራ Cyber Forensic Command' }, ip_address: '192.168.1.104' },
  { id: 'aud-34', timestamp: '2026-10-20T09:15:00Z', user_id: 'usr-inv-01', user_name: 'Marcus Vance', role: 'investigator', action: 'FINDINGS_GENERATE', case_id: 'case-darklock', target_type: 'FINDINGS', target_id: 'findings-darklock', details: { count: 12 }, ip_address: '10.0.4.22' },
  { id: 'aud-35', timestamp: '2026-10-19T21:40:00Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'PASSWORD_RESET_TRIGGER', target_type: 'USER', target_id: 'usr-inv-01', details: { initiated_by: 'admin' }, ip_address: '192.168.1.104' },
  { id: 'aud-36', timestamp: '2026-10-19T18:00:00Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'USER_2FA_TOGGLE', target_type: 'USER', target_id: 'usr-admin', details: { enabled: true }, ip_address: '192.168.1.104' },
  { id: 'aud-37', timestamp: '2026-10-19T16:20:45Z', user_id: 'usr-inv-02', user_name: 'Elena Rostova', role: 'investigator', action: 'EVIDENCE_UPLOAD', case_id: 'case-cobalt-shadow', target_type: 'EVIDENCE', target_id: 'ev-02', details: { filename: 'edge_firewall_traffic.pcap' }, ip_address: '10.0.4.38' },
  { id: 'aud-38', timestamp: '2026-10-19T14:10:00Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'EVIDENCE_UPLOAD', case_id: 'case-cobalt-shadow', target_type: 'EVIDENCE', target_id: 'ev-05', details: { filename: 'ad_schema_telemetry.json' }, ip_address: '192.168.1.104' },
  { id: 'aud-39', timestamp: '2026-10-18T15:02:10Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'EVIDENCE_UPLOAD', case_id: 'case-cobalt-shadow', target_type: 'EVIDENCE', target_id: 'ev-01', details: { filename: 'Security_DC01_auth.evtx' }, ip_address: '192.168.1.104' },
  { id: 'aud-40', timestamp: '2026-10-18T14:32:00Z', user_id: 'usr-admin', user_name: 'Sarem Worku', role: 'admin', action: 'CASE_CREATE', case_id: 'case-darklock', target_type: 'CASE', target_id: 'case-darklock', details: { title: 'Financial Core Breach' }, ip_address: '192.168.1.104' }
];

export const SEED_SYSTEM_HEALTH: AdminSystemHealth = {
  parsers: [
    { type: 'EVTX', status: 'online', success_rate: '99.4%', avg_latency: '420 ms', files_processed: 240 },
    { type: 'PCAP', status: 'online', success_rate: '98.1%', avg_latency: '1.8 s', files_processed: 120 },
    { type: 'LOG', status: 'online', success_rate: '99.9%', avg_latency: '85 ms', files_processed: 890 },
    { type: 'CSV', status: 'online', success_rate: '100%', avg_latency: '45 ms', files_processed: 310 },
    { type: 'JSON', status: 'online', success_rate: '100%', avg_latency: '60 ms', files_processed: 480 },
    { type: 'XML', status: 'online', success_rate: '97.8%', avg_latency: '120 ms', files_processed: 145 },
    { type: 'PDF', status: 'degraded', success_rate: '92.0%', avg_latency: '2.4 s', files_processed: 78 }
  ],
  queue: [
    { id: 'job-01', file_name: 'edge_fw_stream_chunk_04.pcap', parser_type: 'PCAP', status: 'processing', started_at: '2026-10-23T06:58:12Z' },
    { id: 'job-02', file_name: 'ad_replication_audit.evtx', parser_type: 'EVTX', status: 'processing', started_at: '2026-10-23T06:59:01Z' },
    { id: 'job-03', file_name: 'corrupted_memory_dump_notes.txt', parser_type: 'TXT', status: 'failed', started_at: '2026-10-23T06:45:00Z', error: 'header magic mismatch [0x00000000]' }
  ],
  storage_used_bytes: 51754352640, // 48.2 GB
  storage_total_bytes: 268435456000, // 250 GB
  failed_logins_24h: 3,
  recent_errors: [
    { timestamp: '2026-10-23T06:45:00Z', component: 'TXT Parser', message: 'Parser crashed on invalid EOF in corrupted_memory_dump_notes.txt' },
    { timestamp: '2026-10-23T01:14:00Z', component: 'Network Watcher', message: 'PCAP ring buffer dropped 14 frames during burst transmission' },
    { timestamp: '2026-10-22T19:22:15Z', component: 'Auth Gateway', message: 'External brute-force attempt blocked at IP 185.220.101.5' }
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
