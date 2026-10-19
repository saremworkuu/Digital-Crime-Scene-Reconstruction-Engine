import { Case, EvidenceFile, NormalizedEvent, DetectionResult, AttackGraphData } from '../types';

export interface ScenarioBundle {
  caseData: Case;
  evidenceFiles: EvidenceFile[];
  events: NormalizedEvent[];
  detections: DetectionResult[];
  graphData: AttackGraphData;
}

// -------------------------------------------------------------
// SCENARIO 1: Operation "Cobalt Shadow"
// Web Shell Infiltration -> Privilege Escalation -> Lateral Movement to Domain Controller -> C2 Exfiltration
// -------------------------------------------------------------
const cobaltShadowEvidence: EvidenceFile[] = [
  {
    id: 'ev-cs-01',
    case_id: 'case-cobalt-shadow',
    filename: 'nginx_access_2026-09-22.log',
    file_type: 'web_log',
    size_bytes: 412850,
    sha256_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    uploaded_at: '2026-09-22T08:15:30Z',
    uploader_name: 'Sarah Chen (Lead Forensics)',
    uploader_id: 'usr-sarah',
    status: 'Parsed',
    parser_used: 'web_server',
    event_count: 5,
    raw_sample: '198.51.100.42 - - [22/Sep/2026:03:14:22 +0000] "POST /uploads/shell.php?cmd=whoami HTTP/1.1" 200 45 "-" "curl/7.88.1"'
  },
  {
    id: 'ev-cs-02',
    case_id: 'case-cobalt-shadow',
    filename: 'auth.log',
    file_type: 'linux_auth',
    size_bytes: 1042300,
    sha256_hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    uploaded_at: '2026-09-22T08:20:10Z',
    uploader_name: 'Sarah Chen (Lead Forensics)',
    uploader_id: 'usr-sarah',
    status: 'Parsed',
    parser_used: 'linux_auth',
    event_count: 6,
    raw_sample: 'Sep 22 03:22:15 web01 sudo: www-data : TTY=pts/1 ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash'
  },
  {
    id: 'ev-cs-03',
    case_id: 'case-cobalt-shadow',
    filename: 'dc01_security_4624_4688.json',
    file_type: 'windows_evtx',
    size_bytes: 845200,
    sha256_hash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    uploaded_at: '2026-09-22T08:35:45Z',
    uploader_name: 'Marcus Vance (Investigator)',
    uploader_id: 'usr-marcus',
    status: 'Parsed',
    parser_used: 'windows_evtx',
    event_count: 6,
    raw_sample: '{"EventID": 4688, "TimeCreated": "2026-09-22T04:12:05Z", "TargetUserName": "admin_backup", "NewProcessName": "powershell.exe"}'
  },
  {
    id: 'ev-cs-04',
    case_id: 'case-cobalt-shadow',
    filename: 'edge_fw_pcap_summary.csv',
    file_type: 'pcap_summary',
    size_bytes: 320140,
    sha256_hash: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
    uploaded_at: '2026-09-22T09:10:00Z',
    uploader_name: 'Sarah Chen (Lead Forensics)',
    uploader_id: 'usr-sarah',
    status: 'Parsed',
    parser_used: 'pcap_summary',
    event_count: 5,
    raw_sample: 'timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets\n2026-09-22T04:45:10Z,192.168.1.50,198.51.100.42,54210,443,TCP,4892010,3420'
  }
];

const cobaltShadowEvents: NormalizedEvent[] = [
  {
    id: 'evt-cs-101',
    case_id: 'case-cobalt-shadow',
    evidence_id: 'ev-cs-01',
    timestamp: '2026-09-22T02:40:11Z',
    source_type: 'web_server',
    host: 'web01.corp.local',
    user: 'anonymous',
    src_ip: '198.51.100.42',
    dst_ip: '192.168.1.50',
    src_port: 48912,
    dst_port: 80,
    protocol: 'HTTP',
    action: 'Vulnerability Probe / Scan',
    outcome: 'failure',
    severity: 'low',
    raw: '198.51.100.42 - - [22/Sep/2026:02:40:11 +0000] "GET /api/v1/debug.php?test=../../etc/passwd HTTP/1.1" 404 162',
    mitre_technique: 'T1595.002',
    mitre_tactic: 'Reconnaissance',
    is_attack_path: true,
    attack_phase: '1. Reconnaissance'
  },
  {
    id: 'evt-cs-102',
    case_id: 'case-cobalt-shadow',
    evidence_id: 'ev-cs-01',
    timestamp: '2026-09-22T03:10:45Z',
    source_type: 'web_server',
    host: 'web01.corp.local',
    user: 'www-data',
    src_ip: '198.51.100.42',
    dst_ip: '192.168.1.50',
    src_port: 49004,
    dst_port: 443,
    protocol: 'HTTPS',
    action: 'Exploit Public-Facing Web Application (RCE File Upload)',
    outcome: 'success',
    severity: 'critical',
    raw: '198.51.100.42 - - [22/Sep/2026:03:10:45 +0000] "POST /uploads/avatar_temp.php HTTP/1.1" 200 412 "-" "Python-urllib/3.10"',
    mitre_technique: 'T1190',
    mitre_tactic: 'Initial Access',
    is_attack_path: true,
    attack_phase: '2. Initial Compromise'
  },
  {
    id: 'evt-cs-103',
    case_id: 'case-cobalt-shadow',
    evidence_id: 'ev-cs-01',
    timestamp: '2026-09-22T03:14:22Z',
    source_type: 'web_server',
    host: 'web01.corp.local',
    user: 'www-data',
    src_ip: '198.51.100.42',
    dst_ip: '192.168.1.50',
    src_port: 49015,
    dst_port: 443,
    protocol: 'HTTPS',
    process: '/bin/sh',
    action: 'Web Shell Interactive Command Execution (whoami / id)',
    outcome: 'success',
    severity: 'critical',
    raw: '198.51.100.42 - - [22/Sep/2026:03:14:22 +0000] "POST /uploads/shell.php?cmd=whoami;id;uname%20-a HTTP/1.1" 200 84',
    mitre_technique: 'T1505.003',
    mitre_tactic: 'Persistence',
    is_attack_path: true,
    attack_phase: '3. Execution & Persistence'
  },
  {
    id: 'evt-cs-104',
    case_id: 'case-cobalt-shadow',
    evidence_id: 'ev-cs-02',
    timestamp: '2026-09-22T03:22:15Z',
    source_type: 'linux_auth',
    host: 'web01.corp.local',
    user: 'www-data',
    process: 'sudo',
    action: 'Privilege Escalation via Sudo Caching (NOPASSWD /bin/bash)',
    outcome: 'success',
    severity: 'high',
    raw: 'Sep 22 03:22:15 web01 sudo: www-data : TTY=pts/1 ; PWD=/var/www/html/uploads ; USER=root ; COMMAND=/bin/bash',
    mitre_technique: 'T1548.003',
    mitre_tactic: 'Privilege Escalation',
    is_attack_path: true,
    attack_phase: '4. Privilege Escalation'
  },
  {
    id: 'evt-cs-105',
    case_id: 'case-cobalt-shadow',
    evidence_id: 'ev-cs-02',
    timestamp: '2026-09-22T03:35:40Z',
    source_type: 'linux_auth',
    host: 'web01.corp.local',
    user: 'root',
    process: 'cat',
    action: 'Access Credential Vault / Shadow File Dump',
    outcome: 'success',
    severity: 'high',
    raw: 'Sep 22 03:35:40 web01 auditd[1124]: type=SYSCALL arch=c000003e syscall=2 success=yes exit=3 a0=/etc/shadow',
    mitre_technique: 'T1003.008',
    mitre_tactic: 'Credential Access',
    is_attack_path: true,
    attack_phase: '5. Credential Access'
  },
  {
    id: 'evt-cs-106',
    case_id: 'case-cobalt-shadow',
    evidence_id: 'ev-cs-02',
    timestamp: '2026-09-22T03:52:04Z',
    source_type: 'linux_auth',
    host: 'web01.corp.local',
    user: 'admin_backup',
    src_ip: '192.168.1.50',
    dst_ip: '192.168.1.10',
    src_port: 52188,
    dst_port: 22,
    protocol: 'SSH',
    action: 'Lateral Movement: Outbound SSH to Core Domain Controller',
    outcome: 'success',
    severity: 'critical',
    raw: 'Sep 22 03:52:04 web01 ssh[4912]: OpenSSH_9.2 initiated connection from 192.168.1.50:52188 to 192.168.1.10:22 user admin_backup',
    mitre_technique: 'T1021.004',
    mitre_tactic: 'Lateral Movement',
    is_attack_path: true,
    attack_phase: '6. Lateral Movement'
  },
  {
    id: 'evt-cs-107',
    case_id: 'case-cobalt-shadow',
    evidence_id: 'ev-cs-03',
    timestamp: '2026-09-22T03:52:15Z',
    source_type: 'windows_evtx',
    host: 'dc01.corp.local',
    user: 'admin_backup',
    src_ip: '192.168.1.50',
    dst_ip: '192.168.1.10',
    action: 'Successful Network Logon (EventID 4624 - Logon Type 3)',
    outcome: 'success',
    severity: 'medium',
    raw: '{"EventID": 4624, "LogonType": 3, "TargetUserName": "admin_backup", "WorkstationName": "web01", "IpAddress": "192.168.1.50"}',
    mitre_technique: 'T1078.002',
    mitre_tactic: 'Defense Evasion',
    is_attack_path: true,
    attack_phase: '6. Lateral Movement'
  },
  {
    id: 'evt-cs-108',
    case_id: 'case-cobalt-shadow',
    evidence_id: 'ev-cs-03',
    timestamp: '2026-09-22T04:12:05Z',
    source_type: 'windows_evtx',
    host: 'dc01.corp.local',
    user: 'admin_backup',
    process: 'powershell.exe',
    action: 'PowerShell Encoded Command & NTDS.dit Extraction (EventID 4688)',
    outcome: 'success',
    severity: 'critical',
    raw: '{"EventID": 4688, "NewProcessName": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "CommandLine": "powershell -enc JABzAD0AbgBlAHcALQBvAGIAagBlAGMAdAA... (ntdsutil ac i ntds create full C:\\\\temp\\\\dc_dump q q)"}',
    mitre_technique: 'T1059.001',
    mitre_tactic: 'Execution',
    is_attack_path: true,
    attack_phase: '7. Credential Extraction'
  },
  {
    id: 'evt-cs-109',
    case_id: 'case-cobalt-shadow',
    evidence_id: 'ev-cs-04',
    timestamp: '2026-09-22T04:45:10Z',
    source_type: 'pcap_summary',
    host: 'web01.corp.local',
    user: 'root',
    src_ip: '192.168.1.50',
    dst_ip: '198.51.100.42',
    src_port: 54210,
    dst_port: 443,
    protocol: 'TCP',
    action: 'High-Volume C2 Exfiltration over TLS Tunnel (4.89 MB)',
    outcome: 'success',
    severity: 'critical',
    raw: 'FLOW 192.168.1.50:54210 -> 198.51.100.42:443 [TLSv1.3 Application Data] Bytes: 4892010 Packets: 3420 Duration: 142s',
    mitre_technique: 'T1041',
    mitre_tactic: 'Exfiltration',
    is_attack_path: true,
    attack_phase: '8. Data Exfiltration'
  },
  {
    id: 'evt-cs-110',
    case_id: 'case-cobalt-shadow',
    evidence_id: 'ev-cs-04',
    timestamp: '2026-09-22T05:00:00Z',
    source_type: 'pcap_summary',
    host: 'web01.corp.local',
    user: 'system',
    src_ip: '192.168.1.50',
    dst_ip: '198.51.100.42',
    src_port: 54300,
    dst_port: 8443,
    protocol: 'TCP',
    action: 'Periodic C2 Heartbeat Beaconing (Interval: 60s)',
    outcome: 'success',
    severity: 'high',
    raw: 'FLOW 192.168.1.50:54300 -> 198.51.100.42:8443 [SYN/ACK/DATA] Periodic pulse matching Cobalt Strike Malleable C2 profile',
    mitre_technique: 'T1071.001',
    mitre_tactic: 'Command and Control',
    is_attack_path: true,
    attack_phase: '9. Command & Control'
  }
];

const cobaltShadowDetections: DetectionResult[] = [
  {
    id: 'det-cs-01',
    case_id: 'case-cobalt-shadow',
    rule_id: 'rule-web-shell-access',
    rule_name: 'Suspicious Web Shell Access Pattern',
    severity: 'critical',
    mitre_technique: 'T1505.003',
    mitre_tactic: 'Persistence',
    timestamp: '2026-09-22T03:14:22Z',
    description: 'Adversary leveraged uploaded script shell.php with cmd parameter to execute arbitrary shell commands on web01.',
    matched_event_ids: ['evt-cs-103'],
    false_positive: false,
    entities_involved: {
      hosts: ['web01.corp.local'],
      users: ['www-data'],
      ips: ['198.51.100.42', '192.168.1.50']
    }
  },
  {
    id: 'det-cs-02',
    case_id: 'case-cobalt-shadow',
    rule_id: 'rule-sudo-priv-esc',
    rule_name: 'Sudo Abuse or Unauthorized Privilege Escalation',
    severity: 'high',
    mitre_technique: 'T1548.003',
    mitre_tactic: 'Privilege Escalation',
    timestamp: '2026-09-22T03:22:15Z',
    description: 'Service account www-data spawned an interactive root bash shell using sudo without password prompt.',
    matched_event_ids: ['evt-cs-104'],
    false_positive: false,
    entities_involved: {
      hosts: ['web01.corp.local'],
      users: ['www-data', 'root']
    }
  },
  {
    id: 'det-cs-03',
    case_id: 'case-cobalt-shadow',
    rule_id: 'rule-powershell-encoded',
    rule_name: 'Suspicious Encoded PowerShell Execution',
    severity: 'critical',
    mitre_technique: 'T1059.001',
    mitre_tactic: 'Execution',
    timestamp: '2026-09-22T04:12:05Z',
    description: 'Adversary executed obfuscated base64 PowerShell command on DC01 targeting Active Directory database (NTDS.dit).',
    matched_event_ids: ['evt-cs-108'],
    false_positive: false,
    entities_involved: {
      hosts: ['dc01.corp.local'],
      users: ['admin_backup']
    }
  },
  {
    id: 'det-cs-04',
    case_id: 'case-cobalt-shadow',
    rule_id: 'rule-c2-beaconing',
    rule_name: 'High-Frequency C2 Beaconing to External IP',
    severity: 'high',
    mitre_technique: 'T1071.001',
    mitre_tactic: 'Command and Control',
    timestamp: '2026-09-22T05:00:00Z',
    description: 'Persistent outbound beaconing connection from internal server 192.168.1.50 to known malicious external IP 198.51.100.42.',
    matched_event_ids: ['evt-cs-110'],
    false_positive: false,
    entities_involved: {
      hosts: ['web01.corp.local'],
      ips: ['192.168.1.50', '198.51.100.42']
    }
  }
];

const cobaltShadowGraph: AttackGraphData = {
  nodes: [
    {
      id: 'node-ext-ip',
      label: '198.51.100.42 (Adversary C2)',
      type: 'ip',
      is_compromised: true,
      is_attack_path: true,
      event_count: 5,
      first_seen: '2026-09-22T02:40:11Z',
      last_seen: '2026-09-22T05:00:00Z',
      details: { geo: 'External / Threat Feed Match', threat_actor: 'Cobalt Shadow APT' }
    },
    {
      id: 'node-web01',
      label: 'web01.corp.local (192.168.1.50)',
      type: 'host',
      is_compromised: true,
      is_attack_path: true,
      event_count: 8,
      first_seen: '2026-09-22T02:40:11Z',
      last_seen: '2026-09-22T05:00:00Z',
      details: { os: 'Ubuntu 22.04 LTS', role: 'Public DMZ Web Application' }
    },
    {
      id: 'node-usr-www',
      label: 'user: www-data',
      type: 'user',
      is_compromised: true,
      is_attack_path: true,
      event_count: 4,
      details: { uid: 33, privileges: 'Service Account (Escalated to root)' }
    },
    {
      id: 'node-usr-root',
      label: 'user: root',
      type: 'user',
      is_compromised: true,
      is_attack_path: true,
      event_count: 3,
      details: { uid: 0, privileges: 'Superuser / Full Control' }
    },
    {
      id: 'node-usr-backup',
      label: 'user: admin_backup',
      type: 'user',
      is_compromised: true,
      is_attack_path: true,
      event_count: 4,
      details: { domain: 'CORP', role: 'Domain Backup Operator (High Privilege)' }
    },
    {
      id: 'node-dc01',
      label: 'dc01.corp.local (192.168.1.10)',
      type: 'host',
      is_compromised: true,
      is_attack_path: true,
      event_count: 4,
      first_seen: '2026-09-22T03:52:15Z',
      last_seen: '2026-09-22T04:12:05Z',
      details: { os: 'Windows Server 2022', role: 'Enterprise Domain Controller' }
    },
    {
      id: 'node-db01',
      label: 'db01.corp.local (192.168.1.60)',
      type: 'host',
      is_compromised: false,
      is_attack_path: false,
      event_count: 2,
      details: { os: 'Debian 12', role: 'Internal PostgreSQL Cluster' }
    },
    {
      id: 'node-ntds',
      label: 'NTDS.dit (Active Directory DB)',
      type: 'file',
      is_compromised: true,
      is_attack_path: true,
      event_count: 2,
      details: { path: 'C:\\Windows\\NTDS\\ntds.dit', status: 'Exfiltrated' }
    }
  ],
  edges: [
    {
      id: 'edge-1',
      source: 'node-ext-ip',
      target: 'node-web01',
      label: 'Exploit (CVE-2023-xxxx RCE)',
      protocol: 'HTTPS/443',
      timestamp: '2026-09-22T03:10:45Z',
      count: 2,
      is_attack_path: true,
      severity: 'critical'
    },
    {
      id: 'edge-2',
      source: 'node-web01',
      target: 'node-usr-www',
      label: 'Spawn Web Shell (/bin/sh)',
      timestamp: '2026-09-22T03:14:22Z',
      count: 1,
      is_attack_path: true,
      severity: 'critical'
    },
    {
      id: 'edge-3',
      source: 'node-usr-www',
      target: 'node-usr-root',
      label: 'sudo NOPASSWD /bin/bash',
      timestamp: '2026-09-22T03:22:15Z',
      count: 1,
      is_attack_path: true,
      severity: 'high'
    },
    {
      id: 'edge-4',
      source: 'node-usr-root',
      target: 'node-usr-backup',
      label: 'Extract Cached Credential',
      timestamp: '2026-09-22T03:35:40Z',
      count: 1,
      is_attack_path: true,
      severity: 'high'
    },
    {
      id: 'edge-5',
      source: 'node-web01',
      target: 'node-dc01',
      label: 'Lateral Move (SSH / Port 22)',
      protocol: 'SSH',
      timestamp: '2026-09-22T03:52:04Z',
      count: 1,
      is_attack_path: true,
      severity: 'critical'
    },
    {
      id: 'edge-6',
      source: 'node-usr-backup',
      target: 'node-dc01',
      label: 'Logon Type 3 (Admin Session)',
      timestamp: '2026-09-22T03:52:15Z',
      count: 1,
      is_attack_path: true,
      severity: 'medium'
    },
    {
      id: 'edge-7',
      source: 'node-dc01',
      target: 'node-ntds',
      label: 'PowerShell NTDS Dump',
      timestamp: '2026-09-22T04:12:05Z',
      count: 1,
      is_attack_path: true,
      severity: 'critical'
    },
    {
      id: 'edge-8',
      source: 'node-web01',
      target: 'node-ext-ip',
      label: 'Exfiltrate Data (4.89 MB TLS)',
      protocol: 'TLS/443',
      timestamp: '2026-09-22T04:45:10Z',
      count: 1,
      is_attack_path: true,
      severity: 'critical'
    },
    {
      id: 'edge-9',
      source: 'node-web01',
      target: 'node-db01',
      label: 'Routine App DB Connection',
      protocol: 'PGSQL/5432',
      timestamp: '2026-09-22T02:00:00Z',
      count: 142,
      is_attack_path: false,
      severity: 'low'
    }
  ]
};

export const SCENARIO_COBALT_SHADOW: ScenarioBundle = {
  caseData: {
    id: 'case-cobalt-shadow',
    name: 'Operation Cobalt Shadow: DMZ Web Exploit to Domain Controller Compromise',
    description: 'Complex multi-stage advanced threat investigation. Initial perimeter breach via web shell on Linux DMZ server web01, local privilege escalation to root via sudo caching, harvesting of domain backup operator credentials, lateral movement into core Windows Domain Controller DC01, followed by NTDS exfiltration over TLS tunnel.',
    status: 'In Progress',
    created_at: '2026-09-22T08:00:00Z',
    updated_at: '2026-09-22T10:45:00Z',
    owner_id: 'usr-sarah',
    owner_name: 'Sarah Chen (Lead Forensics)',
    assigned_users: ['Sarah Chen (Lead Forensics)', 'Marcus Vance (Investigator)', 'Elena Rostova (DevOps/QA)'],
    evidence_count: 4,
    event_count: 10,
    detection_count: 4,
    critical_detection_count: 2,
    time_start: '2026-09-22T02:40:11Z',
    time_end: '2026-09-22T05:00:00Z',
    tags: ['APT', 'WebShell', 'LateralMovement', 'NTDSDump', 'ActiveDirectory']
  },
  evidenceFiles: cobaltShadowEvidence,
  events: cobaltShadowEvents,
  detections: cobaltShadowDetections,
  graphData: cobaltShadowGraph
};

// -------------------------------------------------------------
// SCENARIO 2: Ransomware Outbreak "DarkLock"
// -------------------------------------------------------------
export const SCENARIO_DARKLOCK: ScenarioBundle = {
  caseData: {
    id: 'case-darklock',
    name: 'DarkLock Ransomware Outbreak: Finance Workstation to NAS',
    description: 'Rapid-onset cryptographic ransomware infection originating from malicious invoice attachment on workstation WS-FIN-04. Volume shadow copies purged via vssadmin and administrative SMB encryption observed targeting network storage FS01.',
    status: 'Open',
    created_at: '2026-09-24T14:10:00Z',
    updated_at: '2026-09-24T16:30:00Z',
    owner_id: 'usr-marcus',
    owner_name: 'Marcus Vance (Investigator)',
    assigned_users: ['Marcus Vance (Investigator)', 'Sarah Chen (Lead Forensics)'],
    evidence_count: 2,
    event_count: 6,
    detection_count: 3,
    critical_detection_count: 2,
    time_start: '2026-09-24T13:45:00Z',
    time_end: '2026-09-24T14:30:00Z',
    tags: ['Ransomware', 'PowerShell', 'VSSDeletion', 'Workstation']
  },
  evidenceFiles: [
    {
      id: 'ev-dl-01',
      case_id: 'case-darklock',
      filename: 'ws_fin_04_sysmon_events.json',
      file_type: 'windows_evtx',
      size_bytes: 512900,
      sha256_hash: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
      uploaded_at: '2026-09-24T14:20:00Z',
      uploader_name: 'Marcus Vance',
      uploader_id: 'usr-marcus',
      status: 'Parsed',
      parser_used: 'windows_evtx',
      event_count: 4
    },
    {
      id: 'ev-dl-02',
      case_id: 'case-darklock',
      filename: 'fs01_storage_audit.log',
      file_type: 'generic_json_csv',
      size_bytes: 284100,
      sha256_hash: 'b2c3d4e5f6a17890123456789abcdef0123456789abcdef0123456789abcdef1',
      uploaded_at: '2026-09-24T14:35:00Z',
      uploader_name: 'Marcus Vance',
      uploader_id: 'usr-marcus',
      status: 'Parsed',
      parser_used: 'generic_json_csv',
      event_count: 2
    }
  ],
  events: [
    {
      id: 'evt-dl-201',
      case_id: 'case-darklock',
      evidence_id: 'ev-dl-01',
      timestamp: '2026-09-24T13:45:12Z',
      source_type: 'windows_evtx',
      host: 'ws-fin-04.corp.local',
      user: 'alice.finance',
      process: 'outlook.exe',
      action: 'Email Attachment Executed (Invoice_Q3.pdf.exe)',
      outcome: 'success',
      severity: 'high',
      raw: 'Sysmon EventID 1: ParentImage=outlook.exe Image=C:\\Users\\alice.finance\\Downloads\\Invoice_Q3.pdf.exe',
      mitre_technique: 'T1566.001',
      mitre_tactic: 'Initial Access',
      is_attack_path: true,
      attack_phase: '1. Phishing Execution'
    },
    {
      id: 'evt-dl-202',
      case_id: 'case-darklock',
      evidence_id: 'ev-dl-01',
      timestamp: '2026-09-24T13:46:02Z',
      source_type: 'windows_evtx',
      host: 'ws-fin-04.corp.local',
      user: 'alice.finance',
      process: 'powershell.exe',
      action: 'Obfuscated PowerShell Downloader Launched',
      outcome: 'success',
      severity: 'critical',
      raw: 'Sysmon EventID 1: powershell.exe -enc SQBFACgAJABQ... (DownloadString payload)',
      mitre_technique: 'T1059.001',
      mitre_tactic: 'Execution',
      is_attack_path: true,
      attack_phase: '2. Payload Retrieval'
    },
    {
      id: 'evt-dl-203',
      case_id: 'case-darklock',
      evidence_id: 'ev-dl-01',
      timestamp: '2026-09-24T13:47:45Z',
      source_type: 'windows_evtx',
      host: 'ws-fin-04.corp.local',
      user: 'alice.finance',
      process: 'vssadmin.exe',
      action: 'Volume Shadow Copies Deletion (vssadmin delete shadows /all /quiet)',
      outcome: 'success',
      severity: 'critical',
      raw: 'Sysmon EventID 1: Image=C:\\Windows\\System32\\vssadmin.exe CommandLine="vssadmin delete shadows /all /quiet"',
      mitre_technique: 'T1490',
      mitre_tactic: 'Impact',
      is_attack_path: true,
      attack_phase: '3. Inhibit System Recovery'
    },
    {
      id: 'evt-dl-204',
      case_id: 'case-darklock',
      evidence_id: 'ev-dl-02',
      timestamp: '2026-09-24T14:15:30Z',
      source_type: 'generic_json_csv',
      host: 'fs01.corp.local',
      user: 'alice.finance',
      src_ip: '10.0.4.12',
      dst_ip: '10.0.1.20',
      action: 'Bulk File Modification on SMB Share \\\\fs01\\Finance\\*.locked',
      outcome: 'success',
      severity: 'critical',
      raw: 'SMB2_WRITE: 1,842 files renamed with extension .darklock in 180 seconds',
      mitre_technique: 'T1486',
      mitre_tactic: 'Impact',
      is_attack_path: true,
      attack_phase: '4. Data Encryption for Impact'
    }
  ],
  detections: [
    {
      id: 'det-dl-01',
      case_id: 'case-darklock',
      rule_id: 'rule-powershell-encoded',
      rule_name: 'Suspicious Encoded PowerShell Execution',
      severity: 'critical',
      mitre_technique: 'T1059.001',
      mitre_tactic: 'Execution',
      timestamp: '2026-09-24T13:46:02Z',
      description: 'PowerShell executed with encoded parameters unpacking ransomware payload binary.',
      matched_event_ids: ['evt-dl-202'],
      false_positive: false,
      entities_involved: {
        hosts: ['ws-fin-04.corp.local'],
        users: ['alice.finance']
      }
    },
    {
      id: 'det-dl-02',
      case_id: 'case-darklock',
      rule_id: 'rule-vss-shadow-deletion',
      rule_name: 'Volume Shadow Copy Deletion (Ransomware Inhibitor)',
      severity: 'critical',
      mitre_technique: 'T1490',
      mitre_tactic: 'Impact',
      timestamp: '2026-09-24T13:47:45Z',
      description: 'vssadmin executed to suppress shadow storage volume recovery copies.',
      matched_event_ids: ['evt-dl-203'],
      false_positive: false,
      entities_involved: {
        hosts: ['ws-fin-04.corp.local'],
        users: ['alice.finance']
      }
    }
  ],
  graphData: {
    nodes: [
      { id: 'node-alice', label: 'alice.finance (Compromised User)', type: 'user', is_compromised: true, is_attack_path: true, event_count: 4 },
      { id: 'node-ws4', label: 'WS-FIN-04 (10.0.4.12)', type: 'host', is_compromised: true, is_attack_path: true, event_count: 3 },
      { id: 'node-fs01', label: 'FS01 Storage (10.0.1.20)', type: 'host', is_compromised: true, is_attack_path: true, event_count: 1 },
      { id: 'node-vss', label: 'Volume Shadow Copies', type: 'file', is_compromised: true, is_attack_path: true, event_count: 1 }
    ],
    edges: [
      { id: 'e-dl-1', source: 'node-alice', target: 'node-ws4', label: 'Exec Invoice_Q3.exe', timestamp: '2026-09-24T13:45:12Z', count: 1, is_attack_path: true, severity: 'high' },
      { id: 'e-dl-2', source: 'node-ws4', target: 'node-vss', label: 'vssadmin delete shadows', timestamp: '2026-09-24T13:47:45Z', count: 1, is_attack_path: true, severity: 'critical' },
      { id: 'e-dl-3', source: 'node-ws4', target: 'node-fs01', label: 'Mass SMB File Encryption', protocol: 'SMB/445', timestamp: '2026-09-24T14:15:30Z', count: 1, is_attack_path: true, severity: 'critical' }
    ]
  }
};

// -------------------------------------------------------------
// SCENARIO 3: Insider Threat & Data Exfiltration
// -------------------------------------------------------------
export const SCENARIO_INSIDER: ScenarioBundle = {
  caseData: {
    id: 'case-insider-exfil',
    name: 'Privileged Insider Intellectual Property Exfiltration',
    description: 'Post-resignation insider data theft investigation. Senior developer account utilized off-hours VPN to access restricted R&D git repositories, packaged source code into /tmp/core_fw.tar.gz and staged SFTP transfer to an unauthorized external server.',
    status: 'Closed',
    created_at: '2026-09-20T09:00:00Z',
    updated_at: '2026-09-21T18:00:00Z',
    owner_id: 'usr-sarah',
    owner_name: 'Sarah Chen (Lead Forensics)',
    assigned_users: ['Sarah Chen (Lead Forensics)', 'Investigator Alex'],
    evidence_count: 2,
    event_count: 5,
    detection_count: 2,
    critical_detection_count: 1,
    time_start: '2026-09-20T23:15:00Z',
    time_end: '2026-09-21T01:10:00Z',
    tags: ['InsiderThreat', 'DataTheft', 'ArchiveStaging', 'SFTP']
  },
  evidenceFiles: [
    {
      id: 'ev-in-01',
      case_id: 'case-insider-exfil',
      filename: 'vpn_access_audit.log',
      file_type: 'linux_auth',
      size_bytes: 182300,
      sha256_hash: 'c3d4e5f6a1b27890123456789abcdef0123456789abcdef0123456789abcdef2',
      uploaded_at: '2026-09-21T09:15:00Z',
      uploader_name: 'Sarah Chen',
      uploader_id: 'usr-sarah',
      status: 'Parsed',
      parser_used: 'linux_auth',
      event_count: 3
    }
  ],
  events: [
    {
      id: 'evt-in-301',
      case_id: 'case-insider-exfil',
      evidence_id: 'ev-in-01',
      timestamp: '2026-09-20T23:15:00Z',
      source_type: 'linux_auth',
      host: 'vpn-gw01.corp.local',
      user: 'j.miller',
      src_ip: '203.0.113.88',
      dst_ip: '10.0.0.1',
      action: 'Anomalous Off-Hours SSL-VPN Logon (Sunday 23:15)',
      outcome: 'success',
      severity: 'medium',
      raw: 'openvpn: Peer connection initiated with [AF_INET]203.0.113.88:41201 for user "j.miller"',
      mitre_technique: 'T1078.002',
      mitre_tactic: 'Initial Access',
      is_attack_path: true,
      attack_phase: '1. Unauthorized Access'
    },
    {
      id: 'evt-in-302',
      case_id: 'case-insider-exfil',
      evidence_id: 'ev-in-01',
      timestamp: '2026-09-20T23:42:10Z',
      source_type: 'linux_auth',
      host: 'git-core.corp.local',
      user: 'j.miller',
      process: 'tar',
      action: 'Data Staged in Compressed Archive: tar -czvf /tmp/core_fw.tar.gz',
      outcome: 'success',
      severity: 'high',
      raw: 'bash_history: tar -czvf /tmp/core_fw.tar.gz /var/git/firmware_v4/ /var/git/patents/',
      mitre_technique: 'T1560.001',
      mitre_tactic: 'Collection',
      is_attack_path: true,
      attack_phase: '2. Data Collection'
    },
    {
      id: 'evt-in-303',
      case_id: 'case-insider-exfil',
      evidence_id: 'ev-in-01',
      timestamp: '2026-09-21T00:18:40Z',
      source_type: 'linux_auth',
      host: 'git-core.corp.local',
      user: 'j.miller',
      process: 'sftp',
      src_ip: '10.0.2.15',
      dst_ip: '198.51.100.99',
      dst_port: 2222,
      protocol: 'SSH/SFTP',
      action: 'Outbound SFTP Exfiltration of /tmp/core_fw.tar.gz (1.24 GB)',
      outcome: 'success',
      severity: 'critical',
      raw: 'sftp[18942]: Sent /tmp/core_fw.tar.gz to 198.51.100.99:2222 (1300234120 bytes transferred)',
      mitre_technique: 'T1048.002',
      mitre_tactic: 'Exfiltration',
      is_attack_path: true,
      attack_phase: '3. Data Exfiltration'
    }
  ],
  detections: [
    {
      id: 'det-in-01',
      case_id: 'case-insider-exfil',
      rule_id: 'rule-mass-archive-staging',
      rule_name: 'Sensitive File Mass Archive Staging for Exfiltration',
      severity: 'medium',
      mitre_technique: 'T1560.001',
      mitre_tactic: 'Collection',
      timestamp: '2026-09-20T23:42:10Z',
      description: 'Creation of large archive core_fw.tar.gz in temporary folder by departing personnel.',
      matched_event_ids: ['evt-in-302'],
      false_positive: false,
      entities_involved: {
        hosts: ['git-core.corp.local'],
        users: ['j.miller']
      }
    }
  ],
  graphData: {
    nodes: [
      { id: 'node-jmiller', label: 'User: j.miller', type: 'user', is_compromised: true, is_attack_path: true, event_count: 3 },
      { id: 'node-git', label: 'git-core.corp.local', type: 'host', is_compromised: true, is_attack_path: true, event_count: 2 },
      { id: 'node-archive', label: '/tmp/core_fw.tar.gz', type: 'file', is_compromised: true, is_attack_path: true, event_count: 2 },
      { id: 'node-vps', label: '198.51.100.99 (Offshore VPS)', type: 'ip', is_compromised: true, is_attack_path: true, event_count: 1 }
    ],
    edges: [
      { id: 'e-in-1', source: 'node-jmiller', target: 'node-git', label: 'Off-hours VPN Access', timestamp: '2026-09-20T23:15:00Z', count: 1, is_attack_path: true, severity: 'medium' },
      { id: 'e-in-2', source: 'node-git', target: 'node-archive', label: 'tar -czvf IP archive', timestamp: '2026-09-20T23:42:10Z', count: 1, is_attack_path: true, severity: 'high' },
      { id: 'e-in-3', source: 'node-archive', target: 'node-vps', label: 'SFTP Exfiltration (1.24 GB)', protocol: 'SFTP/2222', timestamp: '2026-09-21T00:18:40Z', count: 1, is_attack_path: true, severity: 'critical' }
    ]
  }
};

export const INITIAL_SCENARIOS = [
  SCENARIO_COBALT_SHADOW,
  SCENARIO_DARKLOCK
];
