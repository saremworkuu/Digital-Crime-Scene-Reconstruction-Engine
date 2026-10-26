import { Case, EvidenceFile, NormalizedEvent, DetectionResult, AttackGraphData } from '../types';

export interface ScenarioBundle {
  caseData: Case;
  evidenceFiles: EvidenceFile[];
  events: NormalizedEvent[];
  detections: DetectionResult[];
  graphData: AttackGraphData;
}

// -------------------------------------------------------------
// REFERENCE SCENARIO: Operation "Cobalt Shadow"
// Maintained as a single baseline reference for comparison
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
    event_count: 3,
    raw_sample: '198.51.100.42 - - [22/Sep/2026:03:14:22 +0000] "POST /uploads/shell.php?cmd=whoami HTTP/1.1" 200 45 "-" "curl/7.88.1"'
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
      event_count: 3,
      first_seen: '2026-09-22T02:40:11Z',
      last_seen: '2026-09-22T03:14:22Z',
      details: { geo: 'External / Threat Feed Match', threat_actor: 'Cobalt Shadow APT' }
    },
    {
      id: 'node-web01',
      label: 'web01.corp.local (192.168.1.50)',
      type: 'host',
      is_compromised: true,
      is_attack_path: true,
      event_count: 3,
      first_seen: '2026-09-22T02:40:11Z',
      last_seen: '2026-09-22T03:14:22Z',
      details: { os: 'Ubuntu 22.04 LTS', role: 'Public DMZ Web Application' }
    },
    {
      id: 'node-usr-www',
      label: 'user: www-data',
      type: 'user',
      is_compromised: true,
      is_attack_path: true,
      event_count: 2,
      details: { uid: 33, privileges: 'Service Account' }
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
      count: 1,
      is_attack_path: true,
      severity: 'critical'
    },
    {
      id: 'edge-2',
      source: 'node-web01',
      target: 'node-usr-www',
      label: 'Spawn /bin/sh (whoami)',
      timestamp: '2026-09-22T03:14:22Z',
      count: 1,
      is_attack_path: true,
      severity: 'critical'
    }
  ]
};

export const SCENARIO_COBALT_SHADOW: ScenarioBundle = {
  caseData: {
    id: 'case-cobalt-shadow',
    name: 'Operation Cobalt Shadow - APT29 Infiltration',
    description: 'Active digital forensic inquiry investigating web shell deployment and unauthorized persistence.',
    status: 'Open',
    created_at: '2026-09-22T08:00:00Z',
    updated_at: '2026-09-22T09:30:00Z',
    owner_id: 'usr-admin',
    owner_name: 'Lead Forensics Examiner',
    assigned_users: ['Sarem Worku'],
    evidence_count: 1,
    event_count: 3,
    detection_count: 1,
    critical_detection_count: 1,
    tags: ['APT29', 'WebShell', 'RCE', 'Reference']
  },
  evidenceFiles: cobaltShadowEvidence,
  events: cobaltShadowEvents,
  detections: cobaltShadowDetections,
  graphData: cobaltShadowGraph
};

export const INITIAL_SCENARIOS: ScenarioBundle[] = [
  SCENARIO_COBALT_SHADOW
];
