/**
 * Pre-packaged Sigma-style detection rules matching Appendix B of the SRS.
 */
import { DetectionRule } from '../types';

export const INITIAL_SIGMA_RULES: DetectionRule[] = [
  {
    id: 'rule-web-shell-access',
    name: 'Suspicious Web Shell Access Pattern',
    description: 'Detects HTTP requests directed at known web shell filenames or executing interactive commands via web server processes.',
    severity: 'critical',
    mitre_technique: 'T1505.003',
    mitre_tactic: 'Persistence',
    author: 'አሻራ Forensics Team',
    status: 'active',
    yaml_content: `title: Suspicious Web Shell Access Pattern
id: rule-web-shell-access
status: test
description: Detects HTTP requests targeting known web shells or abnormal command execution
references:
  - https://attack.mitre.org/techniques/T1505/003/
tags:
  - attack.persistence
  - attack.t1505.003
logsource:
  category: webserver
detection:
  selection_path:
    - '*.php?cmd=*'
    - '*/shell.php'
    - '*/b374k.php'
    - '*/c99.php'
  condition: selection_path
level: critical`,
  },
  {
    id: 'rule-sudo-priv-esc',
    name: 'Sudo Abuse or Unauthorized Privilege Escalation',
    description: 'Detects non-standard sudo invocations or su switches to root from service accounts.',
    severity: 'high',
    mitre_technique: 'T1548.003',
    mitre_tactic: 'Privilege Escalation',
    author: 'አሻራ Forensics Team',
    status: 'active',
    yaml_content: `title: Sudo Privilege Escalation by Service User
id: rule-sudo-priv-esc
status: production
description: Detects sudo execution from www-data or unprivileged web user
tags:
  - attack.privilege_escalation
  - attack.t1548.003
logsource:
  product: linux
  service: auth
detection:
  selection:
    user: 'www-data'
    action: 'sudo'
  condition: selection
level: high`,
  },
  {
    id: 'rule-ssh-brute-force',
    name: 'SSH Authentication Brute Force Attempt',
    description: 'Detects multiple failed SSH authentications followed by potential successful logon.',
    severity: 'medium',
    mitre_technique: 'T1110.001',
    mitre_tactic: 'Credential Access',
    author: 'አሻራ Forensics Team',
    status: 'active',
    yaml_content: `title: SSH Authentication Brute Force
id: rule-ssh-brute-force
status: test
description: Multiple consecutive failed SSH authentication attempts from single IP
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  product: linux
  service: auth
detection:
  selection:
    action: 'sshd:auth_failure'
  condition: selection | count() > 4
level: medium`,
  },
  {
    id: 'rule-powershell-encoded',
    name: 'Suspicious Encoded PowerShell Execution',
    description: 'Detects PowerShell launched with -EncodedCommand or obfuscated base64 payloads.',
    severity: 'critical',
    mitre_technique: 'T1059.001',
    mitre_tactic: 'Execution',
    author: 'አሻራ Forensics Team',
    status: 'active',
    yaml_content: `title: Suspicious Encoded PowerShell Execution
id: rule-powershell-encoded
status: production
description: Detects commandline containing encoded command switches in powershell.exe
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    process|endswith: 'powershell.exe'
    commandline|contains:
      - ' -e '
      - ' -enc '
      - ' -encodedcommand '
  condition: selection
level: critical`,
  },
  {
    id: 'rule-vss-shadow-deletion',
    name: 'Volume Shadow Copy Deletion (Ransomware Inhibitor)',
    description: 'Detects execution of vssadmin or wmic commands attempting to purge shadow storage copies.',
    severity: 'critical',
    mitre_technique: 'T1490',
    mitre_tactic: 'Impact',
    author: 'አሻራ Forensics Team',
    status: 'active',
    yaml_content: `title: Volume Shadow Copy Deletion
id: rule-vss-shadow-deletion
status: production
description: Adversaries may delete volume shadow copies to prevent system recovery
tags:
  - attack.impact
  - attack.t1490
logsource:
  product: windows
detection:
  selection:
    commandline|contains:
      - 'delete shadows'
      - 'shadowcopy delete'
      - 'resize shadowstorage'
  condition: selection
level: critical`,
  },
  {
    id: 'rule-c2-beaconing',
    name: 'High-Frequency C2 Beaconing to External IP',
    description: 'Detects repetitive periodic outbound network connections to suspicious foreign external endpoints.',
    severity: 'high',
    mitre_technique: 'T1071.001',
    mitre_tactic: 'Command and Control',
    author: 'አሻራ Forensics Team',
    status: 'active',
    yaml_content: `title: High-Frequency Outbound C2 Beaconing
id: rule-c2-beaconing
status: test
description: Repeated outbound connections to untrusted external IP
tags:
  - attack.command_and_control
  - attack.t1071.001
logsource:
  category: network_traffic
detection:
  selection:
    dst_port:
      - 443
      - 8443
    protocol: 'TCP'
  condition: selection
level: high`,
  },
  {
    id: 'rule-mass-archive-staging',
    name: 'Sensitive File Mass Archive Staging for Exfiltration',
    description: 'Detects rapid creation of compressed tar or zip archives containing internal documents or credentials.',
    severity: 'medium',
    mitre_technique: 'T1560.001',
    mitre_tactic: 'Collection',
    author: 'አሻራ Forensics Team',
    status: 'active',
    yaml_content: `title: Data Staged in Compressed Archive
id: rule-mass-archive-staging
status: test
description: Creation of compressed archives in temporary directories
tags:
  - attack.collection
  - attack.t1560.001
logsource:
  product: linux
detection:
  selection:
    process|contains: ['tar', 'zip', '7z']
    commandline|contains: ['/tmp/', '/dev/shm/']
  condition: selection
level: medium`,
  }
];
