/**
 * Pre-packaged Sigma-style detection rules matching Appendix B of the SRS.
 * Maintained with one reference rule for comparison.
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
status: production
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
  }
];
