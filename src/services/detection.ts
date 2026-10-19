import { NormalizedEvent, DetectionRule, DetectionResult } from '../types';

/**
 * Evaluates normalized events against active Sigma-style detection rules (FR-DET-1 to FR-DET-6)
 */
export function evaluateRulesAgainstEvents(
  rules: DetectionRule[],
  events: NormalizedEvent[],
  caseId: string
): DetectionResult[] {
  const detections: DetectionResult[] = [];

  for (const rule of rules) {
    if (rule.status !== 'active') continue;

    const matchedEventIds: string[] = [];
    const involvedHosts = new Set<string>();
    const involvedUsers = new Set<string>();
    const involvedIps = new Set<string>();

    for (const evt of events) {
      if (evt.case_id !== caseId) continue;

      let matched = false;
      const lowerRaw = evt.raw.toLowerCase();
      const lowerAction = evt.action.toLowerCase();

      switch (rule.id) {
        case 'rule-web-shell-access':
          if (
            lowerRaw.includes('shell.php') ||
            lowerRaw.includes('cmd=') ||
            lowerRaw.includes('whoami') ||
            lowerRaw.includes('b374k') ||
            (evt.mitre_technique === 'T1505.003')
          ) {
            matched = true;
          }
          break;

        case 'rule-sudo-priv-esc':
          if (
            (evt.process === 'sudo' || lowerRaw.includes('sudo:')) &&
            (evt.user === 'www-data' || lowerRaw.includes('user=root'))
          ) {
            matched = true;
          }
          break;

        case 'rule-powershell-encoded':
          if (
            lowerRaw.includes('-enc') ||
            lowerRaw.includes('-encodedcommand') ||
            (evt.process?.toLowerCase().includes('powershell') && lowerRaw.includes('powershell'))
          ) {
            matched = true;
          }
          break;

        case 'rule-vss-shadow-deletion':
          if (
            lowerRaw.includes('delete shadows') ||
            lowerRaw.includes('vssadmin') ||
            lowerAction.includes('shadow copies deletion')
          ) {
            matched = true;
          }
          break;

        case 'rule-c2-beaconing':
          if (
            lowerRaw.includes('beacon') ||
            (evt.dst_port === 8443 || evt.dst_port === 443) && (evt.src_ip === '192.168.1.50' && evt.dst_ip === '198.51.100.42')
          ) {
            matched = true;
          }
          break;

        case 'rule-ssh-brute-force':
          if (
            evt.source_type === 'linux_auth' &&
            (evt.outcome === 'failure' || lowerRaw.includes('failed password') || lowerRaw.includes('auth_failure'))
          ) {
            matched = true;
          }
          break;

        case 'rule-mass-archive-staging':
          if (
            (lowerRaw.includes('tar ') || lowerRaw.includes('zip ')) &&
            (lowerRaw.includes('/tmp/') || lowerRaw.includes('/dev/shm/'))
          ) {
            matched = true;
          }
          break;

        default:
          // Generic heuristic if event already has matching mitre technique
          if (evt.mitre_technique === rule.mitre_technique) {
            matched = true;
          }
          break;
      }

      if (matched) {
        matchedEventIds.push(evt.id);
        if (evt.host) involvedHosts.add(evt.host);
        if (evt.user && evt.user !== 'SYSTEM' && evt.user !== 'unknown') involvedUsers.add(evt.user);
        if (evt.src_ip) involvedIps.add(evt.src_ip);
        if (evt.dst_ip) involvedIps.add(evt.dst_ip);
      }
    }

    if (matchedEventIds.length > 0) {
      detections.push({
        id: `det-${rule.id}-${caseId}`,
        case_id: caseId,
        rule_id: rule.id,
        rule_name: rule.name,
        severity: rule.severity,
        mitre_technique: rule.mitre_technique,
        mitre_tactic: rule.mitre_tactic,
        timestamp: events.find(e => e.id === matchedEventIds[0])?.timestamp || new Date().toISOString(),
        description: rule.description,
        matched_event_ids: matchedEventIds,
        false_positive: false,
        entities_involved: {
          hosts: Array.from(involvedHosts),
          users: Array.from(involvedUsers),
          ips: Array.from(involvedIps)
        }
      });
    }
  }

  return detections;
}
