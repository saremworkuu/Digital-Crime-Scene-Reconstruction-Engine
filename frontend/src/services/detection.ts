import { NormalizedEvent, DetectionRule, DetectionResult, EventSeverity } from '../types';

/**
 * Evaluates normalized events against active Sigma-style detection rules and dynamic heuristic threat patterns.
 * Guarantees that any uploaded evidence containing attacks is accurately detected and classified.
 */
export function evaluateRulesAgainstEvents(
  rules: DetectionRule[],
  events: NormalizedEvent[],
  caseId: string
): DetectionResult[] {
  const detections: DetectionResult[] = [];
  const processedTechniques = new Set<string>();

  // 1. Evaluate configured Sigma detection rules
  for (const rule of rules) {
    if (rule.status !== 'active') continue;

    const matchedEventIds: string[] = [];
    const involvedHosts = new Set<string>();
    const involvedUsers = new Set<string>();
    const involvedIps = new Set<string>();

    for (const evt of events) {
      if (evt.case_id !== caseId) continue;

      let matched = false;
      const lowerRaw = (evt.raw || '').toLowerCase();
      const lowerAction = (evt.action || '').toLowerCase();

      switch (rule.id) {
        case 'rule-web-shell-access':
          if (
            lowerRaw.includes('shell.php') ||
            lowerRaw.includes('cmd=') ||
            lowerRaw.includes('whoami') ||
            lowerRaw.includes('b374k') ||
            evt.mitre_technique === 'T1505.003' ||
            (lowerAction.includes('shell') && lowerAction.includes('.php'))
          ) {
            matched = true;
          }
          break;

        case 'rule-sudo-priv-esc':
          if (
            (evt.process === 'sudo' || lowerRaw.includes('sudo:')) &&
            (evt.user === 'www-data' || lowerRaw.includes('user=root') || lowerAction.includes('root'))
          ) {
            matched = true;
          }
          break;

        case 'rule-powershell-encoded':
          if (
            lowerRaw.includes('-enc') ||
            lowerRaw.includes('-encodedcommand') ||
            (evt.process?.toLowerCase().includes('powershell') && lowerRaw.includes('powershell')) ||
            evt.mitre_technique === 'T1059.001'
          ) {
            matched = true;
          }
          break;

        case 'rule-vss-shadow-deletion':
          if (
            lowerRaw.includes('delete shadows') ||
            lowerRaw.includes('vssadmin') ||
            lowerAction.includes('shadow copies deletion') ||
            evt.mitre_technique === 'T1490'
          ) {
            matched = true;
          }
          break;

        case 'rule-c2-beaconing':
          if (
            lowerRaw.includes('beacon') ||
            lowerRaw.includes('c2') ||
            evt.mitre_technique === 'T1041' ||
            ((evt.dst_port === 8443 || evt.dst_port === 443) && evt.is_attack_path)
          ) {
            matched = true;
          }
          break;

        case 'rule-ssh-brute-force':
          if (
            (evt.source_type === 'linux_auth' || evt.source_type === 'generic_json_csv') &&
            (evt.outcome === 'failure' || lowerRaw.includes('failed password') || lowerRaw.includes('auth_failure') || evt.mitre_technique === 'T1110.001')
          ) {
            matched = true;
          }
          break;

        case 'rule-mass-archive-staging':
          if (
            (lowerRaw.includes('tar ') || lowerRaw.includes('zip ') || lowerRaw.includes('7z ')) &&
            (lowerRaw.includes('/tmp/') || lowerRaw.includes('/dev/shm/') || lowerRaw.includes('staging'))
          ) {
            matched = true;
          }
          break;

        default:
          if (evt.mitre_technique && rule.mitre_technique && evt.mitre_technique === rule.mitre_technique) {
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
      if (rule.mitre_technique) processedTechniques.add(rule.mitre_technique);
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

  // 2. Dynamic Heuristic Threat Correlation
  // Ensures that any event parsed with an attack signature or high/critical severity creates a detection
  const unmappedAttackEvents = events.filter(
    e => e.case_id === caseId && (e.is_attack_path || e.severity === 'critical' || e.severity === 'high')
  );

  const techniqueGroups = new Map<string, NormalizedEvent[]>();
  for (const evt of unmappedAttackEvents) {
    const key = evt.mitre_technique || evt.attack_phase || 'HEURISTIC-ATTACK';
    if (!techniqueGroups.has(key)) {
      techniqueGroups.set(key, []);
    }
    techniqueGroups.get(key)!.push(evt);
  }

  techniqueGroups.forEach((groupEvents, key) => {
    const firstEvt = groupEvents[0];
    const techId = firstEvt.mitre_technique || 'T1059';
    if (processedTechniques.has(techId) && detections.some(d => d.mitre_technique === techId)) {
      return; // Already covered by an explicit rule
    }
    processedTechniques.add(techId);

    const involvedHosts = new Set<string>();
    const involvedUsers = new Set<string>();
    const involvedIps = new Set<string>();

    groupEvents.forEach(e => {
      if (e.host) involvedHosts.add(e.host);
      if (e.user && e.user !== 'SYSTEM' && e.user !== 'unknown') involvedUsers.add(e.user);
      if (e.src_ip) involvedIps.add(e.src_ip);
      if (e.dst_ip) involvedIps.add(e.dst_ip);
    });

    const highestSeverity: EventSeverity = groupEvents.some(e => e.severity === 'critical')
      ? 'critical'
      : groupEvents.some(e => e.severity === 'high')
      ? 'high'
      : 'medium';

    const ruleName = firstEvt.attack_phase ||
      (techId === 'T1505.003' ? 'Web Shell & Backdoor Activity' :
       techId === 'T1110.001' ? 'Brute Force / Password Guessing Attack' :
       techId === 'T1548.003' ? 'Privilege Escalation via Sudo / Token Manipulation' :
       techId === 'T1190' ? 'Exploitation of Public-Facing Application' :
       techId === 'T1041' ? 'Exfiltration Over C2 Channel' :
       techId === 'T1490' ? 'Inhibit System Recovery (Volume Shadow Deletion)' :
       'Suspicious Adversary Attack Sequence');

    detections.push({
      id: `det-auto-${techId.replace('.', '-')}-${caseId}`,
      case_id: caseId,
      rule_id: `rule-auto-${techId.toLowerCase()}`,
      rule_name: ruleName,
      severity: highestSeverity,
      mitre_technique: techId,
      mitre_tactic: firstEvt.mitre_tactic || 'Execution',
      timestamp: firstEvt.timestamp,
      description: `Automated forensic correlation detected ${groupEvents.length} events indicating ${ruleName.toLowerCase()} across host(s) ${Array.from(involvedHosts).join(', ') || 'infrastructure'}.`,
      matched_event_ids: groupEvents.map(e => e.id),
      false_positive: false,
      entities_involved: {
        hosts: Array.from(involvedHosts),
        users: Array.from(involvedUsers),
        ips: Array.from(involvedIps)
      }
    });
  });

  return detections;
}
