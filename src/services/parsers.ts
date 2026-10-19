import { NormalizedEvent, ParserType, EventSeverity, EventOutcome } from '../types';

export interface ParseResult {
  events: NormalizedEvent[];
  errors: string[];
}

/**
 * Normalizes input raw timestamp to UTC ISO 8601 string (FR-PARSE-7)
 */
export function normalizeToUTC(rawTimestamp: string | number): string {
  try {
    const d = new Date(rawTimestamp);
    if (!isNaN(d.getTime())) {
      return d.toISOString();
    }
  } catch {
    // fallback
  }
  return new Date().toISOString();
}

/**
 * Compute deduplication key for an event (FR-PARSE-10)
 */
export function computeDedupKey(event: Partial<NormalizedEvent>): string {
  return `${event.timestamp}_${event.source_type}_${event.host}_${event.user}_${event.action}_${event.src_ip || ''}_${event.dst_ip || ''}`;
}

/**
 * Safe multi-format parser matching FR-PARSE-1 through FR-PARSE-9
 */
export function parseEvidenceContent(
  content: string,
  parserType: ParserType,
  caseId: string,
  evidenceId: string,
  fallbackHost: string = 'host01.local'
): ParseResult {
  const events: NormalizedEvent[] = [];
  const errors: string[] = [];

  const lines = content.split(/\r?\n/).filter(line => line.trim().length > 0);

  if (parserType === 'generic_json_csv' || parserType === 'windows_evtx') {
    // Try JSON array parsing first
    try {
      const parsedJson = JSON.parse(content);
      const items = Array.isArray(parsedJson) ? parsedJson : [parsedJson];
      
      items.forEach((item, idx) => {
        try {
          const timestamp = normalizeToUTC(item.timestamp || item.TimeCreated || item['@timestamp'] || Date.now());
          const eventId = item.EventID || item.event_id;
          let action = item.action || item.Message || 'System Event';
          let outcome: EventOutcome = 'success';
          let severity: EventSeverity = 'low';
          let mitre_technique = item.mitre_technique;
          let mitre_tactic = item.mitre_tactic;

          if (eventId === 4625 || item.outcome === 'failure') {
            outcome = 'failure';
            action = 'Logon Failure (EventID 4625)';
            severity = 'medium';
          } else if (eventId === 4624) {
            action = `Logon Success (EventID 4624 - Type ${item.LogonType || 3})`;
            severity = 'low';
          } else if (eventId === 4688 || item.NewProcessName) {
            action = `Process Creation: ${item.NewProcessName || item.process || 'executable'}`;
            if (String(item.CommandLine || '').includes('-enc') || String(item.CommandLine || '').includes('powershell')) {
              severity = 'critical';
              mitre_technique = 'T1059.001';
              mitre_tactic = 'Execution';
            } else {
              severity = 'medium';
            }
          }

          events.push({
            id: `evt-${evidenceId}-${idx}-${Date.now()}`,
            case_id: caseId,
            evidence_id: evidenceId,
            timestamp,
            source_type: parserType,
            host: item.host || item.Computer || item.WorkstationName || fallbackHost,
            user: item.user || item.TargetUserName || item.SubjectUserName || 'SYSTEM',
            src_ip: item.src_ip || item.IpAddress,
            dst_ip: item.dst_ip,
            src_port: item.src_port ? Number(item.src_port) : undefined,
            dst_port: item.dst_port ? Number(item.dst_port) : undefined,
            protocol: item.protocol,
            process: item.process || item.NewProcessName,
            action,
            outcome,
            severity,
            raw: typeof item === 'object' ? JSON.stringify(item) : String(item),
            mitre_technique,
            mitre_tactic,
            metadata: item
          });
        } catch (itemErr: any) {
          errors.push(`JSON object parse error at index ${idx}: ${itemErr.message}`);
        }
      });

      return { events, errors };
    } catch {
      // Not raw JSON, continue to line-by-line fallback
    }
  }

  // Line-by-line parsing
  lines.forEach((line, index) => {
    try {
      if (parserType === 'web_server') {
        // Common / Combined Apache & Nginx log pattern:
        // 192.168.1.5 - - [22/Sep/2026:03:14:22 +0000] "POST /path HTTP/1.1" 200 45 "referer" "user-agent"
        const webRegex = /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+([^"]+?)\s+([^"]*)"\s+(\d{3})\s+(\S+)/;
        const match = line.match(webRegex);
        if (match) {
          const [, ip, user, rawDate, method, path, , statusCodeStr] = match;
          const status = parseInt(statusCodeStr, 10);
          const isAttack = path.includes('.php') || path.includes('cmd=') || path.includes('..') || path.includes('shell') || path.includes('whoami');
          
          events.push({
            id: `evt-${evidenceId}-${index}`,
            case_id: caseId,
            evidence_id: evidenceId,
            timestamp: normalizeToUTC(rawDate.replace(':', ' ')),
            source_type: 'web_server',
            host: fallbackHost,
            user: user !== '-' ? user : 'anonymous',
            src_ip: ip,
            action: `HTTP ${method} ${path} (${status})`,
            outcome: status >= 400 ? 'failure' : 'success',
            severity: isAttack ? 'critical' : status >= 500 ? 'high' : 'low',
            raw: line,
            mitre_technique: isAttack ? 'T1505.003' : undefined,
            mitre_tactic: isAttack ? 'Persistence' : undefined,
            is_attack_path: isAttack
          });
          return;
        }
      }

      if (parserType === 'linux_auth') {
        // Format: Sep 22 03:22:15 web01 sudo: www-data : TTY=pts/1 ; ...
        const authRegex = /^([A-Z][a-z]{2}\s+\d+\s+[\d:]+)\s+(\S+)\s+(\w+)(?:\[\d+\])?:?\s*(.*)$/;
        const match = line.match(authRegex);
        if (match) {
          const [, rawDate, host, service, message] = match;
          const isSudo = service.includes('sudo');
          const isFailed = message.toLowerCase().includes('failed') || message.toLowerCase().includes('invalid');
          const isRoot = message.includes('USER=root') || message.includes('for root');

          events.push({
            id: `evt-${evidenceId}-${index}`,
            case_id: caseId,
            evidence_id: evidenceId,
            timestamp: normalizeToUTC(rawDate + ' 2026'),
            source_type: 'linux_auth',
            host,
            user: message.match(/user\s+(\w+)|USER=(\w+)/i)?.[1] || 'system',
            process: service,
            action: `${service.toUpperCase()}: ${message.slice(0, 100)}`,
            outcome: isFailed ? 'failure' : 'success',
            severity: isSudo && isRoot ? 'high' : isFailed ? 'medium' : 'low',
            raw: line,
            mitre_technique: isSudo ? 'T1548.003' : isFailed ? 'T1110.001' : undefined,
            mitre_tactic: isSudo ? 'Privilege Escalation' : isFailed ? 'Credential Access' : undefined
          });
          return;
        }
      }

      if (parserType === 'pcap_summary') {
        // CSV with headers: timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes
        const parts = line.split(',');
        if (parts.length >= 6 && index > 0) {
          const [ts, src_ip, dst_ip, src_port, dst_port, protocol, bytes] = parts.map(p => p.trim());
          const byteNum = Number(bytes) || 0;
          const isLargeTransfer = byteNum > 1000000;

          events.push({
            id: `evt-${evidenceId}-${index}`,
            case_id: caseId,
            evidence_id: evidenceId,
            timestamp: normalizeToUTC(ts),
            source_type: 'pcap_summary',
            host: fallbackHost,
            user: 'network',
            src_ip,
            dst_ip,
            src_port: Number(src_port),
            dst_port: Number(dst_port),
            protocol,
            action: `Network Flow: ${src_ip}:${src_port} -> ${dst_ip}:${dst_port} (${byteNum} bytes)`,
            outcome: 'success',
            severity: isLargeTransfer ? 'critical' : 'low',
            raw: line,
            mitre_technique: isLargeTransfer ? 'T1041' : undefined,
            mitre_tactic: isLargeTransfer ? 'Exfiltration' : undefined,
            is_attack_path: isLargeTransfer
          });
          return;
        }
      }

      // Generic line capture fallback (FR-PARSE-4)
      events.push({
        id: `evt-${evidenceId}-${index}`,
        case_id: caseId,
        evidence_id: evidenceId,
        timestamp: new Date().toISOString(),
        source_type: parserType,
        host: fallbackHost,
        user: 'unknown',
        action: line.length > 90 ? line.slice(0, 90) + '...' : line,
        outcome: 'unknown',
        severity: 'low',
        raw: line
      });
    } catch (err: any) {
      errors.push(`Line ${index + 1} parse error: ${err.message}`);
    }
  });

  return { events, errors };
}
