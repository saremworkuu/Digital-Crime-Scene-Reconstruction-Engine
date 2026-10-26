import { NormalizedEvent, ParserType, EventSeverity, EventOutcome } from '../types';

export interface ParseResult {
  events: NormalizedEvent[];
  errors: string[];
}

/**
 * Normalizes input raw timestamp to UTC ISO 8601 string (FR-PARSE-7)
 * A4 FIX: Returns null if timestamp cannot be parsed (never synthesizes current time)
 */
export function normalizeToUTC(rawTimestamp: string | number | undefined): string | null {
  if (!rawTimestamp) return null;
  try {
    // Unix epoch in seconds or milliseconds
    if (typeof rawTimestamp === 'number' || /^\d+(\.\d+)?$/.test(String(rawTimestamp).trim())) {
      const num = Number(rawTimestamp);
      const ms = num < 10000000000 ? num * 1000 : num;
      const d = new Date(ms);
      if (!isNaN(d.getTime())) return d.toISOString();
    }

    const str = String(rawTimestamp).trim();
    // Handle Nginx date format: "22/Sep/2026:03:14:22 +0000"
    const nginxMatch = str.match(/^(\d{1,2})\/([A-Za-z]{3})\/(\d{4})[:\s](\d{2}:\d{2}:\d{2})(?:\s+([+\-]\d{4}))?/);
    if (nginxMatch) {
      const [, day, month, year, time, tz] = nginxMatch;
      const formatted = `${day} ${month} ${year} ${time} ${tz || '+0000'}`;
      const d = new Date(formatted);
      if (!isNaN(d.getTime())) return d.toISOString();
    }

    // Handle Syslog date: "Sep 22 03:14:22"
    const syslogMatch = str.match(/^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})/);
    if (syslogMatch) {
      const [, month, day, time] = syslogMatch;
      const curYear = new Date().getFullYear();
      const d = new Date(`${month} ${day} ${curYear} ${time} UTC`);
      if (!isNaN(d.getTime())) return d.toISOString();
    }

    const d = new Date(str);
    if (!isNaN(d.getTime())) {
      return d.toISOString();
    }
  } catch {
    // fallback
  }
  return null;
}

/**
 * Compute deduplication key for an event (FR-PARSE-10)
 */
export function computeDedupKey(event: Partial<NormalizedEvent>): string {
  return `${event.timestamp}_${event.source_type}_${event.host}_${event.user}_${event.action}_${event.src_ip || ''}_${event.dst_ip || ''}`;
}

/**
 * Detect threat indicators and classify MITRE technique & severity
 */
function analyzeThreatIndicators(
  text: string,
  statusCode?: number,
  defaultSeverity: EventSeverity = 'low'
): {
  isAttack: boolean;
  severity: EventSeverity;
  technique?: string;
  tactic?: string;
  phase?: string;
} {
  const lower = (text || '').toLowerCase();

  // 1. Web Shell & Backdoor Execution
  if (
    lower.includes('shell.php') ||
    lower.includes('b374k') ||
    lower.includes('c99.php') ||
    lower.includes('r57.php') ||
    lower.includes('cmd=') ||
    lower.includes('whoami') ||
    lower.includes('eval(') ||
    lower.includes('base64_decode') ||
    lower.includes('system(') ||
    lower.includes('passthru(')
  ) {
    return {
      isAttack: true,
      severity: 'critical',
      technique: 'T1505.003',
      tactic: 'Persistence',
      phase: 'Web Shell & Persistence'
    };
  }

  // 2. Command Injection / Process Creation
  if (
    lower.includes('powershell') && (lower.includes('-enc') || lower.includes('-encodedcommand') || lower.includes('downloadstring')) ||
    lower.includes('/bin/sh') ||
    lower.includes('/bin/bash') ||
    lower.includes('curl ') && lower.includes('| sh') ||
    lower.includes('wget ') && lower.includes('| sh')
  ) {
    return {
      isAttack: true,
      severity: 'critical',
      technique: 'T1059.001',
      tactic: 'Execution',
      phase: 'Malicious Command Execution'
    };
  }

  // 3. SQL Injection
  if (
    lower.includes('union select') ||
    lower.includes('1=1') ||
    lower.includes('sleep(') ||
    lower.includes('benchmark(') ||
    lower.includes('information_schema') ||
    lower.includes('drop table')
  ) {
    return {
      isAttack: true,
      severity: 'high',
      technique: 'T1190',
      tactic: 'Initial Access',
      phase: 'Exploit Public-Facing Application'
    };
  }

  // 4. Privilege Escalation & Sudo Abuse
  if (
    lower.includes('sudo:') && (lower.includes('user=root') || lower.includes('tty=') || lower.includes('command=')) ||
    lower.includes('privilege escalation') ||
    lower.includes('uac bypass') ||
    lower.includes('mimikatz') ||
    lower.includes('secretsdump')
  ) {
    return {
      isAttack: true,
      severity: 'critical',
      technique: 'T1548.003',
      tactic: 'Privilege Escalation',
      phase: 'Privilege Escalation'
    };
  }

  // 5. Authentication Failure / Brute Force
  if (
    lower.includes('failed password') ||
    lower.includes('authentication failure') ||
    lower.includes('eventid 4625') ||
    lower.includes('invalid user') ||
    lower.includes('logon failure') ||
    (statusCode && statusCode === 401)
  ) {
    return {
      isAttack: true,
      severity: 'high',
      technique: 'T1110.001',
      tactic: 'Credential Access',
      phase: 'Brute Force Credential Access'
    };
  }

  // 6. Shadow Copies / Ransomware Impact
  if (
    lower.includes('delete shadows') ||
    lower.includes('vssadmin') ||
    lower.includes('wbadmin') ||
    lower.includes('bcdedit /set') ||
    lower.includes('.locked') ||
    lower.includes('.encrypted')
  ) {
    return {
      isAttack: true,
      severity: 'critical',
      technique: 'T1490',
      tactic: 'Impact',
      phase: 'Inhibit System Recovery'
    };
  }

  // 7. Data Exfiltration / C2 Beaconing
  if (
    lower.includes('beacon') ||
    lower.includes('exfiltration') ||
    lower.includes('tunnel') ||
    lower.includes('c2')
  ) {
    return {
      isAttack: true,
      severity: 'high',
      technique: 'T1041',
      tactic: 'Exfiltration',
      phase: 'Adversary Exfiltration'
    };
  }

  if (statusCode && statusCode >= 500) {
    return {
      isAttack: false,
      severity: 'high'
    };
  }

  return {
    isAttack: false,
    severity: defaultSeverity
  };
}

/**
 * Safe multi-format parser supporting CSV, JSON, NDJSON, Web logs, Linux auth, and generic formats
 */
export function parseEvidenceContent(
  content: string,
  parserType: ParserType,
  caseId: string,
  evidenceId: string,
  fallbackHost: string = 'unknown_host'
): ParseResult {
  const events: NormalizedEvent[] = [];
  const errors: string[] = [];

  if (!content || !content.trim()) {
    return { events, errors };
  }

  const trimmed = content.trim();

  // -------------------------------------------------------------
  // STRATEGY 0: XML / Sysmon Event Parsing (FR-PARSE-XML)
  // -------------------------------------------------------------
  if (trimmed.startsWith('<?xml') || trimmed.startsWith('<Events') || trimmed.startsWith('<Event')) {
    try {
      const dom = new DOMParser().parseFromString(trimmed, 'text/xml');
      const eventNodes = dom.querySelectorAll('Event');
      if (eventNodes && eventNodes.length > 0) {
        eventNodes.forEach((node, idx) => {
          const eid = node.querySelector('EventID')?.textContent?.trim() || '';
          const comp = node.querySelector('Computer')?.textContent?.trim() || fallbackHost;
          const time = node.querySelector('TimeCreated')?.getAttribute('SystemTime') || new Date().toISOString();
          const recId = node.querySelector('EventRecordID')?.textContent?.trim() || String(idx + 1);

          const dataMap: Record<string, string> = {};
          node.querySelectorAll('Data').forEach(d => {
            const k = d.getAttribute('Name');
            if (k) dataMap[k] = d.textContent?.trim() || '';
          });

          const proc = dataMap.Image || dataMap.NewProcessName;
          const parentProc = dataMap.ParentImage || dataMap.ParentProcessName;
          const cmd = dataMap.CommandLine || dataMap.ImagePath;
          const user = dataMap.User || dataMap.TargetUserName || dataMap.SubjectUserName || 'unknown';
          const srcIp = dataMap.SourceIp || dataMap.IpAddress;
          const dstIp = dataMap.DestinationIp;
          const srcPort = dataMap.SourcePort ? Number(dataMap.SourcePort) : undefined;
          const dstPort = dataMap.DestinationPort ? Number(dataMap.DestinationPort) : undefined;
          const targetFile = dataMap.TargetFilename || dataMap.TargetObject;
          const qname = dataMap.QueryName;

          let actionText = `Event ${eid} on ${comp}`;
          if (eid === '1') {
            actionText = `1 process created: ${proc ? proc.split('\\').pop() : ''} (parent ${parentProc ? parentProc.split('\\').pop() : ''}) by ${user}`;
          } else if (eid === '22') {
            actionText = `Sysmon 22 DNS query: ${qname || ''} -> ${dataMap.QueryResults || ''}`;
          } else if (eid === '3') {
            actionText = `Sysmon 3 network connection: ${proc ? proc.split('\\').pop() : ''} -> ${dstIp}:${dstPort}`;
          } else if (eid === '11') {
            actionText = `Sysmon 11 file created: ${targetFile ? targetFile.split('\\').pop() : ''}`;
          } else if (eid === '10') {
            actionText = `Sysmon 10 process access: ${dataMap.SourceImage || ''} accessed ${dataMap.TargetImage || ''}`;
          } else if (cmd) {
            actionText = `Windows Event ${eid}: ${cmd.slice(0, 80)}`;
          }

          const threat = analyzeThreatIndicators(
            actionText + ' ' + (cmd || '') + ' ' + (targetFile || '') + ' ' + JSON.stringify(dataMap),
            undefined,
            eid === '10' || eid === '11' && (targetFile || '').includes('.exe') ? 'critical' : 'medium'
          );

          events.push({
            id: `evt-${evidenceId}-${idx}-${Date.now()}`,
            case_id: caseId,
            evidence_id: evidenceId,
            timestamp: normalizeToUTC(time),
            source_type: 'windows_evtx',
            host: comp,
            host_inferred: !comp || comp === fallbackHost,
            source_record_id: Number(recId) || (idx + 1),
            event_id: Number(eid) || eid,
            user: user,
            src_ip: srcIp,
            dst_ip: dstIp,
            src_port: srcPort,
            dst_port: dstPort,
            protocol: dstPort ? 'TCP' : undefined,
            process: proc,
            parent_process: parentProc,
            command_line: cmd,
            target_file: targetFile,
            action: actionText,
            outcome: threat.isAttack ? 'success' : 'success',
            severity: threat.severity,
            raw: node.outerHTML || actionText,
            mitre_technique: threat.technique,
            mitre_tactic: threat.tactic,
            attack_phase: threat.phase,
            is_attack_path: threat.isAttack,
            metadata: dataMap,
            extra: { ...dataMap, query_name: qname }
          });
        });

        if (events.length > 0) {
          return { events, errors };
        }
      }
    } catch (xmlErr: any) {
      errors.push(`XML parse notice: ${xmlErr.message}`);
    }
  }

  const rawLines = content.split(/\r?\n/).filter(line => line.trim().length > 0);

  // -------------------------------------------------------------
  // STRATEGY 1: Full JSON Array / Object Parsing (incl. EDR alerts)
  // -------------------------------------------------------------
  try {
    if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
      const parsed = JSON.parse(trimmed);
      let items: any[] = [];
      let parentMeta: Record<string, any> = {};

      if (Array.isArray(parsed)) {
        items = parsed;
      } else if (parsed && typeof parsed === 'object') {
        const arrKey = Object.keys(parsed).find(k => Array.isArray(parsed[k]) && ['alerts', 'events', 'records', 'items'].includes(k));
        if (arrKey) {
          parentMeta = { ...parsed };
          delete parentMeta[arrKey];
          items = parsed[arrKey].map((it: any) => ({ ...parentMeta, ...it }));
        } else {
          items = [parsed];
        }
      }

      items.forEach((item, idx) => {
        try {
          if (!item || typeof item !== 'object') return;

          const ts = normalizeToUTC(
            item.time || item.timestamp || item.TimeCreated || item['@timestamp'] || item.date || Date.now()
          );
          const rawText = typeof item === 'object' ? JSON.stringify(item) : String(item);
          const alertRule = item.rule || item.rule_name || item.alert_name;
          const actionText =
            (alertRule ? `EDR Alert: ${alertRule} (${item.id || idx + 1})` : null) ||
            item.action ||
            item.message ||
            item.Message ||
            item.event_type ||
            item.description ||
            `Event ${idx + 1}`;

          const threat = analyzeThreatIndicators(
            rawText + ' ' + actionText,
            item.status_code || item.status,
            item.severity || 'low'
          );

          const mitreVal = item.mitre || item.mitre_technique;
          const mitreTech = Array.isArray(mitreVal) ? mitreVal[0] : (mitreVal || threat.technique);

          events.push({
            id: `evt-${evidenceId}-${idx}-${Date.now()}`,
            case_id: caseId,
            evidence_id: evidenceId,
            timestamp: ts,
            source_type: item.source || parserType || 'generic_json_csv',
            host: item.host || item.Computer || item.WorkstationName || item.hostname || fallbackHost,
            host_inferred: !item.host && !item.Computer && !item.hostname,
            source_record_id: item.id || (idx + 1),
            event_id: item.id,
            user: item.user || item.TargetUserName || item.username || item.SubjectUserName || 'unknown',
            src_ip: item.src_ip || item.source_ip || item.IpAddress || item.client_ip,
            dst_ip: item.dst_ip || item.destination_ip || item.server_ip,
            src_port: item.src_port || item.source_port ? Number(item.src_port || item.source_port) : undefined,
            dst_port: item.dst_port || item.destination_port ? Number(item.dst_port || item.destination_port) : undefined,
            protocol: item.protocol || (item.src_port ? 'TCP' : undefined),
            process: item.process || item.NewProcessName || item.Image,
            command_line: item.command_line || item.CommandLine,
            target_file: item.target_file || item.TargetFilename || item.path,
            action: actionText,
            outcome: item.outcome || 'success',
            severity: (item.severity as EventSeverity) || threat.severity,
            raw: rawText,
            mitre_technique: mitreTech,
            mitre_tactic: item.mitre_tactic || threat.tactic,
            attack_phase: item.attack_phase || threat.phase,
            is_attack_path: item.is_attack_path !== undefined ? Boolean(item.is_attack_path) : (threat.isAttack || Boolean(alertRule)),
            metadata: item,
            extra: item
          });
        } catch (itemErr: any) {
          errors.push(`JSON record parse error at index ${idx}: ${itemErr.message}`);
        }
      });

      if (events.length > 0) {
        return { events, errors };
      }
    }
  } catch {
    // Not valid JSON array/object - fall through to line-by-line & CSV analysis
  }

  // -------------------------------------------------------------
  // STRATEGY 2: CSV Parsing (with Header Row detection)
  // -------------------------------------------------------------
  const firstLine = rawLines[0] || '';
  if (firstLine.includes(',') || firstLine.includes('\t') || firstLine.includes(';')) {
    const delimiter = firstLine.includes('\t') ? '\t' : firstLine.includes(';') ? ';' : ',';
    const splitCsvLine = (line: string): string[] => {
      const result: string[] = [];
      let current = '';
      let inQuotes = false;
      for (let i = 0; i < line.length; i++) {
        const char = line[i];
        if (char === '"' || char === "'") {
          inQuotes = !inQuotes;
        } else if (char === delimiter && !inQuotes) {
          result.push(current.trim().replace(/^["']|["']$/g, ''));
          current = '';
        } else {
          current += char;
        }
      }
      result.push(current.trim().replace(/^["']|["']$/g, ''));
      return result;
    };

    const headers = splitCsvLine(firstLine).map(h => h.toLowerCase().trim());
    const hasHeader = headers.some(h =>
      ['timestamp', 'time', 'date', 'host', 'user', 'action', 'src_ip', 'dst_ip', 'message', 'event'].includes(h)
    );

    if (hasHeader && rawLines.length > 1) {
      const getCol = (cols: string[], possibleNames: string[]): string | undefined => {
        for (const name of possibleNames) {
          const idx = headers.indexOf(name);
          if (idx !== -1 && cols[idx] !== undefined && cols[idx] !== '') {
            return cols[idx];
          }
        }
        return undefined;
      };

      for (let i = 1; i < rawLines.length; i++) {
        const line = rawLines[i].trim();
        if (!line) continue;
        try {
          const cols = splitCsvLine(line);
          const rawTimestamp = getCol(cols, ['timestamp', 'time', 'date', '@timestamp', 'datetime']);
          const hostVal = getCol(cols, ['host', 'hostname', 'computer', 'server', 'node']) || fallbackHost;
          const userVal = getCol(cols, ['user', 'username', 'account', 'actor']) || 'unknown';
          const srcIpVal = getCol(cols, ['src_ip', 'source_ip', 'client_ip', 'src', 'ip']);
          const dstIpVal = getCol(cols, ['dst_ip', 'destination_ip', 'server_ip', 'dst', 'target_ip']);
          const actionVal = getCol(cols, ['action', 'message', 'event', 'event_type', 'command', 'activity']) || line;
          const severityRaw = getCol(cols, ['severity', 'level', 'priority']);
          const mitreVal = getCol(cols, ['mitre_technique', 'technique', 'mitre', 'tid']);

          const threat = analyzeThreatIndicators(
            line,
            undefined,
            (severityRaw as EventSeverity) || 'low'
          );

          events.push({
            id: `evt-${evidenceId}-${i}`,
            case_id: caseId,
            evidence_id: evidenceId,
            timestamp: normalizeToUTC(rawTimestamp),
            source_type: parserType || 'generic_json_csv',
            host: hostVal,
            user: userVal,
            src_ip: srcIpVal,
            dst_ip: dstIpVal,
            action: actionVal,
            outcome: (threat.isAttack && threat.severity === 'critical') ? 'success' : 'success',
            severity: threat.severity,
            raw: line,
            mitre_technique: mitreVal || threat.technique,
            mitre_tactic: threat.tactic,
            attack_phase: threat.phase,
            is_attack_path: threat.isAttack
          });
        } catch (csvErr: any) {
          errors.push(`CSV line ${i + 1} parse error: ${csvErr.message}`);
        }
      }

      if (events.length > 0) {
        return { events, errors };
      }
    }
  }

  // -------------------------------------------------------------
  // STRATEGY 3: Line-by-Line Regex Patterns (Web, Syslog, Auth, PCAP)
  // -------------------------------------------------------------
  rawLines.forEach((line, index) => {
    try {
      const trimmedLine = line.trim();
      if (!trimmedLine) return;

      // Check if line is individual JSON object (NDJSON)
      if (trimmedLine.startsWith('{') && trimmedLine.endsWith('}')) {
        try {
          const item = JSON.parse(trimmedLine);
          const threat = analyzeThreatIndicators(trimmedLine, item.status_code || item.status);
          events.push({
            id: `evt-${evidenceId}-${index}`,
            case_id: caseId,
            evidence_id: evidenceId,
            timestamp: normalizeToUTC(item.timestamp || item['@timestamp'] || item.time),
            source_type: parserType || 'generic_json_csv',
            host: item.host || item.hostname || fallbackHost,
            user: item.user || item.username || 'unknown',
            src_ip: item.src_ip || item.source_ip,
            dst_ip: item.dst_ip || item.destination_ip,
            action: item.action || item.message || item.event || 'System Event',
            outcome: item.outcome || 'success',
            severity: threat.severity,
            raw: trimmedLine,
            mitre_technique: item.mitre_technique || threat.technique,
            mitre_tactic: item.mitre_tactic || threat.tactic,
            attack_phase: item.attack_phase || threat.phase,
            is_attack_path: threat.isAttack
          });
          return;
        } catch {
          // not ndjson, continue
        }
      }

      // Web server access log (Apache / Nginx / W3C)
      const webRegex = /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+([^"]+?)\s+([^"]*)"\s+(\d{3})\s+(\S+)/;
      const webMatch = trimmedLine.match(webRegex);
      if (webMatch) {
        const [, ip, user, rawDate, method, path, , statusCodeStr] = webMatch;
        const statusCode = parseInt(statusCodeStr, 10);
        const threat = analyzeThreatIndicators(trimmedLine, statusCode);

        events.push({
          id: `evt-${evidenceId}-${index}`,
          case_id: caseId,
          evidence_id: evidenceId,
          timestamp: normalizeToUTC(rawDate),
          source_type: 'web_server',
          host: fallbackHost,
          user: user !== '-' ? user : 'anonymous',
          src_ip: ip,
          action: `HTTP ${method} ${path} (${statusCode})`,
          outcome: statusCode >= 400 ? 'failure' : 'success',
          severity: threat.severity,
          raw: trimmedLine,
          mitre_technique: threat.technique || (threat.isAttack ? 'T1505.003' : undefined),
          mitre_tactic: threat.tactic || (threat.isAttack ? 'Persistence' : undefined),
          attack_phase: threat.phase,
          is_attack_path: threat.isAttack
        });
        return;
      }

      // Linux syslog / auth log
      const authRegex = /^([A-Z][a-z]{2}\s+\d+\s+[\d:]+)\s+(\S+)\s+(\w+)(?:\[\d+\])?:?\s*(.*)$/;
      const authMatch = trimmedLine.match(authRegex);
      if (authMatch) {
        const [, rawDate, host, service, message] = authMatch;
        const threat = analyzeThreatIndicators(trimmedLine);
        const isFailed = message.toLowerCase().includes('failed') || message.toLowerCase().includes('invalid');

        events.push({
          id: `evt-${evidenceId}-${index}`,
          case_id: caseId,
          evidence_id: evidenceId,
          timestamp: normalizeToUTC(rawDate),
          source_type: 'linux_auth',
          host: host || fallbackHost,
          user: message.match(/user\s+(\w+)|USER=(\w+)/i)?.[1] || 'system',
          process: service,
          action: `${service.toUpperCase()}: ${message.slice(0, 100)}`,
          outcome: isFailed ? 'failure' : 'success',
          severity: threat.severity,
          raw: trimmedLine,
          mitre_technique: threat.technique || (threat.isAttack ? 'T1548.003' : undefined),
          mitre_tactic: threat.tactic || (threat.isAttack ? 'Privilege Escalation' : undefined),
          attack_phase: threat.phase,
          is_attack_path: threat.isAttack
        });
        return;
      }

      // FSAUDIT File Server Audit Log
      const fsAuditRegex = /^(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+(\S+)\s+(FSAUDIT)\s+(.*)$/;
      const fsAuditMatch = trimmedLine.match(fsAuditRegex);
      if (fsAuditMatch) {
        const [, rawDate, host, service, rest] = fsAuditMatch;
        const userMatch = rest.match(/user=([^\s]+)/);
        const actionMatch = rest.match(/action=([^\s]+)/);
        const pathMatch = rest.match(/(?:path|dst|src)="([^"]+)"|(?:path|dst|src)=([^\s]+)/);
        const user = userMatch ? userMatch[1] : 'unknown';
        const action = actionMatch ? actionMatch[1] : 'ACCESS';
        const targetPath = pathMatch ? (pathMatch[1] || pathMatch[2]) : '';
        const isRansomwareRename = targetPath.endsWith('.cvlk') || targetPath.includes('README_RESTORE_FILES');

        events.push({
          id: `evt-${evidenceId}-${index}`,
          case_id: caseId,
          evidence_id: evidenceId,
          timestamp: normalizeToUTC(rawDate),
          source_type: 'structured_log',
          host: host,
          host_inferred: false,
          user: user,
          action: `FSAUDIT ${action}: ${targetPath} by ${user}`,
          outcome: 'success',
          severity: isRansomwareRename ? 'critical' : 'low',
          raw: trimmedLine,
          mitre_technique: isRansomwareRename ? 'T1486' : undefined,
          mitre_tactic: isRansomwareRename ? 'Impact' : undefined,
          attack_phase: isRansomwareRename ? 'Data Encrypted for Impact' : undefined,
          is_attack_path: isRansomwareRename,
          target_file: targetPath,
          service_name: service,
          source_record_id: index + 1
        });
        return;
      }

      // Linux syslog / auth log / mailgw
      const mailgwRegex = /^([A-Z][a-z]{2}\s+\d+\s+[\d:]+)\s+(\S+)\s+(postfix\/\S+):\s+(.*)$/;
      const mailgwMatch = trimmedLine.match(mailgwRegex);
      if (mailgwMatch) {
        const [, rawDate, host, service, msg] = mailgwMatch;
        const toMatch = msg.match(/to=<([^>]+)>/);
        const attachMatch = msg.match(/attachment=([^\s]+)/);
        const subjMatch = msg.match(/subject="([^"]+)"/);
        const toUser = toMatch ? toMatch[1] : 'unknown';
        const attach = attachMatch ? attachMatch[1] : '';
        const isMaliciousDoc = attach.endsWith('.docm') || attach.endsWith('.xlsm');

        events.push({
          id: `evt-${evidenceId}-${index}`,
          case_id: caseId,
          evidence_id: evidenceId,
          timestamp: normalizeToUTC(rawDate),
          source_type: 'mail_gateway',
          host: host,
          host_inferred: false,
          user: toUser,
          target_file: attach,
          action: `Mail to ${toUser} (subj: "${subjMatch ? subjMatch[1] : ''}") attach: ${attach || '-'}`,
          outcome: 'success',
          severity: isMaliciousDoc ? 'high' : 'low',
          raw: trimmedLine,
          mitre_technique: isMaliciousDoc ? 'T1566.001' : undefined,
          mitre_tactic: isMaliciousDoc ? 'Initial Access' : undefined,
          attack_phase: isMaliciousDoc ? 'Spearphishing Attachment' : undefined,
          is_attack_path: isMaliciousDoc,
          service_name: service,
          source_record_id: index + 1
        });
        return;
      }

      // Heuristic extraction for arbitrary log lines
      // Extract IP addresses if present
      const ipMatch = trimmedLine.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/);
      // Extract date/time if present
      const dateMatch = trimmedLine.match(/\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}/) || trimmedLine.match(/[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/);

      const threat = analyzeThreatIndicators(trimmedLine);

      events.push({
        id: `evt-${evidenceId}-${index}`,
        case_id: caseId,
        evidence_id: evidenceId,
        timestamp: dateMatch ? normalizeToUTC(dateMatch[0]) : new Date(Date.now() - (rawLines.length - index) * 60000).toISOString(),
        source_type: parserType || 'generic_json_csv',
        host: fallbackHost,
        user: 'unknown',
        src_ip: ipMatch ? ipMatch[0] : undefined,
        action: trimmedLine.length > 100 ? trimmedLine.slice(0, 100) + '...' : trimmedLine,
        outcome: threat.isAttack ? 'failure' : 'unknown',
        severity: threat.severity,
        raw: trimmedLine,
        mitre_technique: threat.technique,
        mitre_tactic: threat.tactic,
        attack_phase: threat.phase,
        is_attack_path: threat.isAttack
      });
    } catch (lineErr: any) {
      errors.push(`Line ${index + 1} parse error: ${lineErr.message}`);
    }
  });

  return { events, errors };
}
