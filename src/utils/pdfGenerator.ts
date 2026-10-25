/**
 * DCSRE Client-side Vector PDF Generator (Fallback for offline/direct download).
 * Generates standards-compliant PDF 1.4 binary documents without external npm dependencies.
 */

export interface ReportPdfData {
  caseName: string;
  reportId: string;
  version: string;
  generatedAt: string;
  examinerName: string;
  summary: string;
  evidence: { filename: string; hash: string; size: number; count: number }[];
  compromisedHosts: string[];
  compromisedUsers: string[];
  externalIps: string[];
  detections: { rule: string; technique: string; tactic: string; severity: string; host?: string }[];
  timeline: { time: string; host?: string; user?: string; action: string; severity?: string; src_ip?: string }[];
  recommendations: string[];
}

const TACTIC_MAP: Record<string, string> = {
  'T1041': 'Exfiltration',
  'T1110': 'Credential Access',
  'T1110.001': 'Credential Access',
  'T1569.002': 'Execution',
  'T1021.002': 'Lateral Movement',
  'T1021': 'Lateral Movement',
  'T1059.001': 'Execution',
  'T1059': 'Execution',
  'T1204.002': 'Execution',
  'T1547.001': 'Persistence',
  'T1003.001': 'Credential Access',
  'T1003.003': 'Credential Access',
  'T1070.001': 'Defense Evasion',
  'T1490': 'Impact',
  'T1486': 'Impact',
  'T1567.002': 'Exfiltration',
  'T1087.002': 'Discovery',
  'T1071.004': 'Command and Control',
  'T1190': 'Initial Access',
  'T1078': 'Initial Access',
  'T1548': 'Privilege Escalation',
};

function getTactic(technique: string, fallback = 'Execution'): string {
  if (!technique) return fallback;
  const t = technique.trim().toUpperCase();
  return TACTIC_MAP[t] || TACTIC_MAP[t.split('.')[0]] || fallback;
}

const SEV_WEIGHT: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };

function dedupeFindings(detections: ReportPdfData['detections']): ReportPdfData['detections'] {
  const map = new Map<string, ReportPdfData['detections'][0]>();
  for (const d of detections) {
    const tactic = getTactic(d.technique, d.tactic);
    const key = d.rule ? d.rule.toLowerCase().trim() : `${d.technique}_${d.host || ''}`;
    const existing = map.get(key);
    if (!existing) {
      map.set(key, { ...d, tactic });
    } else {
      const curWeight = SEV_WEIGHT[d.severity?.toLowerCase() || ''] || 0;
      const exWeight = SEV_WEIGHT[existing.severity?.toLowerCase() || ''] || 0;
      if (curWeight > exWeight) {
        existing.severity = d.severity;
      }
      existing.tactic = tactic;
    }
  }
  return Array.from(map.values());
}

function normalizeUser(u: string): string | null {
  if (!u) return null;
  let s = u.replace(/^user:\s*/i, '').trim();
  s = s.split('\\').pop()!.split('@')[0].trim().toLowerCase();
  return (s === '' || s === 'unknown' || s === 'system' || s === '-' || s === 'n/a') ? null : s;
}

function uniqueUsers(users: string[]): string[] {
  const best: Record<string, string> = {};
  for (const raw of users) {
    const key = normalizeUser(raw);
    if (!key) continue;
    const cleanRaw = raw.replace(/^user:\s*/i, '').trim();
    if (!best[key] || (cleanRaw.includes('\\') && !best[key].includes('\\'))) {
      best[key] = cleanRaw;
    }
  }
  return Object.values(best).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
}

function wrapLine(text: string, maxLen = 86): string[] {
  if (!text) return [''];
  if (text.length <= maxLen) return [text];
  const words = text.split(/\s+/);
  const out: string[] = [];
  let cur = '';
  for (const w of words) {
    if (!cur) {
      cur = w;
    } else if (cur.length + 1 + w.length <= maxLen) {
      cur += ' ' + w;
    } else {
      out.push(cur);
      cur = w;
    }
  }
  if (cur) out.push(cur);
  return out;
}

export function generateClientPdfBlob(data: ReportPdfData): Blob {
  const sanitize = (text: string) =>
    (text || '').replace(/[\\()]/g, '\\$&').replace(/[\r\n]+/g, ' ');

  // 1. Build IP -> Host map from timeline events to avoid listing IPs as hosts
  const ipHostMap: Record<string, string> = {};
  for (const t of data.timeline) {
    if (t.host && !t.host.startsWith('unknown') && t.src_ip) {
      ipHostMap[t.src_ip] = t.host;
    }
  }

  // 2. Normalize and resolve hosts & accounts
  const cleanHosts = Array.from(new Set(
    data.compromisedHosts
      .map(h => ipHostMap[h] || h)
      .filter(h => h && !h.startsWith('unknown'))
  )).sort();

  const cleanUsers = uniqueUsers(data.compromisedUsers);

  // 3. Dedupe detections and derive tactics
  const dedupedDetections = dedupeFindings(data.detections);

  // 4. Construct comprehensive executive summary if placeholder was provided
  let summaryText = data.summary;
  if (!summaryText || (summaryText.includes('Analyzed') && summaryText.length < 160)) {
    const critCount = dedupedDetections.filter(d => (d.severity || '').toLowerCase() === 'critical').length;
    summaryText = `[DRAFT] Forensic investigation report for incident '${data.caseName}'. ${data.evidence.length} evidence artifact(s) were ingested and SHA-256 hashed; ${data.timeline.length} normalized events were analyzed. ${dedupedDetections.length} distinct detections (${critCount} critical) triggered across MITRE ATT&CK. ${cleanHosts.length} host(s) (${cleanHosts.join(', ') || 'none'}) and ${cleanUsers.length} account(s) (${cleanUsers.join(', ') || 'none'}) were involved.`;
  }

  // Collect raw lines and apply wrapping
  const lines: string[] = [];
  const pushWrapped = (txt: string, indent = '') => {
    const wrapped = wrapLine(txt, 86 - indent.length);
    for (const w of wrapped) {
      lines.push(indent + w);
    }
  };

  lines.push("CONFIDENTIAL // TLP:AMBER - DFIR EVIDENTIARY");
  lines.push("=========================================================================");
  lines.push("DCSRE DIGITAL FORENSIC RECONSTRUCTION REPORT");
  lines.push("=========================================================================");
  lines.push("");
  lines.push(`Incident:      ${data.caseName}`);
  lines.push(`Report ID:     ${data.reportId}`);
  lines.push(`Edition:       v${data.version}.0`);
  lines.push(`Generated UTC: ${data.generatedAt}`);
  lines.push(`Investigator:  ${data.examinerName || 'Lead Forensics Investigator'}`);
  lines.push("-------------------------------------------------------------------------");
  lines.push("");
  lines.push("1. EXECUTIVE SUMMARY");
  pushWrapped(summaryText);
  lines.push("");
  lines.push("-------------------------------------------------------------------------");
  lines.push("2. CHAIN-OF-CUSTODY DIGITAL EVIDENCE LEDGER");
  if (data.evidence.length === 0) {
    lines.push("No evidence artifacts recorded.");
  } else {
    data.evidence.forEach((ev, i) => {
      lines.push(`  [${i + 1}] ${ev.filename} (${ev.count} events, ${ev.size.toLocaleString()} bytes)`);
      lines.push(`      SHA-256: ${ev.hash}`);
    });
  }
  lines.push("");
  lines.push("-------------------------------------------------------------------------");
  lines.push("3. COMPROMISED ASSETS & AFFECTED ACCOUNTS");
  pushWrapped(`Compromised Hosts:      ${cleanHosts.join(', ') || 'None identified'}`, '  ');
  pushWrapped(`Compromised Accounts:   ${cleanUsers.join(', ') || 'None identified'}`, '  ');
  pushWrapped(`Adversary Infrastructure: ${data.externalIps.join(', ') || 'None identified'}`, '  ');
  lines.push("");
  lines.push("-------------------------------------------------------------------------");
  lines.push("4. MITRE ATT&CK THREAT DETECTIONS & RECORDED FINDINGS");
  if (dedupedDetections.length === 0) {
    lines.push("No threat detections recorded.");
  } else {
    dedupedDetections.forEach((d, i) => {
      lines.push(`  [${i + 1}] ${d.rule} [${(d.severity || 'MEDIUM').toUpperCase()}]`);
      lines.push(`      Technique: ${d.technique} | Tactic: ${d.tactic}`);
    });
  }
  lines.push("");
  lines.push("-------------------------------------------------------------------------");
  lines.push("5. RECONSTRUCTED ATTACK TIMELINE PROGRESSION");
  if (data.timeline.length === 0) {
    lines.push("No chronological events recorded.");
  } else {
    // No truncation or slice: render all events
    data.timeline.forEach((t) => {
      const h = t.host && !t.host.startsWith('unknown') ? (ipHostMap[t.host] || t.host) : (t.src_ip ? (ipHostMap[t.src_ip] || t.src_ip) : 'host');
      const actor = t.user && t.user !== 'unknown' ? ` (${t.user}@${h})` : ` [${h}]`;
      pushWrapped(`${t.time} [${(t.severity || 'INFO').toUpperCase()}] ${t.action}${actor}`, '  ');
    });
  }
  lines.push("");
  lines.push("-------------------------------------------------------------------------");
  lines.push("6. REMEDIATION & INCIDENT RESPONSE RECOMMENDATIONS");
  if (data.recommendations.length === 0) {
    lines.push("None identified");
  } else {
    data.recommendations.forEach((r, idx) => {
      pushWrapped(`${idx + 1}. ${r}`, '  ');
    });
  }
  lines.push("");
  lines.push("=========================================================================");
  lines.push("OFFICIAL EVIDENTIARY RECORD - DIGITAL CRIME SCENE RECONSTRUCTION ENGINE");

  // Chunk into pages of ~48 lines each
  const LINES_PER_PAGE = 48;
  const pages: string[][] = [];
  for (let i = 0; i < lines.length; i += LINES_PER_PAGE) {
    pages.push(lines.slice(i, i + LINES_PER_PAGE));
  }
  if (pages.length === 0) pages.push(["DCSRE Forensic Report"]);

  const numPages = pages.length;

  // Build PDF 1.4 objects
  let output = "%PDF-1.4\n";
  const offsets: number[] = [];

  const addObj = (str: string) => {
    offsets.push(output.length);
    output += str + "\n";
  };

  // 1: Catalog
  addObj("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj");

  // 2: Pages container
  const kidsStr = Array.from({ length: numPages }, (_, idx) => `${3 + idx * 2} 0 R`).join(" ");
  addObj(`2 0 obj\n<< /Type /Pages /Kids [${kidsStr}] /Count ${numPages} >>\nendobj`);

  // Font object (shared)
  const fontObjIndex = 3 + numPages * 2;

  // Build each page object and content stream
  pages.forEach((pageLines, pIdx) => {
    const pageObjNum = 3 + pIdx * 2;
    const contentObjNum = pageObjNum + 1;

    addObj(
      `${pageObjNum} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${fontObjIndex} 0 R >> >> /Contents ${contentObjNum} 0 R >>\nendobj`
    );

    // Stream commands
    let streamText = "BT\n/F1 9 Tf\n36 756 Td\n13 TL\n";
    pageLines.forEach((l) => {
      streamText += `(${sanitize(l)}) Tj T*\n`;
    });

    // Page footer
    streamText += `T* (Page ${pIdx + 1} of ${numPages}) Tj\nET\n`;

    addObj(
      `${contentObjNum} 0 obj\n<< /Length ${streamText.length} >>\nstream\n${streamText}\nendstream\nendobj`
    );
  });

  // Font object
  addObj(`${fontObjIndex} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj`);

  // Xref table
  const startXref = output.length;
  output += "xref\n";
  output += `0 ${offsets.length + 1}\n`;
  output += "0000000000 65535 f \n";
  offsets.forEach((off) => {
    output += `${off.toString().padStart(10, '0')} 00000 n \n`;
  });

  output += `trailer\n<< /Size ${offsets.length + 1} /Root 1 0 R >>\n`;
  output += "startxref\n";
  output += `${startXref}\n`;
  output += "%%EOF\n";

  return new Blob([output], { type: 'application/pdf' });
}
