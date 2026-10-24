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
  detections: { rule: string; technique: string; tactic: string; severity: string }[];
  timeline: { time: string; host?: string; user?: string; action: string; severity?: string }[];
  recommendations: string[];
}

export function generateClientPdfBlob(data: ReportPdfData): Blob {
  const sanitize = (text: string) =>
    (text || '').replace(/[\\()]/g, '\\$&').replace(/[\r\n]+/g, ' ');

  // Collect text lines grouped into pages (approx 52 lines per letter page)
  const lines: string[] = [];
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
  lines.push(data.summary || 'Investigation completed with reconstructed events and threat findings.');
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
  lines.push(`  Compromised Hosts:      ${data.compromisedHosts.join(', ') || 'None verified'}`);
  lines.push(`  Compromised Accounts:   ${data.compromisedUsers.join(', ') || 'None verified'}`);
  lines.push(`  Adversary Infrastructure: ${data.externalIps.join(', ') || 'None verified'}`);
  lines.push("");
  lines.push("-------------------------------------------------------------------------");
  lines.push("4. MITRE ATT&CK THREAT DETECTIONS & VERIFIED FINDINGS");
  if (data.detections.length === 0) {
    lines.push("No verified threat detections triggered.");
  } else {
    data.detections.forEach((d, i) => {
      lines.push(`  [${i + 1}] ${d.rule} [${d.severity.toUpperCase()}]`);
      lines.push(`      Technique: ${d.technique} | Tactic: ${d.tactic}`);
    });
  }
  lines.push("");
  lines.push("-------------------------------------------------------------------------");
  lines.push("5. RECONSTRUCTED ATTACK TIMELINE PROGRESSION");
  if (data.timeline.length === 0) {
    lines.push("No chronological events recorded.");
  } else {
    data.timeline.slice(0, 30).forEach((t) => {
      const actor = t.user ? ` (${t.user}@${t.host || 'host'})` : (t.host ? ` [${t.host}]` : '');
      lines.push(`  ${t.time} [${(t.severity || 'INFO').toUpperCase()}] ${t.action}${actor}`);
    });
  }
  lines.push("");
  lines.push("-------------------------------------------------------------------------");
  lines.push("6. REMEDIATION & INCIDENT RESPONSE RECOMMENDATIONS");
  data.recommendations.forEach((r, idx) => {
    lines.push(`  ${idx + 1}. ${r}`);
  });
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
    let streamText = "BT\n/F1 9.5 Tf\n36 756 Td\n13 TL\n";
    pageLines.forEach((l) => {
      // Bold or header formatting
      if (l.startsWith("===") || l.startsWith("---")) {
        streamText += `(${sanitize(l)}) Tj T*\n`;
      } else if (l.startsWith("1.") || l.startsWith("2.") || l.startsWith("3.") || l.startsWith("4.") || l.startsWith("5.") || l.startsWith("6.")) {
        streamText += `(${sanitize(l)}) Tj T*\n`;
      } else {
        streamText += `(${sanitize(l)}) Tj T*\n`;
      }
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
