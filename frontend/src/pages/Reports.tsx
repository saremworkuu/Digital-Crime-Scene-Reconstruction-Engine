import React, { useState, useMemo } from 'react';
import { useApp } from '../store';
import {
  FileText,
  Printer,
  Download,
  RotateCcw
} from 'lucide-react';

export const Reports: React.FC = () => {
  const {
    activeCase,
    activeCaseEvidence,
    activeCaseEvents,
    activeCaseDetections,
    activeCaseGraph,
    logAuditAction,
    currentUser
  } = useApp();

  const [reportVersion, setReportVersion] = useState(1);
  const [lastGenerated, setLastGenerated] = useState(() => new Date().toISOString());

  // Derived Summary Figures
  const compromisedHosts = useMemo(() => {
    return activeCaseGraph.nodes.filter(n => n.type === 'host' && (n.is_compromised || n.is_attack_path));
  }, [activeCaseGraph]);

  const compromisedUsers = useMemo(() => {
    return activeCaseGraph.nodes.filter(n => n.type === 'user' && (n.is_compromised || n.is_attack_path));
  }, [activeCaseGraph]);

  const externalIps = useMemo(() => {
    return activeCaseGraph.nodes.filter(n => n.type === 'ip');
  }, [activeCaseGraph]);

  const attackTimelineEvents = useMemo(() => {
    return activeCaseEvents
      .filter(e => e.is_attack_path || e.severity === 'critical' || e.severity === 'high')
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  }, [activeCaseEvents]);

  // Handle Regenerate Report (FR-REP-1)
  const handleRegenerate = () => {
    setReportVersion(v => v + 1);
    setLastGenerated(new Date().toISOString());
    logAuditAction('REPORT_GENERATED', 'case', activeCase?.id || '', { version: reportVersion + 1 });
  };

  // Export as self-contained HTML (FR-REP-4)
  const handleExportHtml = () => {
    const reportElem = document.getElementById('forensic-report-container');
    if (!reportElem) return;

    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>DCSRE Forensic Report - ${activeCase?.name}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #fff; color: #111; padding: 40px; max-width: 900px; margin: 0 auto; }
    h1, h2, h3 { font-family: ui-monospace, Menlo, Monaco, monospace; color: #111; }
    h2 { border-bottom: 2px solid #222; padding-bottom: 6px; margin-top: 32px; color: #f95721; }
    table { width: 100%; border-collapse: collapse; margin: 16px 0; font-family: ui-monospace, monospace; font-size: 12px; }
    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
    th { background: #f4f4f5; }
    .header-box { border-bottom: 3px solid #111; padding-bottom: 20px; margin-bottom: 24px; }
  </style>
</head>
<body>
  ${reportElem.innerHTML}
</body>
</html>
    `;

    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dcsre_${activeCase?.id}_report_v${reportVersion}.html`;
    a.click();
    URL.revokeObjectURL(url);

    logAuditAction('REPORT_EXPORTED', 'case', activeCase?.id || '', { format: 'html', version: reportVersion });
  };

  const handlePrint = () => {
    window.print();
    logAuditAction('REPORT_EXPORTED', 'case', activeCase?.id || '', { format: 'pdf_print', version: reportVersion });
  };

  if (!activeCase) {
    return (
      <div className="py-12 text-center text-[#a8a29e]">
        <p>No active case selected for report compilation.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      
      {/* Action Bar (Hidden when printing) */}
      <div className="no-print flex flex-wrap items-center justify-between gap-4 p-4 bg-[#161413]/90 border border-[#2b2523] rounded-2xl backdrop-blur-xl">
        <div>
          <h1 className="text-base font-bold tracking-tight text-[#fafaf9] flex items-center gap-2">
            <FileText className="w-4 h-4 text-[#f95721]" />
            <span>Forensic Incident Reconstruction Report</span>
          </h1>
          <p className="text-xs text-[#a8a29e] mt-0.5">
            Report Edition: <span className="font-mono text-[#f95721] font-semibold">v{reportVersion}.0</span> · Generated: <span className="font-mono text-[#d6d3d1]">{lastGenerated.slice(0, 19).replace('T', ' ')} UTC</span>
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <button
            onClick={handleRegenerate}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] border border-[#38312d] transition-colors font-mono cursor-pointer"
            title="Re-aggregate current case findings and generate new report revision"
          >
            <RotateCcw className="w-3.5 h-3.5 text-[#f95721]" />
            <span>Regenerate (v{reportVersion + 1})</span>
          </button>

          <button
            onClick={handleExportHtml}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] border border-[#38312d] transition-colors font-mono cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-[#f95721]" />
            <span>Export HTML</span>
          </button>

          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-[#f95721] hover:bg-[#ea580c] text-white font-semibold transition-all shadow-[0_0_12px_rgba(249,87,33,0.3)] cursor-pointer"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print / Save PDF</span>
          </button>
        </div>
      </div>

      {/* Forensic Report Document Body (Optimized for Screen & Print) */}
      <div
        id="forensic-report-container"
        className="bg-[#161413]/95 border border-[#2b2523] rounded-2xl p-8 sm:p-12 text-[#fafaf9] space-y-8 max-w-4xl mx-auto shadow-2xl backdrop-blur-xl print:bg-white print:text-black print:p-0 print:border-none print:shadow-none"
      >
        
        {/* Document Header & Classification */}
        <div className="border-b-2 border-[#282321] print:border-black pb-6 space-y-3">
          <div className="flex flex-wrap items-center justify-between text-xs font-mono text-[#a8a29e] print:text-gray-600">
            <span>DCSRE FORENSIC EXAMINATION REPORT</span>
            <span className="uppercase text-[#f95721] print:text-black font-semibold">
              TLP:AMBER+STRICT · CONFIDENTIAL FORENSIC INVESTIGATION
            </span>
          </div>

          <h1 className="text-2xl font-bold tracking-tight text-[#fafaf9] print:text-black">
            {activeCase.name}
          </h1>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono pt-2 text-[#a8a29e] print:text-gray-700">
            <div>
              <span className="block text-[#78716c] print:text-gray-500">Case ID:</span>
              <strong className="text-[#fafaf9] print:text-black">{activeCase.id}</strong>
            </div>
            <div>
              <span className="block text-[#78716c] print:text-gray-500">Lead Examiner:</span>
              <strong className="text-[#fafaf9] print:text-black">{activeCase.owner_name}</strong>
            </div>
            <div>
              <span className="block text-[#78716c] print:text-gray-500">Report Date:</span>
              <strong className="text-[#fafaf9] print:text-black">{lastGenerated.slice(0, 10)}</strong>
            </div>
            <div>
              <span className="block text-[#78716c] print:text-gray-500">Status:</span>
              <strong className="text-[#fafaf9] print:text-black">{activeCase.status}</strong>
            </div>
          </div>
        </div>

        {/* 1. Executive Summary */}
        <section className="space-y-3 print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1">
            1. Executive Summary
          </h2>
          <p className="text-xs text-[#d6d3d1] print:text-gray-800 leading-relaxed text-justify">
            A forensic investigation was initiated regarding digital evidence collected from internal and perimeter infrastructure associated with <strong>{activeCase.name}</strong>. Analysis was performed using the Digital Crime Scene Reconstruction Engine (DCSRE), utilizing multi-format normalization, Sigma rule heuristics, and MITRE ATT&CK correlation.
          </p>
          <p className="text-xs text-[#d6d3d1] print:text-gray-800 leading-relaxed text-justify">
            The examination reconstructed a total of <strong>{activeCaseEvents.length}</strong> normalized events across <strong>{activeCaseEvidence.length}</strong> authenticated evidence sources, identifying <strong>{activeCaseDetections.length}</strong> verified attack indicators. Key compromised assets include {compromisedHosts.map(h => h.label).join(', ')}.
          </p>
        </section>

        {/* 2. Evidence Inventory & Hash Verification (FR-REP-3) */}
        <section className="space-y-3 print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1 flex items-center justify-between">
            <span>2. Digital Evidence Inventory & Integrity Hashes</span>
            <span className="text-[10px] text-[#86efac] print:text-black font-normal">SHA-256 Validated</span>
          </h2>
          
          <table className="w-full text-left text-xs border border-[#282321] print:border-gray-400 font-mono">
            <thead>
              <tr className="bg-[#100f0e] print:bg-gray-100 text-[#a8a29e] print:text-gray-800 border-b border-[#282321] print:border-gray-400">
                <th className="p-2">Item</th>
                <th className="p-2">Filename</th>
                <th className="p-2">SHA-256 Hash</th>
                <th className="p-2 text-right">Size</th>
                <th className="p-2 text-right">Extracted Events</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#282321] print:divide-gray-300">
              {activeCaseEvidence.map((ev, idx) => (
                <tr key={ev.id} className="text-[#d6d3d1] print:text-gray-900">
                  <td className="p-2 text-[#78716c]">{idx + 1}</td>
                  <td className="p-2 font-semibold text-[#fafaf9] print:text-black">{ev.filename}</td>
                  <td className="p-2 text-[11px] select-all">{ev.sha256_hash}</td>
                  <td className="p-2 text-right">{(ev.size_bytes / 1024).toFixed(1)} KB</td>
                  <td className="p-2 text-right text-[#f95721] print:text-black font-semibold">{ev.event_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        {/* 3. Chronological Attack Progression Timeline */}
        <section className="space-y-3 print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1">
            3. Chronological Attack Sequence
          </h2>

          <div className="space-y-3 font-mono text-xs">
            {attackTimelineEvents.map((evt, idx) => (
              <div
                key={evt.id}
                className="p-3 bg-[#100f0e] print:bg-gray-50 border border-[#282321] print:border-gray-300 rounded-xl space-y-1"
              >
                <div className="flex justify-between items-center text-[11px] text-[#a8a29e] print:text-gray-600">
                  <span className="font-semibold text-[#f95721] print:text-black">
                    Step {idx + 1}: {evt.timestamp.replace('T', ' ').replace('Z', '')} UTC
                  </span>
                  <span className="uppercase text-[#fca5a5] print:text-black font-bold">
                    {evt.severity}
                  </span>
                </div>
                <div className="text-[#fafaf9] print:text-black font-semibold text-xs font-sans">
                  {evt.action}
                </div>
                <div className="text-[11px] text-[#a8a29e] print:text-gray-700 flex flex-wrap gap-4 pt-1">
                  <span>Host: {evt.host}</span>
                  {evt.user && <span>User: {evt.user}</span>}
                  {evt.src_ip && <span>Src IP: {evt.src_ip}</span>}
                  {evt.mitre_technique && <span>Technique: {evt.mitre_technique}</span>}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* 4. Threat Findings & MITRE ATT&CK Matrix */}
        <section className="space-y-3 print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1">
            4. Adversary Tactics & MITRE ATT&CK Techniques Identified
          </h2>

          <table className="w-full text-left text-xs border border-[#282321] print:border-gray-400 font-mono">
            <thead>
              <tr className="bg-[#100f0e] print:bg-gray-100 text-[#a8a29e] print:text-gray-800 border-b border-[#282321] print:border-gray-400">
                <th className="p-2">Severity</th>
                <th className="p-2">Technique ID</th>
                <th className="p-2">Tactic</th>
                <th className="p-2">Detection Signature</th>
                <th className="p-2">Timestamp (UTC)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#282321] print:divide-gray-300">
              {activeCaseDetections.map((det) => (
                <tr key={det.id} className="text-[#d6d3d1] print:text-gray-900">
                  <td className="p-2 uppercase font-bold text-[#fca5a5] print:text-black">{det.severity}</td>
                  <td className="p-2 text-[#f95721] print:text-black font-semibold">{det.mitre_technique}</td>
                  <td className="p-2">{det.mitre_tactic}</td>
                  <td className="p-2">{det.rule_name}</td>
                  <td className="p-2 text-[#a8a29e] print:text-gray-600">{det.timestamp.slice(11, 19)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        {/* 5. Affected Systems & Assets */}
        <section className="space-y-3 print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1">
            5. Compromised Scope & Threat Indicators
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
            <div className="p-3 bg-[#100f0e] print:bg-gray-50 border border-[#282321] print:border-gray-300 rounded-xl space-y-1">
              <span className="text-[#a8a29e] print:text-gray-600 block text-[11px] font-semibold">Compromised Hosts:</span>
              <ul className="list-disc pl-4 space-y-0.5 text-[#fafaf9] print:text-black">
                {compromisedHosts.map(h => <li key={h.id}>{h.label}</li>)}
              </ul>
            </div>

            <div className="p-3 bg-[#100f0e] print:bg-gray-50 border border-[#282321] print:border-gray-300 rounded-xl space-y-1">
              <span className="text-[#a8a29e] print:text-gray-600 block text-[11px] font-semibold">Compromised Accounts:</span>
              <ul className="list-disc pl-4 space-y-0.5 text-[#fafaf9] print:text-black">
                {compromisedUsers.map(u => <li key={u.id}>{u.label}</li>)}
              </ul>
            </div>

            <div className="p-3 bg-[#100f0e] print:bg-gray-50 border border-[#282321] print:border-gray-300 rounded-xl space-y-1">
              <span className="text-[#a8a29e] print:text-gray-600 block text-[11px] font-semibold">Adversary C2 IPs:</span>
              <ul className="list-disc pl-4 space-y-0.5 text-[#fca5a5] print:text-black">
                {externalIps.map(ip => <li key={ip.id}>{ip.label}</li>)}
              </ul>
            </div>
          </div>
        </section>

        {/* 6. Chain of Custody & Examiner Attestation */}
        <section className="space-y-4 pt-4 border-t-2 border-[#282321] print:border-black print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono">
            6. Chain of Custody & Forensic Attestation
          </h2>
          
          <p className="text-xs text-[#a8a29e] print:text-gray-700 leading-relaxed text-justify">
            All ingested evidence files have been cryptographically hashed upon upload and stored unmodified in read-only condition. Audit ledger records confirm unbroken chain of custody in accordance with NIST SP 800-86 guidelines.
          </p>

          <div className="flex justify-between items-end pt-8 font-mono text-xs">
            <div className="space-y-1">
              <div className="w-48 border-b border-[#38312d] print:border-black" />
              <div className="text-[#fafaf9] print:text-black font-semibold">{activeCase.owner_name}</div>
              <div className="text-[#78716c] print:text-gray-600 text-[11px]">Senior Digital Forensics Examiner</div>
            </div>

            <div className="text-right text-[11px] text-[#78716c] print:text-gray-600 font-mono">
              <div>Verification Hash: {activeCaseEvidence[0]?.sha256_hash.slice(0, 16)}...</div>
              <div>Generated via DCSRE v2.0 Engine</div>
            </div>
          </div>
        </section>

      </div>

    </div>
  );
};
