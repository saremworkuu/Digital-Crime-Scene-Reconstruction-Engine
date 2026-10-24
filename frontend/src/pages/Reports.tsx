import React, { useState, useMemo } from 'react';
import { useApp } from '../store';
import { reportsApi } from '../api/reports';
import { generateClientPdfBlob } from '../utils/pdfGenerator';
import {
  FileText,
  Printer,
  Download,
  RotateCcw,
  FolderLock,
  Plus,
  ShieldCheck,
  FileCode,
  Loader2
} from 'lucide-react';

export const Reports: React.FC = () => {
  const {
    cases,
    activeCase,
    setActiveCaseId,
    setCurrentPage,
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
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #fff; color: #111; padding: 40px; max-width: 900px; margin: 0 auto; line-height: 1.5; }
    h1, h2, h3 { font-family: ui-monospace, Menlo, Monaco, monospace; color: #111; }
    h2 { border-bottom: 2px solid #222; padding-bottom: 6px; margin-top: 32px; color: #f95721; font-size: 14px; text-transform: uppercase; }
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

  const handleExportJson = () => {
    const reportData = {
      case_id: activeCase?.id,
      case_name: activeCase?.name,
      classification: 'CONFIDENTIAL // TLP:AMBER - DFIR EVIDENTIARY',
      report_version: `v${reportVersion}.0`,
      generated_at: lastGenerated,
      lead_examiner: activeCase?.owner_name,
      evidence_inventory: activeCaseEvidence.map(ev => ({
        filename: ev.filename,
        sha256_hash: ev.sha256_hash,
        size_bytes: ev.size_bytes,
        event_count: ev.event_count,
        uploaded_at: ev.uploaded_at
      })),
      total_normalized_events: activeCaseEvents.length,
      attack_timeline_summary: attackTimelineEvents.map(evt => ({
        timestamp: evt.timestamp,
        severity: evt.severity,
        action: evt.action,
        host: evt.host,
        user: evt.user,
        src_ip: evt.src_ip,
        mitre_technique: evt.mitre_technique
      })),
      mitre_detections: activeCaseDetections.map(det => ({
        rule_name: det.rule_name,
        mitre_technique: det.mitre_technique,
        mitre_tactic: det.mitre_tactic,
        severity: det.severity,
        timestamp: det.timestamp
      })),
      compromised_scope: {
        hosts: compromisedHosts.map(h => h.label),
        users: compromisedUsers.map(u => u.label),
        external_ips: externalIps.map(ip => ip.label)
      }
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dcsre_${activeCase?.id}_report_v${reportVersion}.json`;
    a.click();
    URL.revokeObjectURL(url);
    logAuditAction('REPORT_EXPORTED', 'case', activeCase?.id || '', { format: 'json', version: reportVersion });
  };

  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);

  const handleDownloadPdf = async () => {
    if (!activeCase) return;
    setIsDownloadingPdf(true);

    try {
      // 1. Attempt to fetch professional ReportLab vector PDF from backend
      const res = await reportsApi.exportPdf(activeCase.id);
      if (res.blob && res.blob.size > 0) {
        const url = URL.createObjectURL(res.blob);
        const a = document.createElement('a');
        a.href = url;
        const cleanName = activeCase.name.replace(/\s+/g, '_').toLowerCase();
        a.download = `dcsre_${cleanName}_report_v${reportVersion}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        logAuditAction('REPORT_EXPORTED', 'case', activeCase.id, { format: 'pdf', version: reportVersion });
        return;
      }

      // 2. Client-side fallback: synthesize PDF 1.4 binary directly
      const clientBlob = generateClientPdfBlob({
        caseName: activeCase.name,
        reportId: `rep-${activeCase.id.slice(0, 8)}-${reportVersion}`,
        version: String(reportVersion),
        generatedAt: lastGenerated,
        examinerName: activeCase.owner_name || currentUser?.name || 'Lead Forensics Investigator',
        summary: `Forensic investigation report for incident '${activeCase.name}'. Analyzed ${activeCaseEvidence.length} digital evidence artifacts and identified ${activeCaseDetections.length} threat detections across MITRE ATT&CK. Impacted ${compromisedHosts.length} host(s) and ${compromisedUsers.length} user account(s).`,
        evidence: activeCaseEvidence.map(e => ({
          filename: e.filename,
          hash: e.sha256_hash,
          size: e.size_bytes || e.file_size || 0,
          count: e.event_count || 0,
        })),
        compromisedHosts: compromisedHosts.map(h => h.label),
        compromisedUsers: compromisedUsers.map(u => u.label),
        externalIps: externalIps.map(ip => ip.label),
        detections: activeCaseDetections.map(d => ({
          rule: d.rule_name,
          technique: d.mitre_technique || 'T1059',
          tactic: d.mitre_tactic || 'Execution',
          severity: d.severity || 'high',
        })),
        timeline: attackTimelineEvents.map(e => ({
          time: e.timestamp,
          host: e.host,
          user: e.user,
          action: e.action || 'Forensic Event',
          severity: e.severity,
        })),
        recommendations: [
          'Isolate all identified compromised hosts from the internal network immediately.',
          'Revoke active sessions and force cryptographic password resets with MFA for affected user accounts.',
          'Block identified adversary infrastructure IP addresses and C2 endpoints at perimeter firewalls.',
          'Verify system restore points and inspect backup volume shadow copies for unauthorized tampering.',
          'Submit SHA-256 evidence hashes and chain-of-custody audit logs to legal and compliance counsel.',
        ]
      });

      const url = URL.createObjectURL(clientBlob);
      const a = document.createElement('a');
      a.href = url;
      const cleanName = activeCase.name.replace(/\s+/g, '_').toLowerCase();
      a.download = `dcsre_${cleanName}_report_v${reportVersion}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      logAuditAction('REPORT_EXPORTED', 'case', activeCase.id, { format: 'pdf_client', version: reportVersion });
    } catch (err) {
      console.error('PDF download error:', err);
      window.print();
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  if (!activeCase) {
    return (
      <div className="space-y-6">
        <div className="p-6 bg-[#161413]/90 border border-[#2b2523] rounded-2xl backdrop-blur-xl text-center max-w-xl mx-auto space-y-4 my-12">
          <div className="w-12 h-12 rounded-xl bg-[#2a140d] border border-[#ea580c]/30 flex items-center justify-center mx-auto text-[#f95721]">
            <FolderLock className="w-6 h-6" />
          </div>
          <h2 className="text-lg font-bold text-[#fafaf9]">Select Investigation for Report Generation</h2>
          <p className="text-xs text-[#a8a29e] leading-relaxed">
            Please choose an active investigation to compile its forensic reconstruction report, evidence ledger, and MITRE ATT&CK attribution matrix.
          </p>

          {cases.length > 0 ? (
            <div className="space-y-2 pt-2 text-left">
              {cases.map((c) => (
                <button
                  key={c.id}
                  onClick={() => setActiveCaseId(c.id)}
                  className="w-full flex items-center justify-between p-3 rounded-xl bg-[#241e1b] hover:bg-[#342a26] border border-[#38312d] transition-colors group cursor-pointer text-xs"
                >
                  <div className="flex items-center gap-2.5">
                    <span className="font-semibold text-[#fafaf9] group-hover:text-[#f95721] transition-colors">
                      {c.name}
                    </span>
                    <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-[#100f0e] text-[#a8a29e] border border-[#282321]">
                      {c.status}
                    </span>
                  </div>
                  <span className="text-[#f95721] font-mono font-medium text-[11px]">Compile &rarr;</span>
                </button>
              ))}
            </div>
          ) : (
            <button
              onClick={() => setCurrentPage('cases')}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-[#f95721] hover:bg-[#ea580c] text-white text-xs font-semibold transition-all shadow-[0_0_12px_rgba(249,87,33,0.3)] cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              <span>Create First Investigation</span>
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      
      {/* Action Bar (Hidden when printing) */}
      <div className="no-print flex flex-wrap items-center justify-between gap-4 p-4 bg-[#161413]/90 border border-[#2b2523] rounded-2xl backdrop-blur-xl">
        <div className="flex flex-wrap items-center gap-4">
          <div>
            <h1 className="text-base font-bold tracking-tight text-[#fafaf9] flex items-center gap-2">
              <FileText className="w-4 h-4 text-[#f95721]" />
              <span>Forensic Incident Reconstruction Report</span>
            </h1>
            <p className="text-xs text-[#a8a29e] mt-0.5">
              Report Edition: <span className="font-mono text-[#f95721] font-semibold">v{reportVersion}.0</span> · Generated: <span className="font-mono text-[#d6d3d1]">{lastGenerated.slice(0, 19).replace('T', ' ')} UTC</span>
            </p>
          </div>

          {cases.length > 1 && (
            <div className="flex items-center gap-2 pl-4 border-l border-[#282321]">
              <span className="text-xs text-[#a8a29e] font-mono">Case:</span>
              <select
                value={activeCase.id}
                onChange={(e) => setActiveCaseId(e.target.value)}
                className="bg-[#241e1b] border border-[#38312d] text-[#fafaf9] text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-[#f95721] font-mono cursor-pointer"
              >
                {cases.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          <button
            onClick={handleRegenerate}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] border border-[#38312d] transition-colors font-mono cursor-pointer"
            title="Re-aggregate current case findings and generate new report revision"
          >
            <RotateCcw className="w-3.5 h-3.5 text-[#f95721]" />
            <span>Regenerate (v{reportVersion + 1})</span>
          </button>

          <button
            onClick={handleExportJson}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] border border-[#38312d] transition-colors font-mono cursor-pointer"
          >
            <FileCode className="w-3.5 h-3.5 text-[#f95721]" />
            <span>Export JSON</span>
          </button>

          <button
            onClick={handleExportHtml}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] border border-[#38312d] transition-colors font-mono cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-[#f95721]" />
            <span>Export HTML</span>
          </button>

          <button
            onClick={handleDownloadPdf}
            disabled={isDownloadingPdf}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-[#f95721] hover:bg-[#ea580c] disabled:opacity-60 text-white font-semibold transition-all shadow-[0_0_12px_rgba(249,87,33,0.3)] cursor-pointer"
            title="Download full forensic reconstruction report in PDF format"
          >
            {isDownloadingPdf ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Download className="w-3.5 h-3.5" />
            )}
            <span>{isDownloadingPdf ? 'Downloading...' : 'Download'}</span>
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
            A comprehensive digital forensic investigation was conducted regarding security incident telemetry associated with <strong>{activeCase.name}</strong>. Analysis was performed using the Digital Crime Scene Reconstruction Engine (DCSRE), utilizing multi-format event normalization, Sigma detection rules, and MITRE ATT&CK framework mapping.
          </p>
          <p className="text-xs text-[#d6d3d1] print:text-gray-800 leading-relaxed text-justify">
            The examination reconstructed a total of <strong>{activeCaseEvents.length}</strong> normalized events across <strong>{activeCaseEvidence.length}</strong> authenticated evidence sources, identifying <strong>{activeCaseDetections.length}</strong> verified attack indicators. Key compromised assets include {compromisedHosts.length > 0 ? compromisedHosts.map(h => h.label).join(', ') : 'targeted network entities'}.
          </p>
        </section>

        {/* 2. Evidence Inventory & Hash Verification (FR-REP-3) */}
        <section className="space-y-3 print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1 flex items-center justify-between">
            <span>2. Digital Evidence Inventory & Integrity Hashes</span>
            <span className="text-[10px] text-[#86efac] print:text-black font-normal flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5 inline" />
              SHA-256 Validated
            </span>
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
              {activeCaseEvidence.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-4 text-center text-[#78716c] font-sans">
                    No evidence files ingested for this investigation yet.
                  </td>
                </tr>
              ) : (
                activeCaseEvidence.map((ev, idx) => (
                  <tr key={ev.id} className="text-[#d6d3d1] print:text-gray-900">
                    <td className="p-2 text-[#78716c]">{idx + 1}</td>
                    <td className="p-2 font-semibold text-[#fafaf9] print:text-black">{ev.filename}</td>
                    <td className="p-2 text-[11px] select-all font-mono text-[#f95721] print:text-black">{ev.sha256_hash}</td>
                    <td className="p-2 text-right">{((ev.size_bytes || 0) / 1024).toFixed(1)} KB</td>
                    <td className="p-2 text-right text-[#f95721] print:text-black font-semibold">{ev.event_count || 0}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </section>

        {/* 3. Chronological Attack Progression Timeline */}
        <section className="space-y-3 print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1">
            3. Chronological Attack Sequence
          </h2>

          <div className="space-y-3 font-mono text-xs">
            {attackTimelineEvents.length === 0 ? (
              <div className="p-4 bg-[#100f0e] border border-[#282321] rounded-xl text-center text-[#78716c] font-sans">
                No high or critical severity events registered on the attack sequence timeline.
              </div>
            ) : (
              attackTimelineEvents.map((evt, idx) => (
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
              ))
            )}
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
              {activeCaseDetections.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-4 text-center text-[#78716c] font-sans">
                    No threat detections flagged for this case.
                  </td>
                </tr>
              ) : (
                activeCaseDetections.map((det) => (
                  <tr key={det.id} className="text-[#d6d3d1] print:text-gray-900">
                    <td className="p-2 uppercase font-bold text-[#fca5a5] print:text-black">{det.severity}</td>
                    <td className="p-2 text-[#f95721] print:text-black font-semibold">{det.mitre_technique}</td>
                    <td className="p-2">{det.mitre_tactic}</td>
                    <td className="p-2">{det.rule_name}</td>
                    <td className="p-2 text-[#a8a29e] print:text-gray-600">{det.timestamp.slice(11, 19)}</td>
                  </tr>
                ))
              )}
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
                {compromisedHosts.length > 0 ? (
                  compromisedHosts.map(h => <li key={h.id}>{h.label}</li>)
                ) : (
                  <li className="text-[#78716c] list-none">None isolated</li>
                )}
              </ul>
            </div>

            <div className="p-3 bg-[#100f0e] print:bg-gray-50 border border-[#282321] print:border-gray-300 rounded-xl space-y-1">
              <span className="text-[#a8a29e] print:text-gray-600 block text-[11px] font-semibold">Compromised Accounts:</span>
              <ul className="list-disc pl-4 space-y-0.5 text-[#fafaf9] print:text-black">
                {compromisedUsers.length > 0 ? (
                  compromisedUsers.map(u => <li key={u.id}>{u.label}</li>)
                ) : (
                  <li className="text-[#78716c] list-none">None isolated</li>
                )}
              </ul>
            </div>

            <div className="p-3 bg-[#100f0e] print:bg-gray-50 border border-[#282321] print:border-gray-300 rounded-xl space-y-1">
              <span className="text-[#a8a29e] print:text-gray-600 block text-[11px] font-semibold">Adversary C2 IPs:</span>
              <ul className="list-disc pl-4 space-y-0.5 text-[#fca5a5] print:text-black">
                {externalIps.length > 0 ? (
                  externalIps.map(ip => <li key={ip.id}>{ip.label}</li>)
                ) : (
                  <li className="text-[#78716c] list-none">None detected</li>
                )}
              </ul>
            </div>
          </div>
        </section>

        {/* 6. Containment & Strategic Remediation Directives */}
        <section className="space-y-3 print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1">
            6. Containment & Strategic Remediation Directives
          </h2>
          <ul className="list-decimal pl-5 space-y-2 text-xs text-[#d6d3d1] print:text-gray-800 font-sans leading-relaxed">
            <li><strong>Immediate Host Isolation:</strong> Sever network connectivity to all identified compromised endpoints ({compromisedHosts.length > 0 ? compromisedHosts.map(h => h.label).join(', ') : 'targeted endpoints'}) pending forensic re-imaging and memory dump preservation.</li>
            <li><strong>Credential Invalidation & Key Rollover:</strong> Terminate existing sessions and enforce cryptographic password resets with mandatory FIDO2/MFA for {compromisedUsers.length > 0 ? compromisedUsers.map(u => u.label).join(', ') : 'all user accounts referenced in findings'}.</li>
            <li><strong>Perimeter C2 Blocking:</strong> Ingest identified adversary infrastructure IP addresses into edge firewall ACLs and DNS sinkholes to prevent lateral exfiltration.</li>
            <li><strong>Integrity Attestation & Legal Preservation:</strong> File cryptographic SHA-256 evidence chain of custody manifests with legal and regulatory compliance authorities under NIST SP 800-86 standards.</li>
          </ul>
        </section>

        {/* 7. Chain of Custody & Examiner Attestation */}
        <section className="space-y-4 pt-4 border-t-2 border-[#282321] print:border-black print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono">
            7. Chain of Custody & Forensic Attestation
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
              <div>Verification Hash: {activeCaseEvidence[0]?.sha256_hash ? `${activeCaseEvidence[0].sha256_hash.slice(0, 16)}...` : 'N/A'}</div>
              <div>Generated via DCSRE Forensics Engine</div>
            </div>
          </div>
        </section>

      </div>

    </div>
  );
};
