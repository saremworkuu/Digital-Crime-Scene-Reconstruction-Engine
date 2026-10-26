import React, { useState, useCallback, useEffect } from 'react';
import { useApp } from '../store';
import { reportsApi, BackendReport, ReportHistoryItem } from '../api/reports';
import {
  FileText,
  Download,
  RotateCcw,
  FolderLock,
  Plus,
  FileCode,
  Loader2,
  History,
  FileDown,
  AlertTriangle,
  ShieldCheck,
  Eye,
  Trash2,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Format accounts consistently with the backend's DOMAIN\user report values. */
function fmtUser(u: string): string {
  if (!u || u === 'unknown' || u === 'SYSTEM' || u === '-') return u;
  // Already has domain prefix → keep
  if (u.includes('\\')) return u;
  // Has @domain → convert to DOMAIN\user
  if (u.includes('@')) {
    const [name, domain] = u.split('@');
    return `${domain.split('.')[0].toUpperCase()}\\${name}`;
  }
  return u;
}

function severityColor(s: string) {
  switch ((s || '').toLowerCase()) {
    case 'critical': return 'text-[#fca5a5]';
    case 'high':     return 'text-[#fdba74]';
    case 'medium':   return 'text-[#fde68a]';
    default:         return 'text-[#a8a29e]';
  }
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export const Reports: React.FC = () => {
  const {
    cases,
    activeCase,
    setActiveCaseId,
    setCurrentPage,
    logAuditAction,
    currentUser,
  } = useApp();

  // ---------------------------------------------------------------------------
  // Backend report state
  // ---------------------------------------------------------------------------
  const [reportData, setReportData] = useState<BackendReport | null>(null);
  const [reportHistory, setReportHistory] = useState<ReportHistoryItem[]>([]);
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(null);
  const [viewingHistory, setViewingHistory] = useState<{ item: ReportHistoryItem; html: string } | null>(null);
  const [loadingHistoryReport, setLoadingHistoryReport] = useState(false);
  const [loadingReport, setLoadingReport] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [downloadingReportId, setDownloadingReportId] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);

  // ---------------------------------------------------------------------------
  // Load saved report history
  // ---------------------------------------------------------------------------
  const loadReportHistory = useCallback(async () => {
    if (!activeCase?.id) return;
    setLoadingHistory(true);
    try {
      const res = await reportsApi.list(activeCase.id);
      if (res?.data && Array.isArray(res.data)) {
        setReportHistory(res.data);
      }
    } catch (err) {
      console.warn('Could not load report history:', err);
    } finally {
      setLoadingHistory(false);
    }
  }, [activeCase?.id]);

  // ---------------------------------------------------------------------------
  // Load latest saved report for on-screen rendering
  // ---------------------------------------------------------------------------
  const loadLatestReport = useCallback(async () => {
    if (!activeCase?.id) return;
    setLoadingReport(true);
    try {
      // Load the saved version; opening the page must not create a new version.
      const res = await reportsApi.latest(activeCase.id);
      if (res?.data) {
        setReportData(res.data as BackendReport);
        setSelectedHistoryId(null);
      }
    } catch (err) {
      console.warn('Could not load report from backend:', err);
    } finally {
      setLoadingReport(false);
    }
  }, [activeCase?.id]);

  useEffect(() => {
    setReportData(null);
    setReportHistory([]);
    setSelectedHistoryId(null);
    setViewingHistory(null);
    if (activeCase?.id) {
      loadLatestReport();
      loadReportHistory();
    }
  }, [activeCase?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  // ---------------------------------------------------------------------------
  // Generate a new version
  // ---------------------------------------------------------------------------
  const handleRegenerate = async () => {
    if (!activeCase?.id) return;
    setIsGenerating(true);
    try {
      const res = await reportsApi.generate(activeCase.id);
      if (res?.data) {
        setReportData(res.data as BackendReport);
        setSelectedHistoryId(null);
        logAuditAction('REPORT_GENERATED', 'case', activeCase.id, {
          version: (res.data as BackendReport).version,
        });
      }
      await loadReportHistory();
    } catch (err) {
      console.warn('Could not generate report via backend:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleViewSavedReport = async (item: ReportHistoryItem) => {
    if (!activeCase?.id) return;
    setLoadingHistoryReport(true);
    try {
      const res = await reportsApi.downloadSavedHtml(activeCase.id, item.id);
      if (res.data) {
        setViewingHistory({ item, html: res.data });
        setSelectedHistoryId(item.id);
      } else {
        throw new Error(res.error || 'Could not load saved report HTML');
      }
    } catch (err) {
      console.error('Could not open saved report:', err);
    } finally {
      setLoadingHistoryReport(false);
    }
  };

  const handleDeleteSavedReport = async (item: ReportHistoryItem) => {
    if (!activeCase?.id) return;
    const shouldDelete = window.confirm(`Delete saved report v${item.version}? This cannot be undone.`);
    if (!shouldDelete) return;

    try {
      const res = await reportsApi.deleteSaved(activeCase.id, item.id);
      if (res.error) throw new Error(res.error);

      const nextHistory = reportHistory.filter((saved) => saved.id !== item.id);
      setReportHistory(nextHistory);
      if (viewingHistory?.item.id === item.id) setViewingHistory(null);
      const deletingDisplayedReport =
        selectedHistoryId === item.id ||
        (!selectedHistoryId && reportData?.version === item.version);
      if (deletingDisplayedReport) {
        setSelectedHistoryId(null);
        if (nextHistory.length > 0) {
          await loadLatestReport();
        } else {
          setReportData(null);
        }
      }
      await loadReportHistory();
    } catch (err) {
      console.error('Could not delete saved report:', err);
    }
  };

  // ---------------------------------------------------------------------------
  // Download a specific saved version
  // ---------------------------------------------------------------------------
  const handleDownloadSavedVersion = async (
    item: ReportHistoryItem,
    format: 'pdf' | 'html' = 'pdf'
  ) => {
    if (!activeCase?.id) return;
    setDownloadingReportId(item.id);
    try {
      const cleanName = activeCase.name.replace(/\s+/g, '_').toLowerCase();
      const verClean = (item.version || '1.0').replace('.', '_');

      if (format === 'pdf') {
        const res = await reportsApi.downloadSavedPdf(activeCase.id, item.id);
        if (res.blob && res.blob.size > 0) {
          const url = URL.createObjectURL(res.blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `forensic_report_${cleanName}_v${verClean}.pdf`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
          logAuditAction('SAVED_REPORT_DOWNLOADED', 'case', activeCase.id, {
            report_id: item.id, version: item.version, format: 'pdf',
          });
        }
      } else {
        const res = await reportsApi.downloadSavedHtml(activeCase.id, item.id);
        if (res.data) {
          const blob = new Blob([res.data], { type: 'text/html' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `forensic_report_${cleanName}_v${verClean}.html`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
          logAuditAction('SAVED_REPORT_DOWNLOADED', 'case', activeCase.id, {
            report_id: item.id, version: item.version, format: 'html',
          });
        }
      }
    } catch (err) {
      console.error('Error downloading saved report:', err);
    } finally {
      setDownloadingReportId(null);
    }
  };

  // ---------------------------------------------------------------------------
  // Export: HTML — snapshot the current on-screen container
  // ---------------------------------------------------------------------------
  const handleExportHtml = async () => {
    if (!activeCase) return;
    try {
      const res = selectedHistoryId
        ? await reportsApi.downloadSavedHtml(activeCase.id, selectedHistoryId)
        : await reportsApi.exportHtml(activeCase.id);
      if (res.data) {
        const blob = new Blob([res.data], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `dcsre_${activeCase.id}_report_v${reportData?.version || '1.0'}.html`;
        a.click();
        URL.revokeObjectURL(url);
        logAuditAction('REPORT_EXPORTED', 'case', activeCase.id, { format: 'html' });
      }
    } catch (err) {
      console.error('Could not export the backend report as HTML:', err);
    }
  };

  // ---------------------------------------------------------------------------
  // Export: JSON — uses backend report fields, not local derived data
  // ---------------------------------------------------------------------------
  const handleExportJson = () => {
    if (!activeCase) return;
    const rd = reportData;
    if (!rd) return;
    const reportJsonData = rd;

    const blob = new Blob([JSON.stringify(reportJsonData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dcsre_${activeCase.id}_report_v${reportData?.version || '1.0'}.json`;
    a.click();
    URL.revokeObjectURL(url);
    logAuditAction('REPORT_EXPORTED', 'case', activeCase.id, {
      format: 'json', version: reportData?.version || '1.0',
    });
  };

  // ---------------------------------------------------------------------------
  // Export: PDF — use the same backend report as the HTML export
  // ---------------------------------------------------------------------------
  const handleDownloadPdf = async () => {
    if (!activeCase) return;
    setIsDownloadingPdf(true);
    try {
      const res = selectedHistoryId
        ? await reportsApi.downloadSavedPdf(activeCase.id, selectedHistoryId)
        : await reportsApi.exportPdf(activeCase.id);
      if (res.blob && res.blob.size > 0) {
        const url = URL.createObjectURL(res.blob);
        const a = document.createElement('a');
        a.href = url;
        const cleanName = activeCase.name.replace(/\s+/g, '_').toLowerCase();
        a.download = `dcsre_${cleanName}_report_v${reportData?.version || '1.0'}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        logAuditAction('REPORT_EXPORTED', 'case', activeCase.id, {
          format: 'pdf', version: reportData?.version || '1.0',
        });
        return;
      }
    } catch (err) {
      console.error('Could not export the backend report as PDF:', err);
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  // ---------------------------------------------------------------------------
  // No case selected
  // ---------------------------------------------------------------------------
  if (!activeCase) {
    return (
      <div className="space-y-6">
        <div className="p-6 bg-[#161413]/90 border border-[#2b2523] rounded-2xl backdrop-blur-xl text-center max-w-xl mx-auto space-y-4 my-12">
          <div className="w-12 h-12 rounded-xl bg-[#2a140d] border border-[#ea580c]/30 flex items-center justify-center mx-auto text-[#f95721]">
            <FolderLock className="w-6 h-6" />
          </div>
          <h2 className="text-lg font-bold text-[#fafaf9]">Select Investigation for Report Generation</h2>
          <p className="text-xs text-[#a8a29e] leading-relaxed">
            Choose an active investigation to compile its forensic reconstruction report.
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

  if (viewingHistory) {
    return (
      <main className="min-h-screen space-y-4 p-4 sm:p-6">
        <div className="no-print flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-[#2b2523] bg-[#161413]/90 p-4">
          <div>
            <h1 className="text-base font-bold text-[#fafaf9]">Saved Report v{viewingHistory.item.version}</h1>
            <p className="mt-1 text-xs text-[#a8a29e]">{viewingHistory.item.title} · {viewingHistory.item.generated_at.slice(0, 19).replace('T', ' ')} UTC</p>
          </div>
          <div className="flex gap-2">
            <button onClick={() => { setViewingHistory(null); setSelectedHistoryId(null); }} className="rounded-lg border border-[#38312d] bg-[#241e1b] px-3 py-2 text-xs text-[#fafaf9]">Back to Reports</button>
            <button onClick={() => handleDownloadSavedVersion(viewingHistory.item, 'pdf')} className="rounded-lg bg-[#f95721] px-3 py-2 text-xs font-semibold text-white">Download PDF</button>
            <button onClick={() => handleDownloadSavedVersion(viewingHistory.item, 'html')} className="rounded-lg border border-[#38312d] bg-[#241e1b] px-3 py-2 text-xs text-[#fafaf9]">Download HTML</button>
          </div>
        </div>
        <iframe title={`Forensic report version ${viewingHistory.item.version}`} srcDoc={viewingHistory.html} sandbox="" className="min-h-[80vh] w-full rounded-xl border border-[#2b2523] bg-white" />
      </main>
    );
  }

  if (loadingHistoryReport) {
    return <div className="p-10 text-center text-sm text-[#a8a29e]">Opening saved report…</div>;
  }

  if (!reportData) {
    return (
      <div className="max-w-xl mx-auto my-12 p-6 rounded-2xl border border-[#38312d] bg-[#161413]/90 text-center space-y-3">
        {loadingReport ? <Loader2 className="w-5 h-5 animate-spin text-[#f95721] mx-auto" /> : null}
        <p className="text-sm font-semibold text-[#fafaf9]">
          {loadingReport ? 'Loading the saved report from the backend…' : 'Saved report data is unavailable.'}
        </p>
        {!loadingReport && (
          <button onClick={loadLatestReport} className="px-3 py-1.5 rounded-lg bg-[#f95721] text-white text-xs font-semibold">
            Retry
          </button>
        )}
      </div>
    );
  }

  const rd = reportData;
  const isDraft = rd.status === 'DRAFT';
  const reportVersion = rd.version;
  const lastGenerated = rd.generated_at;
  const reportHash = rd.report_hash;

  const hosts = rd.compromised_assets?.hosts || [];
  const users = rd.compromised_assets?.users || [];
  const advIps = rd.compromised_assets?.adversary_infrastructure || [];
  const observedIps = rd.compromised_assets?.observed_ips || [];
  const entityGroups = rd.entity_groups;
  const timeline = rd.attack_timeline_summary || [];
  const detections = rd.mitre_coverage || [];
  const evidenceRows = rd.chain_of_custody?.length ? rd.chain_of_custody : rd.evidence_manifest?.map((e: any) => ({
    ...e,
    hash_status: e.sha256_hash ? 'recorded (not re-verified)' : 'not recorded',
    uploaded_by: e.uploader || e.uploaded_by || 'Unattributed',
  })) || [];

  return (
    <div className="space-y-6">

      {/* ── Action Bar ─────────────────────────────────────────── */}
      <div className="no-print flex flex-wrap items-center justify-between gap-4 p-4 bg-[#161413]/90 border border-[#2b2523] rounded-2xl backdrop-blur-xl">
        <div className="flex flex-wrap items-center gap-4">
          <div>
            <h1 className="text-base font-bold tracking-tight text-[#fafaf9] flex items-center gap-2">
              <FileText className="w-4 h-4 text-[#f95721]" />
              <span>Forensic Incident Reconstruction Report</span>
            </h1>
            <p className="text-xs text-[#a8a29e] mt-0.5">
              Edition: <span className="font-mono text-[#f95721] font-semibold">v{reportVersion}</span>
              {' · '}Generated:{' '}
              <span className="font-mono text-[#d6d3d1]">{lastGenerated.slice(0, 19).replace('T', ' ')} UTC</span>
              {isDraft && (
                <span className="ml-2 px-1.5 py-0.5 rounded bg-[#fef3c7]/20 text-[#fbbf24] border border-[#fbbf24]/30 text-[10px] font-bold font-mono">
                  DRAFT
                </span>
              )}
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
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          <button
            onClick={handleRegenerate}
            disabled={isGenerating}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] border border-[#38312d] transition-colors font-mono cursor-pointer disabled:opacity-60"
            title="Compile current findings into a new saved report version"
          >
            {isGenerating ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin text-[#f95721]" />
            ) : (
              <RotateCcw className="w-3.5 h-3.5 text-[#f95721]" />
            )}
            <span>{isGenerating ? 'Compiling...' : 'Generate New Version'}</span>
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
          >
            {isDownloadingPdf ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Download className="w-3.5 h-3.5" />
            )}
            <span>{isDownloadingPdf ? 'Downloading...' : 'Download PDF'}</span>
          </button>
        </div>
      </div>

      {/* ── Report History ──────────────────────────────────────── */}
      <div className="no-print p-4 bg-[#161413]/90 border border-[#2b2523] rounded-2xl backdrop-blur-xl space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-[#f95721]" />
            <h2 className="text-sm font-bold text-[#fafaf9]">Report History</h2>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#241e1b] text-[#a8a29e] border border-[#38312d]">
              {reportHistory.length} saved {reportHistory.length === 1 ? 'version' : 'versions'}
            </span>
          </div>
          <button
            onClick={loadReportHistory}
            disabled={loadingHistory}
            className="text-[11px] font-mono text-[#a8a29e] hover:text-[#fafaf9] transition-colors flex items-center gap-1 cursor-pointer"
          >
            <RotateCcw className={`w-3 h-3 ${loadingHistory ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>

        {loadingHistory && reportHistory.length === 0 ? (
          <div className="text-center py-4 text-xs font-mono text-[#78716c]">Loading…</div>
        ) : reportHistory.length === 0 ? (
          <div className="text-center py-4 text-xs font-mono text-[#78716c] border border-dashed border-[#2b2523] rounded-xl">
            No reports saved yet. Click "Generate New Version" to create and store version 1.0.
          </div>
        ) : (
          <div className="divide-y divide-[#26201e] border border-[#2b2523] rounded-xl overflow-hidden">
            {reportHistory.map((item) => {
              const isCurrent = selectedHistoryId
                ? item.id === selectedHistoryId
                : item.version === reportVersion;
              const isDownloading = downloadingReportId === item.id;
              return (
                <div
                  key={item.id}
                  className={`flex flex-wrap items-center justify-between gap-3 p-3 text-xs transition-colors ${
                    isCurrent ? 'bg-[#241a15]/60' : 'bg-[#1a1715]/40 hover:bg-[#201c19]'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-[#f95721] font-bold px-2 py-0.5 rounded bg-[#2b1810] border border-[#ea580c]/30 text-[11px]">
                      v{item.version}
                    </span>
                    <div>
                      <div className="font-semibold text-[#fafaf9] flex items-center gap-2">
                        <span>{item.title}</span>
                        {isCurrent && (
                          <span className="text-[10px] font-mono px-1.5 rounded bg-[#10b981]/20 text-[#34d399] border border-[#10b981]/30">
                            Current
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-[#78716c] font-mono mt-0.5">
                        {(item.generated_at || '').slice(0, 19).replace('T', ' ')} UTC
                        {item.generator_name ? ` · ${item.generator_name}` : ''}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 font-mono text-[11px]">
                    <button
                      onClick={() => handleViewSavedReport(item)}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-[#241e1b] hover:bg-[#342a26] text-[#fafaf9] border border-[#38312d] transition-colors cursor-pointer"
                      title="View this saved report version"
                    >
                      <Eye className="w-3 h-3 text-[#f95721]" />
                      <span>View</span>
                    </button>
                    <button
                      onClick={() => handleDownloadSavedVersion(item, 'pdf')}
                      disabled={isDownloading}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-[#241e1b] hover:bg-[#342a26] text-[#fafaf9] border border-[#38312d] transition-colors cursor-pointer disabled:opacity-50"
                    >
                      {isDownloading ? (
                        <Loader2 className="w-3 h-3 animate-spin text-[#f95721]" />
                      ) : (
                        <FileDown className="w-3 h-3 text-[#f95721]" />
                      )}
                      <span>PDF</span>
                    </button>
                    <button
                      onClick={() => handleDownloadSavedVersion(item, 'html')}
                      disabled={isDownloading}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-[#241e1b] hover:bg-[#342a26] text-[#a8a29e] hover:text-[#fafaf9] border border-[#38312d] transition-colors cursor-pointer disabled:opacity-50"
                    >
                      <span>HTML</span>
                    </button>
                    <button
                      onClick={() => handleDeleteSavedReport(item)}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-[#2a1513] hover:bg-[#471c18] text-[#fca5a5] border border-[#7f1d1d]/50 transition-colors cursor-pointer"
                      title="Delete this saved report version"
                    >
                      <Trash2 className="w-3 h-3" />
                      <span>Delete</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Forensic Report Document Body ─────────────────────────────────── */}
      <div
        id="forensic-report-container"
        className="bg-[#161413]/95 border border-[#2b2523] rounded-2xl p-4 sm:p-8 md:p-12 text-[#fafaf9] space-y-8 max-w-4xl mx-auto shadow-2xl backdrop-blur-xl print:bg-white print:text-black print:p-0 print:border-none print:shadow-none"
      >

        {/* DRAFT banner */}
        {isDraft && (
          <div className="flex items-start gap-3 p-4 rounded-xl bg-[#fef3c7]/10 border-2 border-[#d97706]/50 text-[#fbbf24] print:bg-yellow-50 print:border-yellow-400 print:text-yellow-800">
            <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
            <p className="text-xs font-semibold font-mono leading-relaxed">
              DRAFT — AUTO-GENERATED BY DCSRE RULE ENGINE.
              REQUIRES EXAMINER REVIEW AND APPROVAL BEFORE USE AS LEGAL EVIDENCE.
            </p>
          </div>
        )}

        {/* Loading overlay */}
        {loadingReport && (
          <div className="flex items-center justify-center gap-3 py-8 text-[#a8a29e]">
            <Loader2 className="w-5 h-5 animate-spin text-[#f95721]" />
            <span className="text-sm font-mono">Loading report from backend…</span>
          </div>
        )}

        {/* Document Header */}
        <div className="border-b-2 border-[#282321] print:border-black pb-6 space-y-3">
          <div className="flex flex-wrap items-center justify-between text-xs font-mono text-[#a8a29e] print:text-gray-600">
            <span>DCSRE FORENSIC EXAMINATION REPORT</span>
            <span className="uppercase text-[#f95721] print:text-black font-semibold">
                            {rd?.classification || 'CONFIDENTIAL // TLP:AMBER - DFIR EVIDENTIARY'}
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
              <strong className="text-[#fafaf9] print:text-black">
                {rd?.generator_name || activeCase.owner_name}
              </strong>
            </div>
            <div>
              <span className="block text-[#78716c] print:text-gray-500">Report Date:</span>
              <strong className="text-[#fafaf9] print:text-black">{lastGenerated.slice(0, 10)}</strong>
            </div>
            <div>
              <span className="block text-[#78716c] print:text-gray-500">Status:</span>
              <strong className={`${isDraft ? 'text-[#fbbf24]' : 'text-[#86efac]'} print:text-black`}>
                {rd?.status || 'DRAFT'}
              </strong>
            </div>
          </div>
        </div>

        {/* 1. Executive Summary */}
        <section className="space-y-3 print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1">
            1. Executive Summary
          </h2>
          {rd?.executive_summary ? (
            <p className="text-xs text-[#d6d3d1] print:text-gray-800 leading-relaxed text-justify">
              {rd.executive_summary}
            </p>
          ) : (
            <>
              <p className="text-xs text-[#d6d3d1] print:text-gray-800 leading-relaxed text-justify">
                A digital forensic investigation was conducted for security incident:{' '}
                <strong>{activeCase.name}</strong>. Analysis was performed using the Digital Crime
                Scene Reconstruction Engine (DCSRE), using multi-format event normalization, Sigma
                detection rules, and MITRE ATT&amp;CK framework mapping.
              </p>
              <p className="text-xs text-[#d6d3d1] print:text-gray-800 leading-relaxed text-justify">
                The examination reconstructed <strong>{timeline.length}</strong> events across{' '}
                <strong>{evidenceRows.length}</strong> evidence sources, with{' '}
                <strong>{detections.length}</strong> detections recorded. Key hosts involved:{' '}
                {hosts.length > 0 ? hosts.join(', ') : 'none identified'}.
              </p>
            </>
          )}
        </section>

        {/* 2. Digital Evidence Inventory */}
        <section className="space-y-3 print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1 flex flex-wrap items-center justify-between gap-2">
            <span>2. Digital Evidence Inventory &amp; Integrity Hashes</span>
            <span className="text-[10px] text-[#a8a29e] print:text-gray-600 font-normal flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5 inline" />
              SHA-256 recorded at upload
            </span>
          </h2>

          <div className="overflow-x-auto w-full">
            <table className="w-full text-left text-xs border border-[#282321] print:border-gray-400 font-mono min-w-[540px]">
              <thead>
                <tr className="bg-[#100f0e] print:bg-gray-100 text-[#a8a29e] print:text-gray-800 border-b border-[#282321] print:border-gray-400">
                  <th className="p-2">#</th>
                  <th className="p-2">Filename</th>
                  <th className="p-2">SHA-256 Hash</th>
                  <th className="p-2">Hash Status</th>
                  <th className="p-2 text-right">Size</th>
                  <th className="p-2 text-right">Events</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#282321] print:divide-gray-300">
                {evidenceRows.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-4 text-center text-[#78716c] font-sans">
                      No evidence files ingested.
                    </td>
                  </tr>
                ) : (
                  evidenceRows.map((ev: any, idx: number) => (
                    <tr key={idx} className="text-[#d6d3d1] print:text-gray-900">
                      <td className="p-2 text-[#78716c]">{idx + 1}</td>
                      <td className="p-2 font-semibold text-[#fafaf9] print:text-black">{ev.filename}</td>
                      <td className="p-2 text-[11px] select-all font-mono text-[#f95721] print:text-black break-all">
                        {ev.sha256_hash || '—'}
                      </td>
                      <td className="p-2 text-[#a8a29e] text-[11px]">
                        {ev.hash_status || 'recorded (not re-verified)'}
                      </td>
                      <td className="p-2 text-right">{Number(ev.size_bytes || 0).toLocaleString()} bytes ({(Number(ev.size_bytes || 0) / 1024).toFixed(2)} KiB)</td>
                      <td className="p-2 text-right text-[#f95721] print:text-black font-semibold">
                        {ev.document_artifact ? 'Document artifact' : (ev.event_count ?? 0)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* 3. Chronological Attack Sequence */}
        <section className="space-y-3 print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1">
            3. Chronological Attack Sequence
          </h2>

          <div className="space-y-3 font-mono text-xs">
            {timeline.length === 0 ? (
              <div className="p-4 bg-[#100f0e] border border-[#282321] rounded-xl text-center text-[#78716c] font-sans">
                No attack timeline events recorded.
              </div>
            ) : (
              timeline.map((evt: any, idx: number) => (
                <div
                  key={idx}
                  className="p-3 bg-[#100f0e] print:bg-gray-50 border border-[#282321] print:border-gray-300 rounded-xl space-y-1"
                >
                  <div className="flex justify-between items-center text-[11px] text-[#a8a29e] print:text-gray-600">
                    <span className="font-semibold text-[#f95721] print:text-black">
                      Step {idx + 1}: {(evt.timestamp || '').replace('T', ' ').replace('Z', '')} UTC
                    </span>
                    <span className={`uppercase font-bold ${severityColor(evt.severity)}`}>
                      {evt.severity}
                    </span>
                  </div>
                  <div className="text-[#fafaf9] print:text-black font-semibold text-xs font-sans">
                    {evt.action}
                  </div>
                  <div className="text-[11px] text-[#a8a29e] print:text-gray-700 flex flex-wrap gap-4 pt-1">
                    {evt.host && <span>Host: {evt.host}</span>}
                    {evt.user && evt.user !== 'unknown' && evt.user !== 'SYSTEM' && (
                      <span>User: {fmtUser(evt.user)}</span>
                    )}
                    {evt.src_ip && <span>Src IP: {evt.src_ip}</span>}
                    {evt.mitre_tactic && <span>Tactic: {evt.mitre_tactic}</span>}
                    {evt.mitre_technique && <span>Technique: {evt.mitre_technique}</span>}
                    {evt.source_file && <span>Source file: {evt.source_file}</span>}
                    {evt.source_record_references?.length > 0 && <span>Record references: {evt.source_record_references.join(', ')}</span>}
                    {evt.corroborated_by && evt.corroborated_by.length > 1 && (
                      <span className="text-[#78716c]">Sources: {evt.corroborated_by.join(', ')}</span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </section>

        {/* 4. Threat Detections & MITRE ATT&CK */}
        <section className="space-y-3 print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1">
            4. Adversary Tactics &amp; MITRE ATT&amp;CK Detections
          </h2>

          <div className="overflow-x-auto w-full">
            <table className="w-full text-left text-xs border border-[#282321] print:border-gray-400 font-mono min-w-[540px]">
              <thead>
                <tr className="bg-[#100f0e] print:bg-gray-100 text-[#a8a29e] print:text-gray-800 border-b border-[#282321] print:border-gray-400">
                  <th className="p-2">Severity</th>
                  <th className="p-2">Technique</th>
                  <th className="p-2">Tactic</th>
                  <th className="p-2">Detection</th>
                  <th className="p-2">First Seen (UTC)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#282321] print:divide-gray-300">
                {detections.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="p-4 text-center text-[#78716c] font-sans">
                      No detections recorded for this case.
                    </td>
                  </tr>
                ) : (
                  detections.map((det: any, i: number) => (
                    <tr key={det.id || i} className="text-[#d6d3d1] print:text-gray-900">
                      <td className={`p-2 uppercase font-bold ${severityColor(det.severity)}`}>
                        {det.severity}
                      </td>
                      <td className="p-2 text-[#f95721] print:text-black font-semibold">
                        {(det.mitre_techniques_all || [det.mitre_technique]).filter(Boolean).join(', ') || '—'}
                      </td>
                      <td className="p-2">{det.mitre_tactic || '—'}</td>
                      <td className="p-2">{det.rule_name}</td>
                      {/* first_seen is the event time, not the upload/ingestion time */}
                      <td className="p-2 text-[#a8a29e] print:text-gray-600">
                        {det.first_seen ? det.first_seen.slice(0, 19).replace('T', ' ') : 'Not available'}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* 5. Observed Scope */}
        <section className="space-y-3 print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1">
            5. Observed Scope &amp; Network Indicators
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
            {/* Hosts — IPs that resolve to a hostname are merged */}
            <div className="p-3 bg-[#100f0e] print:bg-gray-50 border border-[#282321] print:border-gray-300 rounded-xl space-y-1">
              <span className="text-[#a8a29e] print:text-gray-600 block text-[11px] font-semibold">
                Hosts in Matching Findings:
              </span>
              <ul className="list-disc pl-4 space-y-0.5 text-[#fafaf9] print:text-black">
                {hosts.length > 0 ? (
                  hosts.map(h => <li key={h}>{h}</li>)
                ) : (
                  <li className="text-[#78716c] list-none">None identified</li>
                )}
              </ul>
            </div>

            {/* Accounts — deduplicated, DOMAIN\user format */}
            <div className="p-3 bg-[#100f0e] print:bg-gray-50 border border-[#282321] print:border-gray-300 rounded-xl space-y-1">
              <span className="text-[#a8a29e] print:text-gray-600 block text-[11px] font-semibold">
                Accounts in Matching Findings/Events:
              </span>
              <ul className="list-disc pl-4 space-y-0.5 text-[#fafaf9] print:text-black">
                {users.length > 0 ? (
                  users.map(u => <li key={u}>{u}</li>)
                ) : (
                  <li className="text-[#78716c] list-none">None identified</li>
                )}
              </ul>
            </div>

            {/* Observed IP addresses; presence alone does not prove attribution. */}
            <div className="p-3 bg-[#100f0e] print:bg-gray-50 border border-[#282321] print:border-gray-300 rounded-xl space-y-1">
              <span className="text-[#a8a29e] print:text-gray-600 block text-[11px] font-semibold">
                Adversary Infrastructure:
              </span>
              <ul className="list-disc pl-4 space-y-0.5 text-[#fca5a5] print:text-black">
                {entityGroups?.adversary_infrastructure?.length ? (
                  entityGroups.adversary_infrastructure.map((item, index) => <li key={`${item.address}-${index}`}>{item.address} ({item.roles.join(', ') || 'Other Observed Addresses'})</li>)
                ) : advIps.filter((ip: string) => ip !== 'None identified').length ? (
                  advIps.filter((ip: string) => ip !== 'None identified').map((ip: string) => <li key={ip}>{ip}</li>)
                ) : (
                  <li className="text-[#78716c] list-none">None detected</li>
                )}
              </ul>
              <span className="text-[#a8a29e] print:text-gray-600 block text-[11px] font-semibold pt-2">Other Observed Addresses:</span>
              <ul className="list-disc pl-4 space-y-0.5 text-[#d6d3d1] print:text-gray-700">
                {(entityGroups?.other_observed_addresses || observedIps.filter((ip: string) => !advIps.includes(ip))).filter((ip: string) => ip !== 'None identified').length ? (entityGroups?.other_observed_addresses || observedIps.filter((ip: string) => !advIps.includes(ip))).filter((ip: string) => ip !== 'None identified').map((ip: string) => <li key={ip}>{ip}</li>) : <li className="list-none text-[#78716c]">None identified</li>}
              </ul>
              <p className="text-[10px] text-[#78716c]">Observed network addresses are not classified as adversary infrastructure unless linked to a finding role.</p>
            </div>
          </div>

          {rd?.compromised_assets?.dwell_time && rd.compromised_assets.dwell_time !== 'Not determinable' && (
            <p className="text-[11px] font-mono text-[#a8a29e] pt-1">
              Estimated dwell time: <strong className="text-[#fafaf9]">{rd.compromised_assets.dwell_time}</strong>
            </p>
          )}
        </section>

        {/* 6. Indicators from findings and evidence */}
        <section className="space-y-3 print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1">
            6. Indicators
          </h2>
          {(rd.indicators || []).length ? (
            <div className="overflow-x-auto w-full">
              <table className="w-full text-left text-xs border border-[#282321] print:border-gray-400 font-mono min-w-[500px]">
                <thead><tr className="bg-[#100f0e] print:bg-gray-100 text-[#a8a29e] print:text-gray-800"><th className="p-2">Type</th><th className="p-2">Indicator</th><th className="p-2">Role</th><th className="p-2">Source finding</th></tr></thead>
                <tbody className="divide-y divide-[#282321] print:divide-gray-300">
                  {rd.indicators!.map((indicator, index) => <tr key={`${indicator.type}-${indicator.value}-${index}`}><td className="p-2">{indicator.type}</td><td className="p-2 font-mono break-all">{indicator.value}</td><td className="p-2">{indicator.role || 'Observed'}</td><td className="p-2">{indicator.source_finding || 'Observed event'}</td></tr>)}
                </tbody>
              </table>
            </div>
          ) : <p className="text-xs text-[#78716c]">No indicators identified.</p>}
        </section>

        {/* 7. Remediation Directives */}
        <section className="space-y-3 print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1">
            7. Containment &amp; Remediation Directives
          </h2>
          {rd.remediation && rd.remediation.length > 0 ? (
            <ol className="list-decimal pl-5 space-y-2 text-xs text-[#d6d3d1] print:text-gray-800 font-sans leading-relaxed">
              {rd.remediation.map((r: any, i: number) => {
                const action = typeof r === 'string' ? r : r.action;
                const refs = typeof r === 'string' ? '' : r.finding_refs;
                return (
                  <li key={i}>
                    {action}
                    {refs && (
                      <span className="ml-1 text-[#78716c] font-mono text-[10px]">
                        (findings: {refs})
                      </span>
                    )}
                  </li>
                );
              })}
            </ol>
          ) : <p className="text-xs text-[#78716c]">No remediation directives recorded.</p>}
        </section>

        {/* 8. Chain of Custody & Attestation */}
        <section className="space-y-4 pt-4 border-t-2 border-[#282321] print:border-black print-break-inside-avoid">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono">
            8. Chain of Custody &amp; Forensic Attestation
          </h2>

          <p className="text-xs text-[#a8a29e] print:text-gray-700 leading-relaxed text-justify">
            {rd?.chain_of_custody_note || 'SHA-256 values are recorded at upload. Current file verification status is listed per evidence item when available.'}
          </p>

          {rd?.methodology && (
            <p className="text-xs text-[#78716c] print:text-gray-600 leading-relaxed">
              <strong className="text-[#a8a29e]">Methodology:</strong> {rd.methodology}
            </p>
          )}

          {rd?.limitations && (
            <p className="text-xs text-[#78716c] print:text-gray-600 leading-relaxed">
              <strong className="text-[#a8a29e]">Limitations:</strong> {rd.limitations}
            </p>
          )}

          <div className="flex justify-between items-end pt-8 font-mono text-xs">
            <div className="space-y-1">
              <div className="w-48 border-b border-[#38312d] print:border-black" />
              <div className="text-[#fafaf9] print:text-black font-semibold">
                {rd?.generator_name || activeCase.owner_name}
              </div>
              <div className="text-[#78716c] print:text-gray-600 text-[11px]">
                {rd?.generator_role || 'Senior Digital Forensics Examiner'}
              </div>
            </div>

            <div className="text-right text-[11px] text-[#78716c] print:text-gray-600 font-mono space-y-0.5">
              {/* Real report content hash from the backend — not a file hash */}
              <div>
                Report SHA-256:{' '}
                <span className="text-[#a8a29e] select-all">
                  {reportHash || 'not computed'}
                </span>
              </div>
              <div className="text-[10px]">Generated via DCSRE Forensics Engine v{rd?.rule_set_version || '—'}</div>
              {isDraft && (
                <div className="text-[#fbbf24] font-bold text-[10px]">STATUS: DRAFT</div>
              )}
            </div>
          </div>
        </section>

      </div>
    </div>
  );
};
