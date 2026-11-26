import React, { useState, useCallback, useEffect, useRef } from 'react';
import { useApp } from '../store';
import { reportsApi, BackendReport, ReportHistoryItem } from '../api/reports';
import { formatCaseNameWithId, formatCaseShortId } from '../utils/caseDisplay';
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
    case 'high': return 'text-[#fdba74]';
    case 'medium': return 'text-[#fde68a]';
    default: return 'text-[#a8a29e]';
  }
}

// Module-level + storage caches and in-flight deduplication so StrictMode, tab switches, and F5 reloads are instant
const latestReportCache = new Map<string, BackendReport>();
const reportHistoryCache = new Map<string, ReportHistoryItem[]>();
const inFlightLatest = new Map<string, Promise<BackendReport | null>>();
const inFlightHistory = new Map<string, Promise<ReportHistoryItem[] | null>>();
const inFlightGenerate = new Map<string, Promise<BackendReport | null>>();

if (typeof window !== 'undefined') {
  window.addEventListener('dcsre:workspace-cleared', () => {
    latestReportCache.clear();
    reportHistoryCache.clear();
  });
}

function getCachedReport(caseId: string): BackendReport | null {
  const mem = latestReportCache.get(caseId);
  if (mem) return mem;
  try {
    const raw =
      sessionStorage.getItem(`dcsre_report_cache_${caseId}`) ??
      localStorage.getItem(`dcsre_report_cache_${caseId}`);
    if (raw) {
      const parsed = JSON.parse(raw) as BackendReport;
      latestReportCache.set(caseId, parsed);
      return parsed;
    }
  } catch {
    // ignore
  }
  return null;
}

function setCachedReport(caseId: string, data: BackendReport) {
  latestReportCache.set(caseId, data);
  const serialized = JSON.stringify(data);
  try {
    localStorage.setItem(`dcsre_report_cache_${caseId}`, serialized);
  } catch {
    // ignore quota errors
  }
  try {
    sessionStorage.setItem(`dcsre_report_cache_${caseId}`, serialized);
  } catch {
    // ignore quota errors
  }
}

function deleteCachedReport(caseId: string) {
  latestReportCache.delete(caseId);
  try {
    sessionStorage.removeItem(`dcsre_report_cache_${caseId}`);
    localStorage.removeItem(`dcsre_report_cache_${caseId}`);
  } catch {
    // ignore
  }
}

function getCachedHistory(caseId: string): ReportHistoryItem[] | null {
  const mem = reportHistoryCache.get(caseId);
  if (mem) return mem;
  try {
    const raw =
      sessionStorage.getItem(`dcsre_history_cache_${caseId}`) ??
      localStorage.getItem(`dcsre_history_cache_${caseId}`);
    if (raw) {
      const parsed = JSON.parse(raw) as ReportHistoryItem[];
      if (Array.isArray(parsed)) {
        reportHistoryCache.set(caseId, parsed);
        return parsed;
      }
    }
  } catch {
    // ignore
  }
  return null;
}

function setCachedHistory(caseId: string, list: ReportHistoryItem[]) {
  reportHistoryCache.set(caseId, list);
  const serialized = JSON.stringify(list);
  try {
    localStorage.setItem(`dcsre_history_cache_${caseId}`, serialized);
  } catch {
    // ignore
  }
  try {
    sessionStorage.setItem(`dcsre_history_cache_${caseId}`, serialized);
  } catch {
    // ignore
  }
}

function deleteCachedHistory(caseId: string) {
  reportHistoryCache.delete(caseId);
  try {
    sessionStorage.removeItem(`dcsre_history_cache_${caseId}`);
    localStorage.removeItem(`dcsre_history_cache_${caseId}`);
  } catch {
    // ignore
  }
}

function fetchLatestReportDeduped(caseId: string): Promise<BackendReport | null> {
  const existing = inFlightLatest.get(caseId);
  if (existing) return existing;
  const promise = reportsApi.latest(caseId)
    .then((res) => {
      const data = (res?.data as BackendReport) || null;
      if (data) setCachedReport(caseId, data);
      return data;
    })
    .catch((err) => {
      console.warn('Could not load report from backend:', err);
      return null;
    })
    .finally(() => {
      inFlightLatest.delete(caseId);
    });
  inFlightLatest.set(caseId, promise);
  return promise;
}

function fetchReportHistoryDeduped(caseId: string): Promise<ReportHistoryItem[] | null> {
  const existing = inFlightHistory.get(caseId);
  if (existing) return existing;
  const promise = reportsApi.list(caseId)
    .then((res) => {
      const list = Array.isArray(res?.data) ? res.data : null;
      if (list) setCachedHistory(caseId, list);
      return list;
    })
    .catch((err) => {
      console.warn('Could not load report history:', err);
      return null;
    })
    .finally(() => {
      inFlightHistory.delete(caseId);
    });
  inFlightHistory.set(caseId, promise);
  return promise;
}

function generateReportDeduped(caseId: string): Promise<BackendReport | null> {
  const existing = inFlightGenerate.get(caseId);
  if (existing) return existing;
  const promise = reportsApi.generate(caseId)
    .then((res) => {
      const data = (res?.data as BackendReport) || null;
      if (data) setCachedReport(caseId, data);
      return data;
    })
    .catch((err) => {
      console.warn('Could not compile report on backend:', err);
      return null;
    })
    .finally(() => {
      inFlightGenerate.delete(caseId);
    });
  inFlightGenerate.set(caseId, promise);
  return promise;
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export const Reports: React.FC = () => {
  const {
    cases,
    activeCase,
    activeCaseEvidence,
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
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [downloadingReportId, setDownloadingReportId] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isLoadingReport, setIsLoadingReport] = useState(false);
  const [reportLoadError, setReportLoadError] = useState<string | null>(null);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);

  // ---------------------------------------------------------------------------
  // Load saved report history
  // ---------------------------------------------------------------------------
  const loadReportHistory = useCallback(async () => {
    const caseId = activeCase?.id;
    if (!caseId) return;
    const cached = getCachedHistory(caseId);
    if (!cached) setLoadingHistory(true);
    try {
      const list = await fetchReportHistoryDeduped(caseId);
      if (list && activeCaseIdRef.current === caseId) {
        setReportHistory(list);
      }
    } finally {
      setLoadingHistory(false);
    }
  }, [activeCase?.id]);

  // ---------------------------------------------------------------------------
  // Load latest saved report for on-screen rendering
  // ---------------------------------------------------------------------------
  const activeCaseIdRef = useRef<string | null>(activeCase?.id ?? null);
  activeCaseIdRef.current = activeCase?.id ?? null;
  const autoCompiledForCaseRef = useRef<Set<string>>(new Set());
  const [historyResolvedCaseId, setHistoryResolvedCaseId] = useState<string | null>(null);
  const caseHasEvidence = Boolean(
    activeCase && (activeCaseEvidence.length > 0 || (activeCase.evidence_count ?? 0) > 0)
  );

  const loadLatestReport = useCallback(async (): Promise<boolean> => {
    const caseId = activeCase?.id;
    if (!caseId) return false;
    const data = await fetchLatestReportDeduped(caseId);
    if (data && activeCaseIdRef.current === caseId) {
      setReportData(data);
      setReportLoadError(null);
      setSelectedHistoryId(null);
      return true;
    }
    return false;
  }, [activeCase?.id]);

  useEffect(() => {
    let cancelled = false;
    const caseId = activeCase?.id;

    setViewingHistory(null);
    setReportLoadError(null);

    if (!caseId) {
      setSelectedHistoryId(null);
      setReportData(null);
      setReportHistory([]);
      setIsLoadingReport(false);
      setHistoryResolvedCaseId(null);
      return;
    }

    let hasFreshUpload = false;
    try {
      hasFreshUpload =
        sessionStorage.getItem(`dcsre_fresh_upload_${caseId}`) === '1' ||
        localStorage.getItem(`dcsre_fresh_upload_${caseId}`) === '1';
    } catch {
      // ignore
    }

    const cachedHistory = getCachedHistory(caseId) || [];
    const cachedReport = hasFreshUpload ? null : getCachedReport(caseId);
    setReportHistory(cachedHistory);
    setReportData(cachedReport);
    setSelectedHistoryId(
      cachedReport && cachedHistory.length > 0
        ? (cachedHistory.find((h) => h.version === cachedReport.version)?.id ?? cachedHistory[0]?.id ?? null)
        : null
    );
    setHistoryResolvedCaseId(null);

    const canExpectReport = hasFreshUpload || caseHasEvidence || cachedHistory.length > 0;
    if (!cachedReport && canExpectReport) {
      setIsLoadingReport(true);
    } else {
      setIsLoadingReport(false);
    }

    const loadHistoryAndReport = async () => {
      setLoadingHistory(true);
      try {
        if (hasFreshUpload) {
          const list = await fetchReportHistoryDeduped(caseId);
          if (cancelled || activeCaseIdRef.current !== caseId) return;
          const resolvedHistory = list || [];
          setReportHistory(resolvedHistory);
          setHistoryResolvedCaseId(caseId);

          const compiled =
            resolvedHistory.length > 0
              ? await generateReportDeduped(caseId)
              : await fetchLatestReportDeduped(caseId);
          if (cancelled || activeCaseIdRef.current !== caseId) return;

          if (compiled) {
            autoCompiledForCaseRef.current.add(caseId);
            try {
              sessionStorage.removeItem(`dcsre_fresh_upload_${caseId}`);
              localStorage.removeItem(`dcsre_fresh_upload_${caseId}`);
            } catch {
              // ignore
            }
            setReportData(compiled);
            setReportLoadError(null);
            deleteCachedHistory(caseId);
            const refreshed = await fetchReportHistoryDeduped(caseId);
            if (!cancelled && activeCaseIdRef.current === caseId && refreshed) {
              setReportHistory(refreshed);
              const matching = refreshed.find((h) => h.version === compiled.version) || refreshed[0];
              if (matching?.id) setSelectedHistoryId(matching.id);
            }
          }
          return;
        }

        // Fetch history and latest report concurrently so opening or refreshing Reports
        // displays the report immediately as soon as it is ready.
        const shouldFetchLatest = Boolean(cachedReport) || canExpectReport;
        const [list, latest] = await Promise.all([
          fetchReportHistoryDeduped(caseId),
          shouldFetchLatest ? fetchLatestReportDeduped(caseId) : Promise.resolve(null),
        ]);
        if (cancelled || activeCaseIdRef.current !== caseId) return;

        const resolvedHistory = list || cachedHistory;
        if (list) setReportHistory(list);
        setHistoryResolvedCaseId(caseId);

        if (latest) {
          setReportData(latest);
          setReportLoadError(null);
          const matching = resolvedHistory.find((h) => h.version === latest.version) || resolvedHistory[0];
          if (matching?.id) setSelectedHistoryId(matching.id);
        } else if (resolvedHistory.length > 0 && !cachedReport) {
          // Fallback to compiling/loading latest if history just became non-empty
          const fallbackLatest = await fetchLatestReportDeduped(caseId);
          if (!cancelled && activeCaseIdRef.current === caseId && fallbackLatest) {
            setReportData(fallbackLatest);
            const matching = resolvedHistory.find((h) => h.version === fallbackLatest.version) || resolvedHistory[0];
            if (matching?.id) setSelectedHistoryId(matching.id);
          }
        }
      } finally {
        if (!cancelled) {
          setLoadingHistory(false);
          setIsLoadingReport(false);
        }
      }
    };

    void loadHistoryAndReport();

    return () => {
      cancelled = true;
    };
  }, [activeCase?.id, caseHasEvidence]); // eslint-disable-line react-hooks/exhaustive-deps

  // ---------------------------------------------------------------------------
  // Generate a new version
  // ---------------------------------------------------------------------------
  const handleRegenerate = async () => {
    if (!activeCase?.id) return;
    setIsGenerating(true);
    setReportLoadError(null);
    try {
      const res = await reportsApi.generate(activeCase.id);
      if (res?.data) {
        const nextReport = res.data as BackendReport;
        setCachedReport(activeCase.id, nextReport);
        setReportData(nextReport);
        deleteCachedHistory(activeCase.id);
        await loadReportHistory();
        const latestList = await fetchReportHistoryDeduped(activeCase.id);
        const matchingItem = latestList?.find((h) => h.version === nextReport.version);
        setSelectedHistoryId(matchingItem?.id ?? null);
        logAuditAction('report.generated', 'case', activeCase.id, {
          version: nextReport.version,
        });
      }
    } catch (err) {
      console.warn('Could not generate report via backend:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleViewSavedReport = async (item: ReportHistoryItem) => {
    if (!activeCase?.id) return;
    setLoadingHistoryReport(true);
    setReportLoadError(null);
    try {
      const res = await reportsApi.getSaved(activeCase.id, item.id);
      if (res.data) {
        const loaded = res.data as BackendReport;
        setCachedReport(activeCase.id, loaded);
        setReportData(loaded);
        setSelectedHistoryId(item.id);
        setViewingHistory(null);
      } else {
        throw new Error(res.error || 'Could not load saved report');
      }
    } catch (err: any) {
      console.error('Could not open saved report:', err);
      setReportLoadError(err?.message || 'Could not load saved report.');
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
      setCachedHistory(activeCase.id, nextHistory);
      setReportHistory(nextHistory);
      if (viewingHistory?.item.id === item.id) setViewingHistory(null);
      const deletingDisplayedReport =
        selectedHistoryId === item.id ||
        (!selectedHistoryId && reportData?.version === item.version);
      if (deletingDisplayedReport) {
        autoCompiledForCaseRef.current.add(activeCase.id);
        deleteCachedReport(activeCase.id);
        setSelectedHistoryId(null);
        setReportData(null);
      }
      if (nextHistory.length === 0) {
        autoCompiledForCaseRef.current.add(activeCase.id);
      }
      deleteCachedHistory(activeCase.id);
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
          logAuditAction('report.downloaded', 'case', activeCase.id, {
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
          logAuditAction('report.downloaded', 'case', activeCase.id, {
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
        logAuditAction('report.exported', 'case', activeCase.id, {
          report_id: reportData?.id || selectedHistoryId || null,
          version: reportData?.version || '1.0',
          report_hash: reportData?.report_hash || null,
          format: 'html',
        });
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
    logAuditAction('report.exported', 'case', activeCase.id, {
      report_id: reportData?.id || selectedHistoryId || null,
      version: reportData?.version || '1.0',
      report_hash: reportData?.report_hash || null,
      format: 'json',
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
        logAuditAction('report.exported', 'case', activeCase.id, {
          report_id: reportData?.id || selectedHistoryId || null,
          version: reportData?.version || '1.0',
          report_hash: reportData?.report_hash || null,
          format: 'pdf',
        });
        return;
      }
    } catch (err) {
      console.error('Could not export the backend report as PDF:', err);
    } finally {
      setIsDownloadingPdf(false);
    }
  };

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

  const rd = reportData;
  const isDraft = rd ? rd.status === 'DRAFT' : true;
  const isStale = Boolean(rd?.stale);
  const analysisNotRun = rd ? Boolean(rd.analysis_not_run) : true;
  const emptySectionMsg = analysisNotRun
    ? 'Analysis not run / no normalized events'
    : 'None identified';
  const reportVersion = rd?.version || '—';
  const lastGenerated = rd?.generated_at || '';
  const reportHash = rd?.report_hash;

  const hosts = rd?.compromised_assets?.hosts || [];
  const users = rd?.compromised_assets?.users || [];
  const advIps = rd?.compromised_assets?.adversary_infrastructure || [];
  const observedIps = rd?.compromised_assets?.observed_ips || [];
  const entityGroups = rd?.entity_groups;
  const timeline = rd?.attack_timeline_summary || [];
  const detections = rd?.mitre_coverage || [];
  const evidenceRows = rd?.chain_of_custody?.length ? rd.chain_of_custody : rd?.evidence_manifest?.map((e: any) => ({
    ...e,
    hash_status: e.sha256_hash ? 'recorded (not re-verified)' : 'not recorded',
    uploaded_by: e.uploader || e.uploaded_by || 'Unattributed',
  })) || [];
  const hasUploadedEvidence = evidenceRows.length > 0 || (activeCase?.evidence_count ?? 0) > 0;

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
              {rd ? (
                <>
                  Edition: <span className="font-mono text-[#f95721] font-semibold">v{reportVersion}</span>
                  {' · '}Generated:{' '}
                  <span className="font-mono text-[#d6d3d1]">{lastGenerated ? `${lastGenerated.slice(0, 19).replace('T', ' ')} UTC` : '—'}</span>
                  {isDraft && (
                    <span className="ml-2 px-1.5 py-0.5 rounded bg-[#fef3c7]/20 text-[#fbbf24] border border-[#fbbf24]/30 text-[10px] font-bold font-mono">
                      DRAFT
                    </span>
                  )}
                </>
              ) : (
                <span className="font-mono text-[#a8a29e]">
                  {!activeCase
                    ? 'No investigation selected'
                    : isLoadingReport
                      ? 'Loading report summary…'
                      : 'No report generated yet'}
                </span>
              )}
            </p>
          </div>

          {cases.length > 0 && (
            <div className="flex items-center gap-2 pl-4 border-l border-[#282321]">
              <span className="text-xs text-[#a8a29e] font-mono">Case:</span>
              <select
                value={activeCase?.id || ''}
                onChange={(e) => setActiveCaseId(e.target.value)}
                className="bg-[#241e1b] border border-[#38312d] text-[#fafaf9] text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-[#f95721] font-mono cursor-pointer"
              >
                {!activeCase && <option value="">-- Select Investigation --</option>}
                {cases.map((c) => (
                  <option key={c.id} value={c.id}>{formatCaseNameWithId(c.name, c.id)}</option>
                ))}
              </select>
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          <button
            onClick={handleRegenerate}
            disabled={!activeCase || isGenerating}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] border border-[#38312d] transition-colors font-mono cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            title={activeCase ? 'Compile current findings into a new saved report version' : 'Select or create an investigation first'}
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
            disabled={!activeCase || !rd}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] border border-[#38312d] transition-colors font-mono cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <FileCode className="w-3.5 h-3.5 text-[#f95721]" />
            <span>Export JSON</span>
          </button>

          <button
            onClick={handleExportHtml}
            disabled={!activeCase || !rd}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] border border-[#38312d] transition-colors font-mono cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Download className="w-3.5 h-3.5 text-[#f95721]" />
            <span>Export HTML</span>
          </button>

          <button
            onClick={handleDownloadPdf}
            disabled={!activeCase || !rd || isDownloadingPdf}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-[#f95721] hover:bg-[#ea580c] disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold transition-all shadow-[0_0_12px_rgba(249,87,33,0.3)] cursor-pointer"
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
              const isCurrent = Boolean(rd) && (
                selectedHistoryId
                  ? item.id === selectedHistoryId
                  : item.version === reportVersion
              );
              const isDownloading = downloadingReportId === item.id;
              return (
                <div
                  key={item.id}
                  onClick={() => handleViewSavedReport(item)}
                  className={`flex flex-wrap items-center justify-between gap-3 p-3 text-xs transition-colors cursor-pointer ${isCurrent ? 'bg-[#241a15]/60' : 'bg-[#1a1715]/40 hover:bg-[#201c19]'
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
                            Viewing
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
                      onClick={(e) => {
                        e.stopPropagation();
                        handleViewSavedReport(item);
                      }}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-[#241e1b] hover:bg-[#342a26] text-[#fafaf9] border border-[#38312d] transition-colors cursor-pointer"
                      title="View this saved report version"
                    >
                      <Eye className="w-3 h-3 text-[#f95721]" />
                      <span>View</span>
                    </button>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDownloadSavedVersion(item, 'pdf');
                      }}
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
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDownloadSavedVersion(item, 'html');
                      }}
                      disabled={isDownloading}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-[#241e1b] hover:bg-[#342a26] text-[#a8a29e] hover:text-[#fafaf9] border border-[#38312d] transition-colors cursor-pointer disabled:opacity-50"
                    >
                      <span>HTML</span>
                    </button>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDeleteSavedReport(item);
                      }}
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
      {loadingHistoryReport || isLoadingReport || (activeCase && loadingHistory && !rd) ? (
        <div
          id="forensic-report-container"
          className="bg-[#161413]/95 border border-[#2b2523] rounded-2xl p-8 md:p-12 text-[#a8a29e] max-w-4xl mx-auto shadow-2xl backdrop-blur-xl text-center text-xs font-mono"
        >
          <Loader2 className="w-5 h-5 animate-spin text-[#f95721] mx-auto mb-2" />
          {loadingHistoryReport ? 'Opening saved report…' : 'Compiling forensic report…'}
        </div>
      ) : !rd ? (
        <div
          id="forensic-report-container"
          className="bg-[#161413]/95 border border-dashed border-[#2b2523] rounded-2xl p-8 md:p-16 text-[#a8a29e] max-w-4xl mx-auto shadow-2xl backdrop-blur-xl min-h-[320px] flex flex-col items-center justify-center text-center space-y-3"
        >
          {reportLoadError && (
            <p className="text-xs text-[#fca5a5] font-mono">{reportLoadError}</p>
          )}
          <p className="text-xs font-mono text-[#78716c]">
            {!activeCase
              ? 'Select an investigation above or upload evidence to generate a forensic report.'
              : 'No report generated yet. Upload evidence or click "Generate New Version" above.'}
          </p>
        </div>
      ) : (
      <div
        id="forensic-report-container"
        className="bg-[#161413]/95 border border-[#2b2523] rounded-2xl p-4 sm:p-8 md:p-12 text-[#fafaf9] space-y-8 max-w-4xl mx-auto shadow-2xl backdrop-blur-xl print:bg-white print:text-black print:p-0 print:border-none print:shadow-none"
      >

        {/* STALE banner */}
        {isStale && (
          <div className="no-print flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-[#dc2626]/15 border-2 border-[#dc2626]/60 text-[#fca5a5]">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0 text-[#f87171]" />
              <p className="text-xs font-semibold font-mono leading-relaxed">
                STALE: case changed after this report was generated - regenerate
              </p>
            </div>
            <button
              onClick={handleRegenerate}
              disabled={isGenerating}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#dc2626] hover:bg-[#b91c1c] text-white text-xs font-semibold transition-colors cursor-pointer disabled:opacity-60"
            >
              {isGenerating ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <RotateCcw className="w-3.5 h-3.5" />
              )}
              <span>{isGenerating ? 'Regenerating...' : 'Regenerate'}</span>
            </button>
          </div>
        )}

        {/* DRAFT banner */}
        {rd && isDraft && (
          <div className="flex items-start gap-3 p-4 rounded-xl bg-[#fef3c7]/10 border-2 border-[#d97706]/50 text-[#fbbf24] print:bg-yellow-50 print:border-yellow-400 print:text-yellow-800">
            <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
            <p className="text-xs font-semibold font-mono leading-relaxed">
              DRAFT — AUTO-GENERATED BY DCSRE RULE ENGINE.
              REQUIRES EXAMINER REVIEW AND APPROVAL BEFORE USE AS LEGAL EVIDENCE.
            </p>
          </div>
        )}

        {/* Empty / No-evidence / No-report notice banner inside report layout */}
        {(!activeCase || !rd || !hasUploadedEvidence) && (
          <div className="no-print flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-[#100f0e] border border-[#38312d] text-[#d6d3d1]">
            <div className="flex items-start gap-3">
              <FolderLock className="w-4 h-4 mt-0.5 shrink-0 text-[#f95721]" />
              <div className="space-y-1">
                <p className="text-xs font-semibold font-mono text-[#fafaf9]">
                  {!activeCase
                    ? 'No investigation selected'
                    : isLoadingReport && !rd
                      ? 'Loading forensic report…'
                      : !rd
                        ? (reportLoadError || 'No report generated yet for this investigation')
                        : 'No evidence files uploaded for this investigation yet'}
                </p>
                <p className="text-xs text-[#a8a29e]">
                  {!activeCase
                    ? (cases.length > 0
                      ? 'Select an existing investigation from the Case dropdown above or upload evidence to start a new one.'
                      : 'Create an investigation or upload evidence files to populate the report sections below.')
                    : 'Upload forensic evidence files and generate a report version to populate findings, timeline steps, and indicators.'}
                </p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {!activeCase && cases.length === 0 && (
                <button
                  onClick={() => setCurrentPage('cases')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] border border-[#38312d] text-[#fafaf9] text-xs font-mono cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5 text-[#f95721]" />
                  <span>Create Investigation</span>
                </button>
              )}
              <button
                onClick={() => setCurrentPage('evidence')}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#f95721] hover:bg-[#ea580c] text-white text-xs font-semibold cursor-pointer"
              >
                <span>Upload Evidence</span>
              </button>
            </div>
          </div>
        )}



        {/* Document Header */}
        <div className="border-b-2 border-[#282321] print:border-black pb-6 space-y-3">
          <div className="flex flex-wrap items-center justify-between text-xs font-mono text-[#a8a29e] print:text-gray-600 gap-2">
            <span>DCSRE FORENSIC EXAMINATION REPORT</span>
            <span className="uppercase text-[#f95721] print:text-black font-semibold">
              {rd?.classification || 'CONFIDENTIAL // TLP:AMBER - DFIR EVIDENTIARY'}
            </span>
          </div>

          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#fafaf9] print:text-black">
            {activeCase ? formatCaseNameWithId(activeCase.name, activeCase.id) : 'No Investigation Selected'}
          </h1>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono pt-2 text-[#a8a29e] print:text-gray-700">
            <div>
              <span className="block text-[#78716c] print:text-gray-500">Case ID:</span>
              <strong className="text-[#fafaf9] print:text-black">{activeCase?.id || '—'}</strong>
            </div>
            <div>
              <span className="block text-[#78716c] print:text-gray-500">Lead Examiner:</span>
              <strong className="text-[#fafaf9] print:text-black">
                {rd?.generator_name || activeCase?.owner_name || currentUser?.name || '—'}
              </strong>
            </div>
            <div>
              <span className="block text-[#78716c] print:text-gray-500">Report Date:</span>
              <strong className="text-[#fafaf9] print:text-black">{lastGenerated ? lastGenerated.slice(0, 10) : '—'}</strong>
            </div>
            <div>
              <span className="block text-[#78716c] print:text-gray-500">Status:</span>
              <strong className={`${isDraft ? 'text-[#fbbf24]' : 'text-[#86efac]'} print:text-black`}>
                {rd?.status || 'NO REPORT'}
              </strong>
            </div>
          </div>
        </div>

        {/* 1. Executive Summary */}
        <section className="space-y-3">
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
                <strong>{activeCase?.name || 'Pending Case Selection'}</strong>. Analysis was performed using the Digital Crime
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
        <section className="space-y-3">
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
        <section className="space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1">
            3. Chronological Attack Sequence
          </h2>

          <div className="space-y-3 font-mono text-xs">
            {timeline.length === 0 ? (
              <div className="p-4 bg-[#100f0e] border border-[#282321] rounded-xl text-center text-[#78716c] font-sans">
                {analysisNotRun ? emptySectionMsg : 'No attack timeline events recorded.'}
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
        <section className="space-y-3">
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
                      {analysisNotRun ? emptySectionMsg : 'No detections recorded for this case.'}
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
        <section className="space-y-3">
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
                {hosts.filter((h: string) => h !== 'None identified' && h !== 'Analysis not run / no normalized events').length > 0 ? (
                  hosts.filter((h: string) => h !== 'None identified' && h !== 'Analysis not run / no normalized events').map(h => <li key={h}>{h}</li>)
                ) : (
                  <li className="text-[#78716c] list-none">{emptySectionMsg}</li>
                )}
              </ul>
            </div>

            {/* Accounts — deduplicated, DOMAIN\user format */}
            <div className="p-3 bg-[#100f0e] print:bg-gray-50 border border-[#282321] print:border-gray-300 rounded-xl space-y-1">
              <span className="text-[#a8a29e] print:text-gray-600 block text-[11px] font-semibold">
                Accounts in Matching Findings/Events:
              </span>
              <ul className="list-disc pl-4 space-y-0.5 text-[#fafaf9] print:text-black">
                {users.filter((u: string) => u !== 'None identified' && u !== 'Analysis not run / no normalized events').length > 0 ? (
                  users.filter((u: string) => u !== 'None identified' && u !== 'Analysis not run / no normalized events').map(u => <li key={u}>{u}</li>)
                ) : (
                  <li className="text-[#78716c] list-none">{emptySectionMsg}</li>
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
                ) : advIps.filter((ip: string) => ip !== 'None identified' && ip !== 'Analysis not run / no normalized events').length ? (
                  advIps.filter((ip: string) => ip !== 'None identified' && ip !== 'Analysis not run / no normalized events').map((ip: string) => <li key={ip}>{ip}</li>)
                ) : (
                  <li className="text-[#78716c] list-none">{analysisNotRun ? emptySectionMsg : 'None detected'}</li>
                )}
              </ul>
              <span className="text-[#a8a29e] print:text-gray-600 block text-[11px] font-semibold pt-2">Other Observed Addresses:</span>
              <ul className="list-disc pl-4 space-y-0.5 text-[#d6d3d1] print:text-gray-700">
                {(entityGroups?.other_observed_addresses || observedIps.filter((ip: string) => !advIps.includes(ip))).filter((ip: string) => ip !== 'None identified' && ip !== 'Analysis not run / no normalized events').length ? (entityGroups?.other_observed_addresses || observedIps.filter((ip: string) => !advIps.includes(ip))).filter((ip: string) => ip !== 'None identified' && ip !== 'Analysis not run / no normalized events').map((ip: string) => <li key={ip}>{ip}</li>) : <li className="list-none text-[#78716c]">{emptySectionMsg}</li>}
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
        <section className="space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1">
            6. Indicators
          </h2>
          {(rd?.indicators || []).length ? (
            <div className="overflow-x-auto w-full">
              <table className="w-full text-left text-xs border border-[#282321] print:border-gray-400 font-mono min-w-[500px]">
                <thead><tr className="bg-[#100f0e] print:bg-gray-100 text-[#a8a29e] print:text-gray-800"><th className="p-2">Type</th><th className="p-2">Indicator</th><th className="p-2">Role</th><th className="p-2">Source finding</th></tr></thead>
                <tbody className="divide-y divide-[#282321] print:divide-gray-300">
                  {rd!.indicators!.map((indicator, index) => <tr key={`${indicator.type}-${indicator.value}-${index}`}><td className="p-2">{indicator.type}</td><td className="p-2 font-mono break-all">{indicator.value}</td><td className="p-2">{indicator.role || 'Observed'}</td><td className="p-2">{indicator.source_finding || 'Observed event'}</td></tr>)}
                </tbody>
              </table>
            </div>
          ) : <p className="text-xs text-[#78716c]">{analysisNotRun ? emptySectionMsg : 'No indicators identified.'}</p>}
        </section>

        {/* 7. Remediation Directives */}
        <section className="space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#f95721] print:text-black font-mono border-b border-[#282321] print:border-gray-300 pb-1">
            7. Containment &amp; Remediation Directives
          </h2>
          {rd?.remediation && rd.remediation.length > 0 ? (
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
          ) : <p className="text-xs text-[#78716c]">{analysisNotRun ? emptySectionMsg : 'No remediation directives recorded.'}</p>}
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
                {rd?.generator_name || activeCase?.owner_name || currentUser?.name || '—'}
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
              {rd && isDraft && (
                <div className="text-[#fbbf24] font-bold text-[10px]">STATUS: DRAFT</div>
              )}
            </div>
          </div>
        </section>

      </div>
      )}
    </div>
  );
};
