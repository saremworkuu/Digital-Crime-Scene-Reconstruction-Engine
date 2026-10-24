import React, { useState, useEffect } from 'react';
import {
  FileCheck2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Lock,
  Trash2,
  Shield,
  Copy,
  Check,
  FileCode,
  Loader2
} from 'lucide-react';
import { DataTable, Column } from '../components/DataTable';
import { FilterBar } from '../components/FilterBar';
import { StatusBadge } from '../components/StatusBadge';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { evidenceService, casesService } from '../../services/admin';
import { AdminEvidence, AdminCase } from '../types';
import { toast } from '../../components/Toast';
import { useApp } from '../../store';

export const EvidencePage: React.FC = () => {
  const { theme } = useApp();
  const isLight = theme === 'light';

  const [evidenceList, setEvidenceList] = useState<AdminEvidence[]>([]);
  const [casesMap, setCasesMap] = useState<Record<string, AdminCase>>({});
  const [isLoading, setIsLoading] = useState(true);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

  // Selected Evidence for Error Details Modal
  const [selectedError, setSelectedError] = useState<AdminEvidence | null>(null);

  // Confirm Dialog
  const [confirmDialog, setConfirmDialog] = useState<{
    isOpen: boolean;
    title: string;
    message: string;
    action: () => Promise<void>;
  }>({
    isOpen: false,
    title: '',
    message: '',
    action: async () => {}
  });

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [items, cases] = await Promise.all([
        evidenceService.getEvidence({ search, type: typeFilter, status: statusFilter }),
        casesService.getCases()
      ]);
      setEvidenceList(items);

      const map: Record<string, AdminCase> = {};
      cases.forEach((c) => {
        map[c.id] = c;
      });
      setCasesMap(map);
    } catch (err: any) {
      toast.error('Failed to load evidence files: ' + err.message);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [search, typeFilter, statusFilter]);

  const handleVerify = async (item: AdminEvidence) => {
    setVerifyingId(item.id);
    try {
      const res = await evidenceService.verifyIntegrity(item.id);
      if (res.match) {
        toast.success(`Integrity MATCH for ${item.file_name}. SHA-256 seal is intact.`);
      } else {
        toast.error(`Integrity MISMATCH for ${item.file_name}! Hash tampering flagged.`);
      }
      loadData();
    } catch (err: any) {
      toast.error('Verification failed: ' + err.message);
    } finally {
      setVerifyingId(null);
    }
  };

  const handleDelete = (item: AdminEvidence) => {
    const parentCase = casesMap[item.case_id];
    if (parentCase?.legal_hold) {
      toast.error(`Deletion Prohibited: Case "${parentCase.title}" is under Legal Hold.`);
      return;
    }

    setConfirmDialog({
      isOpen: true,
      title: `Purge Evidence: ${item.file_name}`,
      message: `Permanently delete ${item.file_name}? This action removes raw forensic chunks and will be written to the immutable audit log.`,
      action: async () => {
        try {
          await evidenceService.deleteEvidence(item.id);
          toast.success(`Evidence ${item.file_name} purged.`);
          loadData();
        } catch (err: any) {
          toast.error(err.message || 'Deletion failed');
        }
      }
    });
  };

  const handleCopy = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
    toast.success('SHA-256 hash copied to clipboard');
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const columns: Column<AdminEvidence>[] = [
    {
      key: 'file_name',
      header: 'Evidence File & Case',
      render: (e) => {
        const parentCase = casesMap[e.case_id];
        return (
          <div className="space-y-0.5">
            <div className={`font-bold font-sans text-xs sm:text-sm flex items-center gap-1.5 ${isLight ? 'text-slate-900' : 'text-white'}`}>
              <span>{e.file_name}</span>
              {parentCase?.legal_hold && (
                <span title="Protected under Legal Hold" className="text-red-500">
                  <Lock className="w-3 h-3" />
                </span>
              )}
            </div>
            <div className={`text-[10px] font-mono ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
              Case: {parentCase?.title || e.case_id}
            </div>
          </div>
        );
      }
    },
    {
      key: 'type',
      header: 'Format',
      render: (e) => (
        <span
          className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold border ${
            isLight
              ? 'bg-orange-50 border-orange-200 text-[#f95721]'
              : 'bg-black/50 border-[#2e2623] text-[#ff936b]'
          }`}
        >
          {e.type}
        </span>
      )
    },
    {
      key: 'size_bytes',
      header: 'Size',
      render: (e) => (
        <span className={`text-xs font-mono ${isLight ? 'text-slate-600' : 'text-stone-300'}`}>
          {formatBytes(e.size_bytes)}
        </span>
      )
    },
    {
      key: 'uploader',
      header: 'Examiner & Ingest Time',
      render: (e) => (
        <div className="space-y-0.5 text-xs font-mono">
          <span className={`block font-semibold ${isLight ? 'text-slate-900' : 'text-white'}`}>{e.uploader}</span>
          <span className={`text-[10px] ${isLight ? 'text-slate-400' : 'text-stone-500'}`}>
            {new Date(e.uploaded_at).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}
          </span>
        </div>
      )
    },
    {
      key: 'sha256',
      header: 'SHA-256 Hash Seal',
      render: (e) => {
        const isCopied = copiedHash === e.sha256;
        return (
          <div className="flex items-center gap-1.5">
            <code
              className={`text-[10px] font-mono px-2 py-1 rounded border truncate max-w-[140px] select-all ${
                isLight
                  ? 'text-slate-700 bg-slate-100 border-slate-200'
                  : 'text-stone-300 bg-black/60 border-[#2b2523]'
              }`}
            >
              {e.sha256.slice(0, 10)}...{e.sha256.slice(-6)}
            </code>
            <button
              type="button"
              onClick={() => handleCopy(e.sha256)}
              className={`p-1 rounded cursor-pointer ${
                isLight ? 'text-slate-400 hover:text-slate-700' : 'text-stone-400 hover:text-white'
              }`}
              title="Copy Full SHA-256 Hash"
            >
              {isCopied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        );
      }
    },
    {
      key: 'parsing_status',
      header: 'Parsing Status',
      render: (e) => (
        <div className="flex items-center gap-2">
          <StatusBadge status={e.parsing_status} />
          {e.parsing_status === 'failed' && (
            <button
              type="button"
              onClick={() => setSelectedError(e)}
              className="text-[10px] font-mono text-red-500 hover:underline cursor-pointer flex items-center gap-1"
            >
              <AlertTriangle className="w-3 h-3" />
              <span>Details</span>
            </button>
          )}
        </div>
      )
    },
    {
      key: 'actions',
      header: 'Verification & Integrity',
      className: 'text-right',
      render: (e) => {
        const parentCase = casesMap[e.case_id];
        const isUnderHold = parentCase?.legal_hold;
        const isVerifying = verifyingId === e.id;

        return (
          <div className="flex items-center justify-end gap-2">
            <button
              type="button"
              disabled={isVerifying}
              onClick={() => handleVerify(e)}
              className={`px-2.5 py-1.5 rounded-lg text-xs font-mono transition-all flex items-center gap-1.5 cursor-pointer border ${
                e.verified === true
                  ? isLight
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-700 hover:bg-emerald-100'
                    : 'bg-emerald-950/70 border-emerald-600/60 text-emerald-300 hover:bg-emerald-900/60'
                  : e.verified === false
                  ? isLight
                    ? 'bg-rose-50 border-rose-200 text-rose-700 hover:bg-rose-100'
                    : 'bg-red-950/70 border-red-700/60 text-red-300 hover:bg-red-900/60'
                  : isLight
                  ? 'bg-slate-100 border-slate-300 text-slate-700 hover:bg-slate-200'
                  : 'bg-stone-900 border-stone-700 text-stone-300 hover:text-white hover:border-[#f95721]'
              }`}
              title="Verify Cryptographic Hash Match"
            >
              {isVerifying ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : e.verified === true ? (
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
              ) : e.verified === false ? (
                <XCircle className="w-3.5 h-3.5 text-red-500" />
              ) : (
                <Shield className="w-3.5 h-3.5 text-[#f95721]" />
              )}
              <span>{isVerifying ? 'Checking...' : e.verified === true ? 'Verified' : 'Verify'}</span>
            </button>

            <button
              type="button"
              disabled={isUnderHold}
              onClick={() => handleDelete(e)}
              className={`p-1.5 rounded-lg border transition-colors ${
                isUnderHold
                  ? isLight
                    ? 'opacity-30 border-slate-200 text-slate-400 cursor-not-allowed'
                    : 'opacity-30 border-stone-800 text-stone-600 cursor-not-allowed'
                  : isLight
                  ? 'bg-slate-100 hover:bg-rose-50 text-slate-600 hover:text-rose-700 border-slate-200 hover:border-rose-200 cursor-pointer'
                  : 'bg-stone-900 hover:bg-red-950/50 text-stone-400 hover:text-red-400 border-stone-700 hover:border-red-600/50 cursor-pointer'
              }`}
              title={isUnderHold ? 'Deletion Blocked: Case under Legal Hold' : 'Purge Evidence File'}
            >
              {isUnderHold ? <Lock className="w-3.5 h-3.5 text-stone-400" /> : <Trash2 className="w-3.5 h-3.5" />}
            </button>
          </div>
        );
      }
    }
  ];

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div
        className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b ${
          isLight ? 'border-slate-200' : 'border-[#282321]'
        }`}
      >
        <div>
          <h1
            className={`text-xl sm:text-2xl font-black tracking-tight font-sans flex items-center gap-2.5 ${
              isLight ? 'text-slate-900' : 'text-white'
            }`}
          >
            <FileCheck2 className="w-6 h-6 text-[#f95721]" />
            <span>Forensic Evidence & Hash Verification</span>
          </h1>
          <p className={`text-xs sm:text-sm font-sans mt-0.5 ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
            SHA-256 non-repudiation verification and legal hold deletion locking. Evidence editing is strictly disallowed.
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <FilterBar
        searchQuery={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search evidence files by filename, examiner, or hash prefix..."
        filters={[
          {
            key: 'type',
            label: 'Format',
            value: typeFilter,
            options: [
              { label: 'All Formats', value: 'all' },
              { label: 'EVTX', value: 'EVTX' },
              { label: 'PCAP', value: 'PCAP' },
              { label: 'LOG', value: 'LOG' },
              { label: 'CSV', value: 'CSV' },
              { label: 'JSON', value: 'JSON' },
              { label: 'XML', value: 'XML' },
              { label: 'PDF', value: 'PDF' },
              { label: 'TXT', value: 'TXT' }
            ],
            onChange: setTypeFilter
          },
          {
            key: 'status',
            label: 'Status',
            value: statusFilter,
            options: [
              { label: 'All Statuses', value: 'all' },
              { label: 'Completed', value: 'completed' },
              { label: 'Failed', value: 'failed' },
              { label: 'Processing', value: 'processing' }
            ],
            onChange: setStatusFilter
          }
        ]}
        onResetFilters={() => {
          setSearch('');
          setTypeFilter('all');
          setStatusFilter('all');
        }}
      />

      {/* Main Evidence Table */}
      <DataTable
        columns={columns}
        data={evidenceList}
        keyExtractor={(e) => e.id}
        isLoading={isLoading}
        emptyTitle="No evidence files matched"
        emptyMessage="Try adjusting filter options to inspect forensic files."
      />

      {/* Error Details Modal */}
      {selectedError && (
        <div
          className={`fixed inset-0 z-50 flex items-center justify-center p-4 backdrop-blur-sm animate-fadeIn ${
            isLight ? 'bg-slate-900/40' : 'bg-black/80'
          }`}
        >
          <div
            className={`w-full max-w-md rounded-2xl border p-6 shadow-2xl space-y-4 ${
              isLight ? 'bg-white border-red-200 text-slate-800' : 'bg-[#141211] border-red-900/60 text-white'
            }`}
          >
            <div className={`flex items-center justify-between pb-3 border-b ${isLight ? 'border-slate-100' : 'border-[#26201e]'}`}>
              <div className="flex items-center gap-2 text-red-500 font-bold font-sans">
                <AlertTriangle className="w-5 h-5 text-red-500" />
                <span>Parser Failure Diagnostics</span>
              </div>
              <button
                type="button"
                onClick={() => setSelectedError(null)}
                className={`text-xs font-mono cursor-pointer ${
                  isLight ? 'text-slate-400 hover:text-slate-700' : 'text-stone-400 hover:text-white'
                }`}
              >
                Close
              </button>
            </div>

            <div className="space-y-1">
              <span className={`text-xs font-mono ${isLight ? 'text-slate-600' : 'text-stone-400'}`}>
                File: {selectedError.file_name}
              </span>
              <p
                className={`p-3 rounded-xl border font-mono text-xs leading-relaxed ${
                  isLight
                    ? 'bg-red-50 border-red-200 text-red-700'
                    : 'bg-black/60 border-red-800/40 text-red-300'
                }`}
              >
                {selectedError.error_text || 'Unknown parser crash during chunk decompression.'}
              </p>
            </div>

            <p className={`text-[11px] font-sans ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
              Resolution: Trigger raw hex repair via the Ingestion Queue in System Health.
            </p>

            <div className="pt-2 text-right">
              <button
                type="button"
                onClick={() => setSelectedError(null)}
                className={`px-4 py-2 rounded-xl text-xs font-semibold border cursor-pointer ${
                  isLight
                    ? 'text-slate-700 bg-slate-100 hover:bg-slate-200 border-slate-300'
                    : 'text-stone-300 bg-stone-900 hover:bg-stone-800 border-stone-700'
                }`}
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirm Dialog */}
      <ConfirmDialog
        isOpen={confirmDialog.isOpen}
        title={confirmDialog.title}
        message={confirmDialog.message}
        onConfirm={async () => {
          await confirmDialog.action();
          setConfirmDialog((prev) => ({ ...prev, isOpen: false }));
        }}
        onCancel={() => setConfirmDialog((prev) => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
};
