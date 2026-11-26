import React, { useState, useRef } from 'react';
import { useApp } from '../store';
import { UploadCloud, FileText, CheckCircle2, AlertTriangle, RefreshCw, Hash, FolderOpen } from 'lucide-react';
import { ParserType } from '../types';
import {
  collectFilesFromDataTransfer,
  collectFilesFromFileList,
  FolderWalkResult,
  validateUploadBatch,
} from '../utils/folderUpload';

interface UploadDropzoneProps {
  caseId: string;
  onUploadSuccess?: () => void;
}

type UploadQueueStatus = 'queued' | 'uploading' | 'parsed' | 'unsupported' | 'duplicate' | 'failed';

interface UploadBatchItem {
  key: string;
  name: string;
  relativePath?: string;
  hash: string;
  events: number;
  status: UploadQueueStatus;
  reason?: string;
}

const STATUS_BADGE_CLASS: Record<UploadQueueStatus, string> = {
  queued: 'text-[#a8a29e]',
  uploading: 'text-[#f95721]',
  parsed: 'text-emerald-400',
  duplicate: 'text-amber-400',
  unsupported: 'text-orange-400',
  failed: 'text-red-400',
};

const STATUS_LABEL: Record<UploadQueueStatus, string> = {
  queued: 'Queued',
  uploading: 'Uploading...',
  parsed: 'Parsed',
  duplicate: 'Duplicate, skipped',
  unsupported: 'Unsupported',
  failed: 'Failed',
};

export const UploadDropzone: React.FC<UploadDropzoneProps> = ({ caseId, onUploadSuccess }) => {
  const { uploadEvidence, currentUser, setCurrentPage, setAuthNotice } = useApp();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const batchCounterRef = useRef(0);

  const [isDragging, setIsDragging] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [selectedParser, setSelectedParser] = useState<ParserType | 'auto'>('auto');
  const [recentUploads, setRecentUploads] = useState<UploadBatchItem[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [batchNotice, setBatchNotice] = useState<string | null>(null);

  const requireAuth = (): boolean => {
    if (!currentUser) {
      setAuthNotice('Please sign in to upload digital evidence. If you do not have an account, please register.');
      setCurrentPage('login');
      return false;
    }
    return true;
  };

  const updateBatchItem = (key: string, patch: Partial<UploadBatchItem>) => {
    setRecentUploads((prev) => prev.map((item) => (item.key === key ? { ...item, ...patch } : item)));
  };

  const insertChildrenAfter = (parentKey: string, children: UploadBatchItem[]) => {
    if (children.length === 0) return;
    setRecentUploads((prev) => {
      const idx = prev.findIndex((item) => item.key === parentKey);
      if (idx === -1) return [...children, ...prev];
      const next = [...prev];
      next.splice(idx + 1, 0, ...children);
      return next;
    });
  };

  const processWalkResult = async (walkResult: FolderWalkResult) => {
    if (!requireAuth()) return;

    setErrorMessage(null);
    setBatchNotice(null);

    if (walkResult.files.length === 0) {
      if (walkResult.skippedJunkCount > 0) {
        setErrorMessage(
          `No uploadable evidence files found (skipped ${walkResult.skippedJunkCount} hidden/system file(s)).`
        );
      } else if (walkResult.skippedDirectoryCount > 0) {
        setErrorMessage('Selected folder is empty or contains no uploadable evidence files.');
      }
      return;
    }

    const validation = validateUploadBatch(walkResult.files);
    if (validation.batchError) {
      setErrorMessage(validation.batchError);
      return;
    }

    batchCounterRef.current += 1;
    const batchPrefix = `batch-${batchCounterRef.current}-${Date.now()}`;

    const initialItems: UploadBatchItem[] = [
      ...validation.validFiles.map((entry, idx) => ({
        key: `${batchPrefix}-file-${idx}`,
        name: entry.file.name,
        relativePath: entry.relativePath !== entry.file.name ? entry.relativePath : undefined,
        hash: '-',
        events: 0,
        status: 'queued' as const,
      })),
      ...validation.oversizedFiles.map((entry, idx) => ({
        key: `${batchPrefix}-oversize-${idx}`,
        name: entry.file.name,
        relativePath: entry.relativePath !== entry.file.name ? entry.relativePath : undefined,
        hash: '-',
        events: 0,
        status: 'failed' as const,
        reason: entry.reason,
      })),
    ];

    setRecentUploads((prev) => [...initialItems, ...prev]);

    const skippedNotes: string[] = [];
    if (walkResult.skippedJunkCount > 0) {
      skippedNotes.push(`Skipped ${walkResult.skippedJunkCount} hidden/system file(s)`);
    }
    if (validation.oversizedFiles.length > 0) {
      setErrorMessage(
        validation.oversizedFiles
          .map((f) => `File ${f.file.name}: ${f.reason}`)
          .join('; ')
      );
    }

    if (validation.validFiles.length === 0) {
      if (skippedNotes.length > 0) setBatchNotice(skippedNotes.join(' · '));
      return;
    }

    setIsProcessing(true);

    let batchCaseId = caseId;
    let uploadedOrReusedCount = 0;
    const failureMessages: string[] = validation.oversizedFiles.map(
      (f) => `${f.file.name}: ${f.reason}`
    );
    let duplicateCount = 0;

    for (let i = 0; i < validation.validFiles.length; i += 1) {
      const { file, relativePath } = validation.validFiles[i];
      const itemKey = `${batchPrefix}-file-${i}`;

      updateBatchItem(itemKey, { status: 'uploading', reason: undefined });

      try {
        const parserOverride = selectedParser === 'auto' ? undefined : selectedParser;
        const result = await uploadEvidence(batchCaseId, file, parserOverride);
        if (!batchCaseId && result.case_id) {
          batchCaseId = result.case_id;
        }
        uploadedOrReusedCount += 1;

        const hasZipMembers =
          Array.isArray(result.extracted_results) && result.extracted_results.length > 0;

        if (result.duplicate && !hasZipMembers) {
          duplicateCount += 1;
          updateBatchItem(itemKey, {
            name: result.filename || file.name,
            hash: result.sha256_hash || '-',
            events: result.event_count ?? 0,
            status: 'duplicate',
            reason: 'Already ingested in this case',
          });
          continue;
        }

        if (hasZipMembers) {
          if (result.duplicate) duplicateCount += 1;
          updateBatchItem(itemKey, {
            name: result.filename || file.name,
            hash: result.sha256_hash || '-',
            events: result.event_count ?? 0,
            status: result.duplicate
              ? 'duplicate'
              : result.status === 'Failed'
                ? 'failed'
                : 'parsed',
            reason: result.duplicate
              ? 'Archive already ingested; existing artifacts reused'
              : result.status === 'Failed'
                ? 'Archive extraction failed'
                : undefined,
          });

          const childItems: UploadBatchItem[] = result.extracted_results!.map((member, mIdx) => {
            let memberStatus: UploadQueueStatus = 'parsed';
            let memberReason: string | undefined;

            if (member.status === 'duplicate') {
              memberStatus = 'duplicate';
              memberReason = 'Already ingested in this case';
              duplicateCount += 1;
            } else if (member.status === 'failed') {
              const errText = member.error || 'Failed to parse';
              memberStatus = /unsupported file extension|no suitable parser/i.test(errText)
                ? 'unsupported'
                : 'failed';
              memberReason = errText;
              failureMessages.push(`${member.filename}: ${errText}`);
            } else if (member.evidence?.status === 'Failed') {
              memberStatus = 'failed';
              memberReason = 'Parsing failed';
              failureMessages.push(`${member.filename}: Parsing failed`);
            }

            return {
              key: `${itemKey}-zip-${mIdx}`,
              name: member.filename,
              relativePath: `${relativePath} -> ${member.filename}`,
              hash: member.evidence?.sha256_hash || '-',
              events: member.evidence?.event_count ?? 0,
              status: memberStatus,
              reason: memberReason,
            };
          });

          insertChildrenAfter(itemKey, childItems);
          continue;
        }

        if (result.status === 'Failed') {
          failureMessages.push(`${file.name}: Failed to parse`);
          updateBatchItem(itemKey, {
            name: result.filename || file.name,
            hash: result.sha256_hash || '-',
            events: result.event_count ?? 0,
            status: 'failed',
            reason: 'Parser could not extract events from this artifact',
          });
        } else {
          updateBatchItem(itemKey, {
            name: result.filename || file.name,
            hash: result.sha256_hash || '-',
            events: result.event_count ?? 0,
            status: 'parsed',
            reason: undefined,
          });
        }
      } catch (err: any) {
        const reason = err?.message || 'Upload failed';
        const isUnsupported = /unsupported file extension|no suitable parser/i.test(reason);
        failureMessages.push(`${file.name}: ${reason}`);
        updateBatchItem(itemKey, {
          status: isUnsupported ? 'unsupported' : 'failed',
          reason,
        });
      }
    }

    if (failureMessages.length > 0) {
      setErrorMessage(
        failureMessages.length === 1
          ? `Failed to process ${failureMessages[0]}`
          : `${failureMessages.length} file(s) could not be fully processed: ${failureMessages.slice(0, 3).join('; ')}${failureMessages.length > 3 ? ` (+${failureMessages.length - 3} more)` : ''}`
      );
    }

    if (duplicateCount > 0) {
      skippedNotes.push(`${duplicateCount} duplicate(s) skipped (already ingested)`);
    }
    if (skippedNotes.length > 0) {
      setBatchNotice(skippedNotes.join(' · '));
    }

    setIsProcessing(false);

    if (onUploadSuccess && uploadedOrReusedCount > 0) {
      onUploadSuccess();
    }
  };

  const handleFiles = async (files: FileList | null) => {
    const walkResult = collectFilesFromFileList(files);
    await processWalkResult(walkResult);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (!requireAuth()) return;
    try {
      const walkResult = await collectFilesFromDataTransfer(e.dataTransfer);
      await processWalkResult(walkResult);
    } catch (err: any) {
      setErrorMessage(`Failed to read dropped folder or files: ${err?.message || 'Unknown error'}`);
    }
  };

  return (
    <div className="space-y-4">
      {/* Configuration & Dropzone Card */}
      <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-6 shadow-xl space-y-5">

        {/* Top Controls */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[#2b2523]">
          <div>
            <h3 className="text-sm font-semibold text-[#fafaf9]">Evidence Ingestion & Integrity Validator</h3>
            <p className="text-xs text-[#a8a29e] mt-0.5">
              Supports files, nested folders, and ZIP archives (Linux syslog, Windows EVTX/Sysmon, Web server logs, PCAP, XML, JSON, CSV, TXT).
            </p>
          </div>

          {/* Parser selector */}
          <div className="flex items-center gap-2 text-xs">
            <span className="text-[#78716c] font-mono text-[11px]">Parser Target:</span>
            <select
              value={selectedParser}
              onChange={(e) => setSelectedParser(e.target.value as any)}
              className="bg-[#100f0e] border border-[#2e2926] rounded-lg px-2.5 py-1 text-[#d6d3d1] text-xs focus:outline-none focus:border-[#f95721] font-mono"
            >
              <option value="auto">Auto-Detect by Format & MIME</option>
              <option value="web_server">Nginx / Apache Web Server Log</option>
              <option value="linux_auth">Linux Auth / Syslog</option>
              <option value="windows_evtx">Windows Event Logs (EVTX/JSON)</option>
              <option value="pcap_summary">PCAP Network Capture / Summary</option>
              <option value="generic_json_csv">Generic Forensic CSV / JSON / TXT</option>
            </select>
          </div>
        </div>

        {/* Clean Full-Width Drag and Drop Area */}
        <div
          onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          onClick={() => {
            if (isProcessing || !requireAuth()) return;
            fileInputRef.current?.click();
          }}
          className={`w-full relative border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all flex flex-col items-center justify-center min-h-[180px] ${isDragging
              ? 'border-[#f95721] bg-[#2a140d]/40 shadow-[0_0_15px_rgba(249,87,33,0.3)]'
              : 'border-[#332c28] hover:border-[#f95721]/60 bg-[#110f0e]/80 hover:bg-[#141210]'
            }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            multiple
            className="hidden"
            accept=".log,.txt,.evtx,.pcap,.pcapng,.csv,.json,.pdf,.xml,.zip"
            onChange={(e) => {
              void handleFiles(e.target.files);
              e.target.value = '';
            }}
          />
          <input
            ref={folderInputRef}
            type="file"
            multiple
            className="hidden"
            {...({ webkitdirectory: '', directory: '' } as Record<string, string>)}
            onChange={(e) => {
              void handleFiles(e.target.files);
              e.target.value = '';
            }}
          />

          <div className="flex flex-col items-center justify-center space-y-3">
            <div className="w-12 h-12 rounded-xl bg-[#221712] border border-[#ea580c]/40 flex items-center justify-center text-[#f95721] shadow-inner">
              {isProcessing ? (
                <RefreshCw className="w-6 h-6 animate-spin text-[#f95721]" />
              ) : (
                <UploadCloud className="w-6 h-6" />
              )}
            </div>

            <div className="space-y-2">
              <p className="text-sm font-medium text-[#fafaf9]">
                {isProcessing ? 'Streaming cryptographic SHA-256 hash & parsing forensic artifacts one by one...' : (
                  <span>
                    Drag & drop forensic files or a folder here, or{' '}
                    <span className="text-[#f95721] underline underline-offset-2 font-semibold">Browse Files</span>
                  </span>
                )}
              </p>

              {!isProcessing && (
                <div className="flex items-center justify-center">
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      if (!requireAuth()) return;
                      folderInputRef.current?.click();
                    }}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#1d1816] hover:bg-[#2a211d] border border-[#3a312c] hover:border-[#f95721]/60 text-xs font-medium text-[#fafaf9] cursor-pointer transition-colors"
                  >
                    <FolderOpen className="w-3.5 h-3.5 text-[#f95721]" />
                    <span>Browse Folder</span>
                  </button>
                </div>
              )}

              <p className="text-[11px] text-[#78716c] mt-1 font-mono">
                Supported formats: PCAP, EVTX, LOG, TXT, CSV, JSON, XML, PDF, ZIP or Folders (Max 100 files, 100 MB/file, 250 MB total)
              </p>
            </div>

            <div className="inline-flex items-center gap-1.5 text-[10px] text-[#a8a29e] font-mono pt-1">
              <Hash className="w-3 h-3 text-[#f95721]" />
              <span>Cryptographic SHA-256 integrity verification · Automated Chain of Custody</span>
            </div>
          </div>
        </div>

        {/* Info / Duplicate / Skipped Notification */}
        {batchNotice && (
          <div className="p-3 bg-amber-950/35 border border-amber-700/60 rounded-lg flex items-center gap-2 text-xs text-amber-200">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>{batchNotice}</span>
          </div>
        )}

        {/* Error Notification */}
        {errorMessage && (
          <div className="p-3 bg-red-950/50 border border-red-800/80 rounded-lg flex items-center gap-2 text-xs text-red-300">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

      </div>

      {/* Recent Uploads & Per-File Progress Table */}
      {recentUploads.length > 0 && (
        <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-4 shadow-xl">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2.5">
            <h4 className="text-xs font-semibold text-[#fafaf9] uppercase font-mono flex items-center gap-2">
              {isProcessing ? (
                <RefreshCw className="w-3.5 h-3.5 text-[#f95721] animate-spin" />
              ) : (
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              )}
              <span>{isProcessing ? 'Ingestion Progress (Sequential)' : 'Recent Upload Ingestion Batch'}</span>
            </h4>
            <span className="text-[11px] font-mono text-[#a8a29e] tabular-nums">
              {recentUploads.filter((u) => u.status === 'parsed' || u.status === 'duplicate').length} / {recentUploads.length} completed
            </span>
          </div>
          <div className="space-y-2 max-h-[340px] overflow-y-auto pr-1">
            {recentUploads.map((up) => (
              <div
                key={up.key}
                className="flex flex-wrap items-center justify-between gap-2 p-2.5 bg-[#100f0e] border border-[#282321] rounded-xl text-xs"
              >
                <div className="flex flex-col gap-0.5 min-w-0">
                  <div className="flex items-center gap-2">
                    <FileText className="w-3.5 h-3.5 text-[#f95721] shrink-0" />
                    <span className="font-medium text-[#e7e5e4] truncate">{up.name}</span>
                  </div>
                  {(up.relativePath || up.reason) && (
                    <div className="pl-5.5 text-[11px] text-[#a8a29e] truncate">
                      {up.relativePath && <span>{up.relativePath}</span>}
                      {up.relativePath && up.reason && <span> · </span>}
                      {up.reason && (
                        <span className={up.status === 'failed' || up.status === 'unsupported' ? 'text-red-300' : 'text-amber-300/90'}>
                          {up.reason}
                        </span>
                      )}
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-4 text-[#a8a29e] font-mono text-[11px] shrink-0">
                  <span>
                    SHA-256:{' '}
                    <strong className="text-[#fafaf9] font-normal">
                      {up.hash && up.hash !== '-' ? `${up.hash.slice(0, 16)}...` : '-'}
                    </strong>
                  </span>
                  <span>
                    Extracted: <strong className="text-[#f95721]">{up.events} events</strong>
                  </span>
                  <span className={`${STATUS_BADGE_CLASS[up.status]} font-semibold`}>
                    {STATUS_LABEL[up.status]}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
