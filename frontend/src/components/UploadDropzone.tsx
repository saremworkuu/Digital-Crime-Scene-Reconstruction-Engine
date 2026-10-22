import React, { useState, useRef } from 'react';
import { useApp } from '../store';
import { UploadCloud, FileText, CheckCircle2, AlertTriangle, RefreshCw, Hash } from 'lucide-react';
import { ParserType } from '../types';

interface UploadDropzoneProps {
  caseId: string;
  onUploadSuccess?: () => void;
}

export const UploadDropzone: React.FC<UploadDropzoneProps> = ({ caseId, onUploadSuccess }) => {
  const { uploadEvidence, currentUser, setCurrentPage, setAuthNotice } = useApp();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [isDragging, setIsDragging] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [selectedParser, setSelectedParser] = useState<ParserType | 'auto'>('auto');
  const [recentUploads, setRecentUploads] = useState<{ name: string; hash: string; events: number; status: string }[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleFiles = async (files: FileList | null) => {
    if (!currentUser) {
      setAuthNotice('Please sign in to upload digital evidence. If you do not have an account, please register.');
      setCurrentPage('login');
      return;
    }

    if (!files || files.length === 0) return;

    setIsProcessing(true);
    setErrorMessage(null);

    const uploadsSummary: { name: string; hash: string; events: number; status: string }[] = [];

    for (let i = 0; i < files.length; i++) {
      const file = files[i];

      // Check max size (100 MB per FR-EVID-4)
      if (file.size > 100 * 1024 * 1024) {
        setErrorMessage(`File ${file.name} exceeds maximum allowed size of 100 MB.`);
        continue;
      }

      try {
        const parserOverride = selectedParser === 'auto' ? undefined : selectedParser;
        const result = await uploadEvidence(caseId, file, parserOverride);
        uploadsSummary.push({
          name: result.filename,
          hash: result.sha256_hash,
          events: result.event_count,
          status: result.status
        });
      } catch (err: any) {
        setErrorMessage(`Failed to process ${file.name}: ${err.message}`);
      }
    }

    setRecentUploads(prev => [...uploadsSummary, ...prev]);
    setIsProcessing(false);

    if (onUploadSuccess && uploadsSummary.length > 0) {
      onUploadSuccess();
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    handleFiles(e.dataTransfer.files);
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
              Supports Linux syslog, Windows EVTX/Sysmon, Web server logs, PCAP network captures, XML, JSON, CSV & TXT manifests.
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
            if (!currentUser) {
              setAuthNotice('Please sign in to upload digital evidence. If you do not have an account, please register.');
              setCurrentPage('login');
              return;
            }
            fileInputRef.current?.click();
          }}
          className={`w-full relative border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all flex flex-col items-center justify-center min-h-[180px] ${
            isDragging
              ? 'border-[#f95721] bg-[#2a140d]/40 shadow-[0_0_15px_rgba(249,87,33,0.3)]'
              : 'border-[#332c28] hover:border-[#f95721]/60 bg-[#110f0e]/80 hover:bg-[#141210]'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            multiple
            className="hidden"
            accept=".log,.txt,.evtx,.pcap,.pcapng,.csv,.json,.pdf,.xml"
            onChange={(e) => handleFiles(e.target.files)}
          />

          <div className="flex flex-col items-center justify-center space-y-3">
            <div className="w-12 h-12 rounded-xl bg-[#221712] border border-[#ea580c]/40 flex items-center justify-center text-[#f95721] shadow-inner">
              {isProcessing ? (
                <RefreshCw className="w-6 h-6 animate-spin text-[#f95721]" />
              ) : (
                <UploadCloud className="w-6 h-6" />
              )}
            </div>

            <div>
              <p className="text-sm font-medium text-[#fafaf9]">
                {isProcessing ? 'Streaming cryptographic SHA-256 hash & parsing forensic artifacts...' : (
                  <span>Drag & drop forensic files here or <span className="text-[#f95721] underline underline-offset-2 font-semibold">Browse Files</span></span>
                )}
              </p>
              <p className="text-[11px] text-[#78716c] mt-1 font-mono">
                Supported formats: PCAP, EVTX, LOG, TXT, CSV, JSON, XML, PDF (Max 100 MB per file)
              </p>
            </div>

            <div className="inline-flex items-center gap-1.5 text-[10px] text-[#a8a29e] font-mono pt-1">
              <Hash className="w-3 h-3 text-[#f95721]" />
              <span>Cryptographic SHA-256 integrity verification · Automated Chain of Custody</span>
            </div>
          </div>
        </div>

        {/* Error Notification */}
        {errorMessage && (
          <div className="p-3 bg-red-950/50 border border-red-800/80 rounded-lg flex items-center gap-2 text-xs text-red-300">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

      </div>

      {/* Recent Uploads Table */}
      {recentUploads.length > 0 && (
        <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-4 shadow-xl">
          <h4 className="text-xs font-semibold text-[#fafaf9] uppercase font-mono mb-2.5 flex items-center gap-2">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            Recent Upload Ingestion Batch
          </h4>
          <div className="space-y-2">
            {recentUploads.map((up, i) => (
              <div
                key={i}
                className="flex flex-wrap items-center justify-between gap-2 p-2.5 bg-[#100f0e] border border-[#282321] rounded-xl text-xs"
              >
                <div className="flex items-center gap-2">
                  <FileText className="w-3.5 h-3.5 text-[#f95721]" />
                  <span className="font-medium text-[#e7e5e4]">{up.name}</span>
                </div>
                <div className="flex items-center gap-4 text-[#a8a29e] font-mono text-[11px]">
                  <span>SHA-256: <strong className="text-[#fafaf9] font-normal">{up.hash.slice(0, 16)}...</strong></span>
                  <span>Extracted: <strong className="text-[#f95721]">{up.events} events</strong></span>
                  <span className={up.status === 'Parsed' ? 'text-emerald-400 font-semibold' : 'text-red-400 font-semibold'}>
                    {up.status}
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
