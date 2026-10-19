import React, { useState, useRef } from 'react';
import { useApp } from '../store';
import {
  UploadCloud,
  Lock,
  CheckCircle2,
  UserPlus,
  ChevronRight,
  FolderLock,
  ArrowRight,
  RefreshCw,
  AlertCircle,
  Copy,
  Check,
  FileCheck2
} from 'lucide-react';
import { ThreatHeroGlobe } from '../components/ThreatHeroGlobe';

export const Home: React.FC = () => {
  const {
    currentUser,
    setCurrentPage,
    cases,
    activeCaseId,
    evidenceList,
    events,
    detections,
    setAuthNotice,
    uploadEvidence
  } = useApp();

  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState(false);
  const [uploadSuccess, setUploadSuccess] = useState<{
    filename: string;
    hash: string;
    eventCount: number;
    caseName: string;
  } | null>(null);

  // Directly open the user's file chooser ("where my files are kept")
  const handleUploadClick = () => {
    if (!currentUser) {
      setAuthNotice('Please sign in to upload digital evidence into the active forensic ledger.');
      setCurrentPage('login');
      return;
    }
    fileInputRef.current?.click();
  };

  const processFiles = async (files: FileList | null) => {
    if (!files || files.length === 0) return;

    if (!currentUser) {
      setAuthNotice('Please sign in to securely ingest digital evidence into the active case ledger.');
      setCurrentPage('login');
      return;
    }

    const targetCase = cases.find(c => c.id === activeCaseId) || cases[0];
    const targetCaseId = targetCase?.id || 'case-001';

    setIsProcessing(true);
    setUploadError(null);

    try {
      let lastUploaded: any = null;
      let totalEvents = 0;

      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        if (file.size > 100 * 1024 * 1024) {
          throw new Error(`File "${file.name}" exceeds 100 MB limit.`);
        }
        const result = await uploadEvidence(targetCaseId, file);
        lastUploaded = result;
        totalEvents += result.event_count;
      }

      if (lastUploaded) {
        setUploadSuccess({
          filename: files.length === 1 ? lastUploaded.filename : `${files.length} evidence files`,
          hash: lastUploaded.sha256_hash,
          eventCount: totalEvents,
          caseName: targetCase?.name || 'Active Investigation'
        });
      }
    } catch (err: any) {
      setUploadError(err.message || 'Failed to process evidence file.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      processFiles(e.target.files);
    }
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files) {
      processFiles(e.dataTransfer.files);
    }
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const handleRegisterClick = () => {
    setAuthNotice('Create an account to securely upload and ingest digital evidence.');
    setCurrentPage('register');
  };

  return (
    <div className="space-y-12 pb-16">
      {/* ========================================================================= */}
      {/* MOTIONAL HERO HEADLINE (Below Navbar, Above 3D Threat Mesh Sphere)        */}
      {/* ========================================================================= */}
      <div className="pt-2 sm:pt-3 text-center max-w-2xl mx-auto animate-motion-title">
        <div className="animate-kinetic-container">
          <h1 className="text-base sm:text-lg md:text-xl font-bold tracking-tight text-[#fafaf9] leading-snug flex flex-wrap items-center justify-center gap-x-1.5 gap-y-1">
            <span className="animate-kinetic-word" style={{ animationDelay: '0s' }}>Reconstruct</span>
            <span className="animate-kinetic-word" style={{ animationDelay: '0.14s' }}>Digital</span>
            <span className="animate-kinetic-word" style={{ animationDelay: '0.28s' }}>Crime</span>
            <span className="animate-kinetic-word" style={{ animationDelay: '0.42s' }}>Scenes</span>
            <span className="animate-kinetic-word text-[#a8a29e]" style={{ animationDelay: '0.56s' }}>with</span>
            <span
              className="animate-kinetic-word text-transparent bg-clip-text bg-gradient-to-r from-[#f95721] via-[#fb923c] to-[#ffb28d] animate-text-shimmer animate-cyber-glow"
              style={{ animationDelay: '0.70s' }}
            >
              Cryptographic
            </span>
            <span
              className="animate-kinetic-word text-transparent bg-clip-text bg-gradient-to-r from-[#f95721] via-[#fb923c] to-[#ffb28d] animate-text-shimmer animate-cyber-glow"
              style={{ animationDelay: '0.84s' }}
            >
              Precision
            </span>
          </h1>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 3D THREAT MESH SPHERE (Interactive Geodesic 3D Design under Headline)      */}
      {/* ========================================================================= */}
      <ThreatHeroGlobe />

      {/* ========================================================================= */}
      {/* DIRECT EVIDENCE INGESTION DROPZONE (Prominently featured per user request) */}
      {/* ========================================================================= */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-xl font-bold tracking-tight text-[#fafaf9]">
            Evidence Dropzone
          </h2>
          <div className="text-xs text-[#a8a29e] flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#f95721]" />
            <span>.log · .evtx · .pcap · .json · .csv · .txt</span>
          </div>
        </div>

        {/* Dropzone Area */}
        <div
          onClick={handleUploadClick}
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          className={`relative rounded-2xl border-2 border-dashed p-8 sm:p-12 text-center transition-all cursor-pointer group ${
            isDragging
              ? 'border-[#f95721] bg-[#27130b]/80 shadow-[0_0_24px_rgba(249,87,33,0.3)]'
              : 'border-[#382f2c] hover:border-[#f95721]/80 bg-[#141211]/80 hover:bg-[#1a1715]'
          }`}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            className="hidden"
            multiple
          />

          {isProcessing ? (
            <div className="max-w-md mx-auto space-y-4 py-4 animate-fadeIn">
              <div className="w-16 h-16 mx-auto rounded-2xl bg-[#26130b] border border-[#ea580c]/50 flex items-center justify-center text-[#f95721] shadow-lg">
                <RefreshCw className="w-8 h-8 animate-spin" />
              </div>
              <div className="space-y-1">
                <h3 className="text-base font-bold text-[#fafaf9]">
                  Ingesting & Computing Cryptographic Hashes...
                </h3>
                <p className="text-xs text-[#a8a29e] font-mono">
                  Calculating SHA-256 and parsing evidentiary artifacts into custody ledger
                </p>
              </div>
            </div>
          ) : uploadSuccess ? (
            <div className="max-w-lg mx-auto space-y-4 py-2 animate-fadeIn" onClick={(e) => e.stopPropagation()}>
              <div className="w-16 h-16 mx-auto rounded-2xl bg-emerald-950/60 border border-emerald-500/50 flex items-center justify-center text-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.2)]">
                <CheckCircle2 className="w-9 h-9" />
              </div>

              <div className="space-y-1">
                <h3 className="text-base font-bold text-[#fafaf9] flex items-center justify-center gap-2">
                  <span>Evidence Ingested Successfully</span>
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700/50">
                    VERIFIED
                  </span>
                </h3>
                <p className="text-xs text-[#a8a29e]">
                  {uploadSuccess.filename} has been securely committed to {uploadSuccess.caseName}.
                </p>
              </div>

              <div className="bg-[#0e0d0d] border border-[#2b2523] rounded-xl p-3 text-left space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between text-[#78716c]">
                  <span>SHA-256 HASH:</span>
                  <button
                    type="button"
                    onClick={() => handleCopyHash(uploadSuccess.hash)}
                    className="text-[#f95721] hover:underline flex items-center gap-1 cursor-pointer"
                  >
                    {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedHash ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <div className="text-[11px] text-[#fafaf9] break-all select-all font-mono">
                  {uploadSuccess.hash}
                </div>
                <div className="flex items-center justify-between pt-1 border-t border-[#221e1c] text-[#a8a29e] text-[11px]">
                  <span>Extracted Events:</span>
                  <span className="text-[#fb923c] font-bold">{uploadSuccess.eventCount} normalized</span>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
                <button
                  type="button"
                  onClick={handleUploadClick}
                  className="px-4 py-2 bg-[#f95721] hover:bg-[#ea580c] text-white font-semibold rounded-lg text-xs flex items-center gap-1.5 transition-colors shadow-sm cursor-pointer"
                >
                  <UploadCloud className="w-3.5 h-3.5" />
                  <span>Select Another File</span>
                </button>

                <button
                  type="button"
                  onClick={() => setCurrentPage('evidence')}
                  className="px-4 py-2 bg-[#1c1816] hover:bg-[#25201d] text-[#fafaf9] border border-[#382f2c] font-semibold rounded-lg text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <FileCheck2 className="w-3.5 h-3.5 text-[#f95721]" />
                  <span>View in Evidence Ledger</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="max-w-md mx-auto space-y-4">
              <div className="w-16 h-16 mx-auto rounded-2xl bg-[#26130b] border border-[#ea580c]/50 flex items-center justify-center text-[#f95721] group-hover:scale-110 transition-transform shadow-lg">
                <UploadCloud className="w-8 h-8" />
              </div>

              <div className="space-y-1">
                <h3 className="text-base font-bold text-[#fafaf9] group-hover:text-[#f95721] transition-colors">
                  Drop Forensic Evidence Here or Browse Files
                </h3>
              </div>

              {uploadError && (
                <div className="p-3 rounded-lg bg-red-950/60 border border-red-800/80 text-xs text-red-300 flex items-center gap-2 text-left">
                  <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                  <span>{uploadError}</span>
                </div>
              )}

              {/* Authentication requirement reminder banner */}
              {!currentUser ? (
                <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-[#20100a] border border-[#ea580c]/40 text-xs text-[#ff936b] font-mono">
                  <Lock className="w-3.5 h-3.5 text-[#f95721]" />
                  <span>Sign-in required to upload</span>
                </div>
              ) : (
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-emerald-950/60 border border-emerald-700/60 text-xs text-emerald-300 font-mono">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Logged in as {currentUser.name} ({currentUser.role})</span>
                </div>
              )}

              <div className="flex items-center justify-center gap-3 pt-2">
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    handleUploadClick();
                  }}
                  className="px-4 py-2 bg-[#f95721] hover:bg-[#ea580c] text-white font-semibold rounded-lg text-xs flex items-center gap-1.5 transition-colors shadow-sm cursor-pointer"
                >
                  <UploadCloud className="w-3.5 h-3.5" />
                  <span>Select Evidence File</span>
                </button>

                {!currentUser && (
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleRegisterClick();
                    }}
                    className="px-3 py-2 bg-[#27130b] hover:bg-[#38180e] border border-[#ea580c]/50 text-[#ff8d60] font-semibold rounded-lg text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <UserPlus className="w-3.5 h-3.5" />
                    <span>Register First</span>
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </section>

      {/* ========================================================================= */}
      {/* ACTIVE CASES DIRECTORY PREVIEW (Limited to two investigations) */}
      {/* ========================================================================= */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-xl font-bold tracking-tight text-[#fafaf9]">
            Current Investigations
          </h2>
          <button
            type="button"
            onClick={() => {
              if (!currentUser) {
                setAuthNotice('Please sign in to inspect all active case investigations.');
                setCurrentPage('login');
              } else {
                setCurrentPage('cases');
              }
            }}
            className="text-xs font-semibold text-[#f95721] hover:text-[#fb923c] flex items-center gap-1 transition-colors cursor-pointer"
          >
            <span>View All Cases</span>
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {cases.slice(0, 2).map((c) => {
            const caseEvidence = evidenceList.filter((e) => e.case_id === c.id);
            const caseEvents = events.filter((e) => e.case_id === c.id);
            const caseDetections = detections.filter((d) => d.case_id === c.id);

            return (
              <div
                key={c.id}
                className="p-5 rounded-2xl bg-[#141211] border border-[#2e2825] hover:border-[#f95721]/60 transition-all space-y-4 shadow-lg"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[#27130b] text-[#ff8d60] border border-[#ea580c]/40 font-bold">
                        {c.status}
                      </span>
                      <span className="text-[11px] font-mono text-[#a8a29e]">{c.id}</span>
                    </div>
                    <h3 className="text-base font-bold text-[#fafaf9]">{c.name}</h3>
                  </div>
                  <FolderLock className="w-5 h-5 text-[#f95721] shrink-0" />
                </div>

                <p className="text-xs text-[#a8a29e] line-clamp-2 leading-relaxed">
                  {c.description}
                </p>

                <div className="grid grid-cols-3 gap-2 pt-2 border-t border-[#26201e] text-[11px] font-mono text-[#a8a29e]">
                  <div>
                    <span className="text-[#78716c] block text-[10px]">Evidence</span>
                    <strong className="text-[#fafaf9]">{caseEvidence.length} files</strong>
                  </div>
                  <div>
                    <span className="text-[#78716c] block text-[10px]">Events</span>
                    <strong className="text-[#fafaf9]">{caseEvents.length}</strong>
                  </div>
                  <div>
                    <span className="text-[#78716c] block text-[10px]">Threats</span>
                    <strong className="text-red-400">{caseDetections.length} alerts</strong>
                  </div>
                </div>

                <div className="pt-1 flex items-center justify-between">
                  <span className="text-[10px] font-mono text-[#78716c]">
                    Lead: {c.lead_investigator || 'DFIR Team'}
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      if (!currentUser) {
                        setAuthNotice(`Please sign in to inspect case "${c.name}".`);
                        setCurrentPage('login');
                      } else {
                        setCurrentPage('cases');
                      }
                    }}
                    className="px-3 py-1.5 rounded-lg bg-[#22130c] hover:bg-[#30160d] text-[#ff8d60] border border-[#ea580c]/40 text-xs font-semibold flex items-center gap-1 transition-colors cursor-pointer"
                  >
                    <span>Open Case</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
};
