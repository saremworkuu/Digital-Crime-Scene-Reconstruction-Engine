import React, { useState } from 'react';

import { useApp } from '../store';

import { EvidenceFile, ParserType } from '../types';

import { UploadDropzone } from '../components/UploadDropzone';

import {

  FileCheck2,

  Copy,

  Check,

  Download,

  Trash2,

  RefreshCw,

  AlertTriangle,

  FileCode,

  Eye,

  X,

  Hash,

  Search,

  ChevronDown,

  ArrowUpDown,

  Lock

} from 'lucide-react';

const getEffectiveParser = (ev: EvidenceFile): string => {
  if (ev.parser_used) {
    const p = ev.parser_used.toLowerCase();
    if (p.includes('pcap')) return 'pcap_summary';
    if (p.includes('evtx') || p.includes('windows')) return 'windows_evtx';
    if (p.includes('web') || p.includes('access') || p.includes('nginx') || p.includes('apache')) return 'web_server';
    if (p.includes('auth') || p.includes('syslog') || p.includes('secure')) return 'linux_auth';
    if (p.includes('csv') || p.includes('json') || p.includes('txt') || p.includes('generic')) return 'generic_json_csv';
    return ev.parser_used;
  }
  const name = ev.filename.toLowerCase();
  if (name.endsWith('.pcap') || name.endsWith('.pcapng')) return 'pcap_summary';
  if (name.endsWith('.evtx')) return 'windows_evtx';
  if (name.includes('nginx') || name.includes('access') || name.includes('web') || name.includes('apache')) return 'web_server';
  if (name.includes('auth') || name.includes('syslog') || name.includes('secure')) return 'linux_auth';
  return 'generic_json_csv';
};

export const Evidence: React.FC = () => {

  const {

    activeCase,

    activeCaseId,

    activeCaseEvidence,

    reparseEvidence,

    deleteEvidence,

    logAuditAction,

    currentUser,

    setCurrentPage,

    setAuthNotice,

    theme

  } = useApp();



  const isLight = theme === 'light';



  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const [selectedPreview, setSelectedPreview] = useState<EvidenceFile | null>(null);

  const [searchQuery, setSearchQuery] = useState('');

  const [statusFilter, setStatusFilter] = useState<'All' | 'Parsed' | 'Failed'>('All');

  const [sortBy, setSortBy] = useState<'newest' | 'oldest' | 'name' | 'size' | 'events'>('newest');



  const filteredEvidence = activeCaseEvidence

    .filter((ev) => {

      const matchesStatus = statusFilter === 'All' || ev.status === statusFilter;

      const q = searchQuery.toLowerCase().trim();

      const matchesSearch =

        !q ||

        ev.filename.toLowerCase().includes(q) ||

        ev.sha256_hash.toLowerCase().includes(q) ||

        (ev.parser_used?.toLowerCase().includes(q) ?? false) ||

        (ev.uploader_name?.toLowerCase().includes(q) ?? false);

      return matchesStatus && matchesSearch;

    })

    .sort((a, b) => {

      if (sortBy === 'newest') {

        return new Date(b.uploaded_at).getTime() - new Date(a.uploaded_at).getTime();

      }

      if (sortBy === 'oldest') {

        return new Date(a.uploaded_at).getTime() - new Date(b.uploaded_at).getTime();

      }

      if (sortBy === 'name') {

        return a.filename.localeCompare(b.filename);

      }

      if (sortBy === 'size') {

        return (b.size_bytes || 0) - (a.size_bytes || 0);

      }

      if (sortBy === 'events') {

        return (b.event_count || 0) - (a.event_count || 0);

      }

      return 0;

    });



  const handleCopyHash = (hash: string) => {

    navigator.clipboard.writeText(hash);

    setCopiedHash(hash);

    setTimeout(() => setCopiedHash(null), 2000);

  };



  const handleDownload = (ev: EvidenceFile) => {

    const content = ev.raw_sample || `Evidence ID: ${ev.id}\nFilename: ${ev.filename}\nSHA-256: ${ev.sha256_hash}\nEvents Extracted: ${ev.event_count}\n`;

    const blob = new Blob([content], { type: 'text/plain' });

    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');

    a.href = url;

    a.download = ev.filename;

    a.click();

    URL.revokeObjectURL(url);



    logAuditAction('EVIDENCE_DOWNLOADED', 'evidence', ev.id, { filename: ev.filename, sha256: ev.sha256_hash });

  };



  const canDeleteEvidence = Boolean(currentUser);



  return (

    <div className="space-y-6">

      

      {/* Header */}

      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[#282321]">

        <div>

          <div className="text-[11px] font-mono text-[#a8a29e] mb-1 flex items-center gap-1.5">

            <span>&gt;</span>

            <span className="text-[#d6d3d1]">Evidence Repository</span>

          </div>

          <h1 className="text-xl font-bold tracking-tight text-[#fafaf9] flex items-center gap-2.5">

            <FileCheck2 className="w-5 h-5 text-[#f95721]" />

            <span>Digital Evidence Ingestion & Custody Inventory</span>

          </h1>

          <p className="text-xs text-[#a8a29e] mt-0.5">

            Case: <strong className="text-[#fafaf9] font-semibold">{activeCase?.name}</strong> · Forensic verification with SHA-256 integrity checks

          </p>

        </div>



        <div className="font-mono text-xs text-[#a8a29e] tabular-nums">

          Total evidence items: <span className="text-[#f95721] font-semibold">{activeCaseEvidence.length}</span>

        </div>

      </div>



      {/* Unauthenticated notice */}

      {!currentUser && (

        <div className="p-4 rounded-xl bg-[#26130b] border-2 border-[#ea580c]/60 flex flex-wrap items-center justify-between gap-4 text-xs shadow-lg">

          <div className="flex items-center gap-3">

            <div className="p-2 rounded-lg bg-[#3a160d] text-[#f95721] shrink-0">

              <Lock className="w-5 h-5" />

            </div>

            <div>

              <div className="font-bold text-[#fafaf9] text-sm">Sign In Required to Upload Evidence</div>

              <div className="text-[#a8a29e] text-xs">You are currently in read-only mode. Please sign in or register to ingest new forensic evidence files.</div>

            </div>

          </div>

          <div className="flex items-center gap-2 shrink-0">

            <button

              onClick={() => {

                setAuthNotice('Please sign in to upload digital evidence. If you do not have an account, please register.');

                setCurrentPage('login');

              }}

              className="px-3.5 py-2 rounded-lg bg-[#f95721] hover:bg-[#ea580c] text-white font-semibold text-xs cursor-pointer shadow-sm transition-colors"

            >

              Sign In to Upload

            </button>

            <button

              onClick={() => {

                setAuthNotice('Please register an account to upload digital evidence.');

                setCurrentPage('register');

              }}

              className="px-3.5 py-2 rounded-lg bg-[#1e1b19] hover:bg-[#282421] border border-[#352e2b] text-[#fafaf9] font-medium text-xs cursor-pointer transition-colors"

            >

              Register

            </button>

          </div>

        </div>

      )}



      {/* Upload Dropzone (FR-EVID-1..4) with Concern Heatmap Matrix */}
      <UploadDropzone caseId={activeCase?.id || activeCaseId} />



      {/* Evidence Files Inventory Table (FR-EVID-5, FR-EVID-7) */}

      <div className={`${isLight ? 'bg-white border-[#e4e4e7]' : 'bg-[#161413]/90 border-[#2b2523]'} border rounded-2xl overflow-hidden flex flex-col shadow-xl`}>

        <div className={`px-5 py-3.5 border-b ${isLight ? 'bg-slate-50 border-[#e4e4e7]' : 'bg-[#121110] border-[#2b2523]'} flex flex-wrap items-center justify-between gap-3`}>

          <div className="flex items-center gap-2">

            <h3 className={`text-xs font-semibold ${isLight ? 'text-[#0f172a]' : 'text-[#fafaf9]'} uppercase font-mono`}>

              Evidence Custody Inventory

            </h3>

            <span className={`text-[11px] font-mono ${isLight ? 'text-[#64748b]' : 'text-[#78716c]'}`}>

              ({filteredEvidence.length} files)

            </span>

          </div>



          {/* Search & Dropdown Controls */}

          <div className="flex items-center gap-2.5 flex-wrap">

            {/* Search Input */}

            <div className="relative min-w-[180px] sm:min-w-[220px]">

              <Search className={`w-3.5 h-3.5 ${isLight ? 'text-[#94a3b8]' : 'text-[#78716c]'} absolute left-2.5 top-1/2 -translate-y-1/2`} />

              <input

                type="text"

                placeholder="Search filename, SHA-256, parser..."

                value={searchQuery}

                onChange={(e) => setSearchQuery(e.target.value)}

                className={`w-full ${isLight ? 'bg-white border-slate-300 text-[#0f172a] placeholder-[#94a3b8]' : 'bg-[#0d0c0c] border-[#2b2523] text-[#fafaf9] placeholder-[#78716c]'} border rounded-lg pl-8 pr-7 py-1 text-xs focus:outline-none focus:border-[#f95721] font-mono transition-colors`}

              />

              {searchQuery && (

                <button

                  onClick={() => setSearchQuery('')}

                  className={`absolute right-2 top-1/2 -translate-y-1/2 ${isLight ? 'text-[#94a3b8] hover:text-[#0f172a]' : 'text-[#78716c] hover:text-[#fafaf9]'} cursor-pointer`}

                >

                  <X className="w-3 h-3" />

                </button>

              )}

            </div>



            {/* Status Dropdown */}

            <div className={`relative flex items-center ${isLight ? 'bg-white border-slate-300 text-[#0f172a]' : 'bg-[#0d0c0c] border-[#2b2523] text-[#fafaf9]'} border rounded-lg px-2.5 py-1 text-xs font-mono`}>

              <span className={`${isLight ? 'text-[#64748b]' : 'text-[#78716c]'} text-[11px] mr-1`}>Status:</span>

              <select

                value={statusFilter}

                onChange={(e) => setStatusFilter(e.target.value as any)}

                className={`bg-transparent ${isLight ? 'text-[#0f172a]' : 'text-[#fafaf9]'} focus:outline-none cursor-pointer pr-5 font-semibold text-xs appearance-none`}

              >

                <option value="All" className={isLight ? 'bg-white text-[#0f172a]' : 'bg-[#161413] text-[#e7e5e4]'}>All</option>

                <option value="Parsed" className={isLight ? 'bg-white text-emerald-600' : 'bg-[#161413] text-[#86efac]'}>Parsed</option>

                <option value="Failed" className={isLight ? 'bg-white text-red-600' : 'bg-[#161413] text-[#fca5a5]'}>Failed</option>

              </select>

              <ChevronDown className={`w-3 h-3 ${isLight ? 'text-[#94a3b8]' : 'text-[#78716c]'} absolute right-2 pointer-events-none`} />

            </div>



            {/* Sort Dropdown */}

            <div className={`relative flex items-center ${isLight ? 'bg-white border-slate-300 text-[#0f172a]' : 'bg-[#0d0c0c] border-[#2b2523] text-[#fafaf9]'} border rounded-lg px-2.5 py-1 text-xs font-mono`}>

              <ArrowUpDown className="w-3 h-3 text-[#f95721] mr-1" />

              <span className={`${isLight ? 'text-[#64748b]' : 'text-[#78716c]'} text-[11px] mr-1`}>Sort:</span>

              <select

                value={sortBy}

                onChange={(e) => setSortBy(e.target.value as any)}

                className={`bg-transparent ${isLight ? 'text-[#0f172a]' : 'text-[#fafaf9]'} focus:outline-none cursor-pointer pr-5 font-semibold text-xs appearance-none`}

              >

                <option value="newest" className={isLight ? 'bg-white text-[#0f172a]' : 'bg-[#161413] text-[#e7e5e4]'}>Newest</option>

                <option value="oldest" className={isLight ? 'bg-white text-[#0f172a]' : 'bg-[#161413] text-[#e7e5e4]'}>Oldest</option>

                <option value="name" className={isLight ? 'bg-white text-[#0f172a]' : 'bg-[#161413] text-[#e7e5e4]'}>Filename</option>

                <option value="size" className={isLight ? 'bg-white text-[#0f172a]' : 'bg-[#161413] text-[#e7e5e4]'}>Size</option>

                <option value="events" className={isLight ? 'bg-white text-[#0f172a]' : 'bg-[#161413] text-[#e7e5e4]'}>Events</option>

              </select>

              <ChevronDown className={`w-3 h-3 ${isLight ? 'text-[#94a3b8]' : 'text-[#78716c]'} absolute right-2 pointer-events-none`} />

            </div>

          </div>

        </div>



        <div className="overflow-x-auto">

          <table className="w-full text-left border-collapse text-xs">

            <thead>

              <tr className={`border-b ${isLight ? 'border-slate-200 bg-slate-100/80 text-slate-600' : 'border-[#2b2523] bg-[#100f0e] text-[#a8a29e]'} font-mono text-[11px]`}>

                <th className="py-2.5 px-4">Filename & Parser</th>

                <th className="py-2.5 px-4">SHA-256 Hash</th>

                <th className="py-2.5 px-4 text-right">Size</th>

                <th className="py-2.5 px-4 text-center">Status</th>

                <th className="py-2.5 px-4 text-right">Extracted Events</th>

                <th className="py-2.5 px-4">Uploaded By</th>

                <th className="py-2.5 px-4 text-center">Actions</th>

              </tr>

            </thead>

            <tbody className={`divide-y ${isLight ? 'divide-slate-200' : 'divide-[#26211f]'}`}>

              {filteredEvidence.length === 0 ? (

                <tr>

                  <td colSpan={7} className={`py-12 text-center ${isLight ? 'text-slate-500' : 'text-[#78716c]'}`}>

                    {activeCaseEvidence.length === 0

                      ? 'No evidence files ingested for this case yet. Drop files in the upload zone above.'

                      : 'No evidence files match the current search or filter criteria.'}

                  </td>

                </tr>

              ) : (

                filteredEvidence.map((ev) => (

                  <tr key={ev.id} className={`${isLight ? 'hover:bg-slate-50' : 'hover:bg-[#1c1918]'} transition-colors`}>

                    {/* Filename & Parser selector */}

                    <td className="py-3 px-4">

                      <div className={`font-semibold ${isLight ? 'text-[#0f172a]' : 'text-[#fafaf9]'} font-mono`}>{ev.filename}</div>

                      <div className="flex items-center gap-2 mt-1">

                        <select

                          value={getEffectiveParser(ev)}

                          onChange={(e) => reparseEvidence(ev.id, e.target.value as ParserType)}

                          className={`${isLight ? 'bg-slate-100 border-slate-300 text-orange-700' : 'bg-[#100f0e] border-[#2e2926] text-[#fb923c]'} border rounded px-1.5 py-0.5 text-[10px] font-mono focus:outline-none`}

                          title="Change parser and reparse"

                        >

                          <option value="linux_auth">linux_auth</option>

                          <option value="web_server">web_server</option>

                          <option value="windows_evtx">windows_evtx</option>

                          <option value="pcap_summary">pcap_summary</option>

                          <option value="generic_json_csv">generic_json_csv</option>

                        </select>

                        {ev.parse_errors && ev.parse_errors.length > 0 && (

                          <span className="text-[10px] font-mono text-amber-400 flex items-center gap-0.5" title={ev.parse_errors.join('; ')}>

                            <AlertTriangle className="w-3 h-3" />

                            <span>{ev.parse_errors.length} errs</span>

                          </span>

                        )}

                      </div>

                    </td>



                    {/* SHA-256 Hash with Copy */}

                    <td className="py-3 px-4 font-mono text-[#d6d3d1]">

                      <div className="flex items-center gap-1.5">

                        <span className="text-[#a8a29e] tracking-tight" title={ev.sha256_hash}>

                          {ev.sha256_hash.slice(0, 16)}...{ev.sha256_hash.slice(-8)}

                        </span>

                        <button

                          onClick={() => handleCopyHash(ev.sha256_hash)}

                          className="p-1 rounded text-[#78716c] hover:text-[#f95721] transition-colors"

                          title="Copy full 256-bit hash"

                        >

                          {copiedHash === ev.sha256_hash ? (

                            <Check className="w-3 h-3 text-emerald-400" />

                          ) : (

                            <Copy className="w-3 h-3" />

                          )}

                        </button>

                      </div>

                    </td>



                    {/* File Size */}

                    <td className="py-3 px-4 font-mono text-[#a8a29e] text-right tabular-nums">

                      {(ev.size_bytes / 1024).toFixed(1)} KB

                    </td>



                    {/* Status */}

                    <td className="py-3 px-4 text-center">

                      <span className={`inline-block font-mono text-[11px] font-semibold uppercase px-2 py-0.5 rounded ${

                        ev.status === 'Parsed'

                          ? 'bg-emerald-950/70 text-emerald-400 border border-emerald-800/60'

                          : ev.status === 'Failed'

                          ? 'bg-red-950/70 text-red-400 border border-red-800/60'

                          : 'bg-[#221f1d] text-[#a8a29e]'

                      }`}>

                        {ev.status}

                      </span>

                    </td>



                    {/* Extracted Events */}

                    <td className="py-3 px-4 font-mono text-right font-semibold text-[#fafaf9] tabular-nums">

                      {ev.event_count}

                    </td>



                    {/* Uploader & Date */}

                    <td className="py-3 px-4 font-mono text-[#a8a29e] text-[11px]">

                      <div className="text-[#d6d3d1]">{ev.uploader_name}</div>

                      <div className="text-[#78716c]">{ev.uploaded_at.slice(0, 16).replace('T', ' ')}</div>

                    </td>



                    {/* Actions */}

                    <td className="py-3 px-4 text-center">

                      <div className="flex items-center justify-center gap-1.5">

                        <button

                          onClick={() => setSelectedPreview(ev)}

                          className="p-1.5 rounded text-[#a8a29e] hover:text-[#f95721] hover:bg-[#25201d] transition-colors"

                          title="Preview raw evidence sample"

                        >

                          <Eye className="w-3.5 h-3.5" />

                        </button>



                        <button

                          onClick={() => handleDownload(ev)}

                          className="p-1.5 rounded text-[#a8a29e] hover:text-[#f95721] hover:bg-[#25201d] transition-colors"

                          title="Download original evidence file (FR-EVID-8)"

                        >

                          <Download className="w-3.5 h-3.5" />

                        </button>



                        {canDeleteEvidence && (

                          <button

                            onClick={() => {

                              if (window.confirm(`Delete evidence file "${ev.filename}"? This also removes its parsed events.`)) {

                                void deleteEvidence(ev.id);

                              }

                            }}

                            className="p-1.5 rounded text-[#a8a29e] hover:text-red-400 hover:bg-[#25201d] transition-colors"

                            title={`Delete ${ev.filename}`}
                            aria-label={`Delete evidence file ${ev.filename}`}

                          >

                            <Trash2 className="w-3.5 h-3.5" />

                          </button>

                        )}

                      </div>

                    </td>

                  </tr>

                ))

              )}

            </tbody>

          </table>

        </div>

      </div>



      {/* Raw Sample Preview Modal (FR-EVID-6) */}

      {selectedPreview && (

        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">

          <div className="w-full max-w-3xl bg-[#161413] border border-[#2b2523] rounded-2xl shadow-2xl p-6 space-y-4">

            <div className="flex items-center justify-between pb-3 border-b border-[#2b2523]">

              <div className="flex items-center gap-2">

                <FileCode className="w-4 h-4 text-[#f95721]" />

                <h3 className="text-sm font-semibold text-[#fafaf9] font-mono">

                  {selectedPreview.filename} (Evidence Inspection)

                </h3>

              </div>

              <button

                onClick={() => setSelectedPreview(null)}

                className="text-[#78716c] hover:text-[#fafaf9]"

              >

                <X className="w-4 h-4" />

              </button>

            </div>



            <div className="text-xs font-mono text-[#a8a29e] space-y-1">

              <div>SHA-256: <span className="text-[#fafaf9]">{selectedPreview.sha256_hash}</span></div>

              <div>Parser Applied: <span className="text-[#f95721]">{selectedPreview.parser_used}</span></div>

            </div>



            <pre className="p-4 bg-[#0e0d0d] border border-[#2b2523] rounded-xl font-mono text-xs text-[#d6d3d1] overflow-x-auto whitespace-pre-wrap max-h-96">

              {selectedPreview.raw_sample || 'No raw text sample stored for this binary artifact.'}

            </pre>



            <div className="flex justify-end pt-2 border-t border-[#2b2523]">

              <button

                onClick={() => setSelectedPreview(null)}

                className="px-4 py-1.5 rounded-lg bg-[#221f1d] hover:bg-[#2d2825] text-[#d6d3d1] text-xs font-semibold transition-colors"

              >

                Close

              </button>

            </div>

          </div>

        </div>

      )}



    </div>

  );

};

