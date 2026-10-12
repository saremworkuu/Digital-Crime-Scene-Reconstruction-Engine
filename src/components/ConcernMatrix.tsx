import React, { useState } from 'react';
import { Eye, ShieldAlert, Code2, Check, Copy } from 'lucide-react';

interface ConcernItem {
  id: string;
  level: 'low' | 'moderate' | 'high';
  title: string;
  source: string;
  timestamp: string;
  codeSnippet: string;
}

const CONCERNS: ConcernItem[] = [
  {
    id: 'c-1',
    level: 'high',
    title: 'Hardcoded Cryptographic Salt in Ingestion',
    source: 'auth/crypto.py:42',
    timestamp: '2026-09-22 02:14:09 UTC',
    codeSnippet: `import bcrypt\n\ndef hash_password(password):\n    # CRITICAL: static salt fallback detected\n    salt = b"$2b$12$e8uqN7RkQ0m1s..."\n    return bcrypt.hashpw(password.encode(), salt)\n\ndef check_password(password, hashed):\n    return bcrypt.checkpw(password.encode(), hashed)`
  },
  {
    id: 'c-2',
    level: 'high',
    title: 'Shadow Credential Dumping via NTDS.dit',
    source: 'windows_evtx/ntdsutil.log',
    timestamp: '2026-09-22 02:41:20 UTC',
    codeSnippet: `CMD: ntdsutil.exe "ac i ntds" "ifm" "create full C:\\Windows\\Temp\\export" q q\nPROCESS: PID 4812 spawned by NT AUTHORITY\\SYSTEM\nINTEGRITY: Elevated (SeBackupPrivilege enabled)`
  },
  {
    id: 'c-3',
    level: 'moderate',
    title: 'Direct Sudo Execution Without TTY Prompt',
    source: 'linux_auth/auth.log:182',
    timestamp: '2026-09-22 02:15:33 UTC',
    codeSnippet: `web-admin ALL=(ALL) NOPASSWD: /usr/bin/python3 -c "import pty; pty.spawn('/bin/bash')"\nAUTH_METHOD: sudo setuid elevation\nRESULT: root shell granted`
  },
  {
    id: 'c-4',
    level: 'low',
    title: 'Unencrypted Internal HTTP Flow',
    source: 'pcap/flow_summary.csv:91',
    timestamp: '2026-09-22 01:58:12 UTC',
    codeSnippet: `GET /api/v1/internal/config HTTP/1.1\nHost: 10.0.1.10:8080\nAuthorization: Bearer dev-token-cleartext\nStatus: 200 OK (2104 bytes)`
  },
  {
    id: 'c-5',
    level: 'high',
    title: 'WebShell Upload in /var/www/uploads',
    source: 'web_server/access.log:402',
    timestamp: '2026-09-22 02:08:15 UTC',
    codeSnippet: `POST /upload.php HTTP/1.1\nContent-Disposition: name="payload"; filename="cmd.php"\nContent-Type: application/x-php\n<?php system($_GET['cmd']); ?>`
  },
  {
    id: 'c-6',
    level: 'moderate',
    title: 'Excessive TLS Egress Outbound Exfiltration',
    source: 'suricata/eve.json:512',
    timestamp: '2026-09-22 03:00:18 UTC',
    codeSnippet: `SRC: 10.0.3.50:49210 -> DST: 198.51.100.23:443\nFLOW_BYTES: 1.42 GB transmitted in 240s\nALERT: Outbound bulk data transfer exceeding policy baseline`
  },
  {
    id: 'c-7',
    level: 'low',
    title: 'TLS v1.1 Deprecated Protocol Negotiation',
    source: 'nginx/ssl.log:14',
    timestamp: '2026-09-22 00:44:00 UTC',
    codeSnippet: `SSL_PROTOCOL: TLSv1.1\nCIPHER: ECDHE-RSA-AES256-SHA\nCLIENT_IP: 10.0.0.12 (Internal Monitoring Node)`
  },
  {
    id: 'c-8',
    level: 'moderate',
    title: 'Repeated Kerberos Ticket Request Failure (KRB_AP_ERR_MODIFIED)',
    source: 'windows_evtx/security.evtx:4768',
    timestamp: '2026-09-22 02:30:45 UTC',
    codeSnippet: `EventID: 4768\nTargetUserName: krbtgt\nServiceName: HOST/DC01.corp\nFailureCode: 0x25 (Kerberoasting pre-auth anomaly)`
  }
];

export const ConcernMatrix: React.FC = () => {
  const [activeConcern, setActiveConcern] = useState<ConcernItem>(CONCERNS[0]);
  const [copied, setCopied] = useState(false);

  // Generate a 4x16 block matrix like in Screenshot 2
  const gridCells = [
    { row: 0, level: 'high', concern: CONCERNS[0] },
    { row: 0, level: 'high', concern: CONCERNS[1] },
    { row: 0, level: 'moderate', concern: CONCERNS[2] },
    { row: 0, level: 'moderate', concern: CONCERNS[3] },
    { row: 0, level: 'high', concern: CONCERNS[4] },
    { row: 0, level: 'low', concern: CONCERNS[6] },
    { row: 0, level: 'moderate', concern: CONCERNS[5] },
    { row: 0, level: 'high', concern: CONCERNS[1] },
    { row: 0, level: 'moderate', concern: CONCERNS[7] },
    { row: 0, level: 'high', concern: CONCERNS[0] },
    { row: 0, level: 'low', concern: CONCERNS[3] },
    { row: 0, level: 'high', concern: CONCERNS[4] },

    { row: 1, level: 'moderate', concern: CONCERNS[2] },
    { row: 1, level: 'high', concern: CONCERNS[4] },
    { row: 1, level: 'high', concern: CONCERNS[1] },
    { row: 1, level: 'low', concern: CONCERNS[6] },
    { row: 1, level: 'moderate', concern: CONCERNS[7] },
    { row: 1, level: 'high', concern: CONCERNS[0] },
    { row: 1, level: 'high', concern: CONCERNS[5] },
    { row: 1, level: 'moderate', concern: CONCERNS[2] },
    { row: 1, level: 'high', concern: CONCERNS[4] },
    { row: 1, level: 'low', concern: CONCERNS[3] },
    { row: 1, level: 'high', concern: CONCERNS[1] },
    { row: 1, level: 'moderate', concern: CONCERNS[7] },

    { row: 2, level: 'low', concern: CONCERNS[6] },
    { row: 2, level: 'high', concern: CONCERNS[0] },
    { row: 2, level: 'moderate', concern: CONCERNS[3] },
    { row: 2, level: 'high', concern: CONCERNS[5] },
    { row: 2, level: 'high', concern: CONCERNS[1] },
    { row: 2, level: 'low', concern: CONCERNS[6] },
    { row: 2, level: 'moderate', concern: CONCERNS[2] },
    { row: 2, level: 'high', concern: CONCERNS[4] },
    { row: 2, level: 'moderate', concern: CONCERNS[7] },
    { row: 2, level: 'high', concern: CONCERNS[0] },
    { row: 2, level: 'high', concern: CONCERNS[1] },
    { row: 2, level: 'low', concern: CONCERNS[3] },
  ];

  const handleCopy = () => {
    navigator.clipboard.writeText(activeConcern.codeSnippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getCellColor = (level: string, isSelected: boolean) => {
    if (isSelected) return 'bg-white shadow-[0_0_12px_#fff] scale-110 z-10';
    switch (level) {
      case 'high':
        return 'bg-[#ff461e] shadow-[0_0_8px_rgba(255,70,30,0.6)] hover:brightness-125';
      case 'moderate':
        return 'bg-[#ff8f3d] shadow-[0_0_6px_rgba(255,143,61,0.5)] hover:brightness-125';
      case 'low':
      default:
        return 'bg-[#e5a00d] opacity-80 hover:opacity-100 hover:brightness-125';
    }
  };

  return (
    <div className="relative space-y-3">
      {/* Legend Header */}
      <div className="flex items-center justify-between text-[11px] text-neutral-400">
        <span className="font-semibold text-neutral-300">Live Security Concern Heatmap</span>
        <div className="flex items-center gap-3 font-mono text-[10px]">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-[2px] bg-[#e5a00d]" /> Low Concern
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-[2px] bg-[#ff8f3d]" /> Moderate Concern
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-[2px] bg-[#ff461e]" /> High Concern
          </span>
        </div>
      </div>

      {/* Grid of Blocks */}
      <div className="p-3 rounded-xl bg-neutral-950/80 border border-neutral-800/80 backdrop-blur-md">
        <div className="grid grid-cols-12 gap-1.5">
          {gridCells.map((cell, idx) => {
            const isSelected = activeConcern.id === cell.concern.id;
            return (
              <button
                key={idx}
                onClick={() => setActiveConcern(cell.concern)}
                onMouseEnter={() => setActiveConcern(cell.concern)}
                className={`w-full aspect-square rounded-[3px] transition-all duration-150 cursor-pointer ${getCellColor(
                  cell.level,
                  isSelected
                )}`}
                title={`${cell.concern.title} (${cell.level.toUpperCase()})`}
                aria-label={`View concern ${cell.concern.title}`}
              />
            );
          })}
        </div>
      </div>

      {/* Glassmorphic Floating Concern Preview Card (Matches Screenshot 2!) */}
      <div className="p-4 rounded-xl bg-neutral-900/90 border border-neutral-800/90 backdrop-blur-xl shadow-2xl space-y-3">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-[#ff461e]/15 border border-[#ff461e]/30 flex items-center justify-center text-[#ff461e]">
              <Eye className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-neutral-100">{activeConcern.title}</span>
                <span className={`text-[9px] uppercase font-mono px-1.5 py-0.5 rounded font-bold ${
                  activeConcern.level === 'high' 
                    ? 'bg-[#ff461e]/20 text-[#ff461e] border border-[#ff461e]/40' 
                    : activeConcern.level === 'moderate'
                    ? 'bg-[#ff8f3d]/20 text-[#ff8f3d] border border-[#ff8f3d]/40'
                    : 'bg-[#e5a00d]/20 text-[#e5a00d] border border-[#e5a00d]/40'
                }`}>
                  {activeConcern.level}
                </span>
              </div>
              <span className="text-[10px] text-neutral-400 font-mono">{activeConcern.source} · {activeConcern.timestamp}</span>
            </div>
          </div>

          <button
            onClick={handleCopy}
            className="p-1.5 rounded-lg bg-neutral-800/80 hover:bg-neutral-700 text-neutral-300 transition-colors text-xs flex items-center gap-1"
            title="Copy code snippet"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
        </div>

        {/* Code / Evidence Window */}
        <pre className="p-3 rounded-lg bg-[#070709] border border-neutral-800/80 text-[11px] font-mono text-neutral-200 overflow-x-auto selection:bg-[#ff461e]/30 selection:text-[#ff8f3d] leading-relaxed">
          <code>{activeConcern.codeSnippet}</code>
        </pre>
      </div>
    </div>
  );
};
