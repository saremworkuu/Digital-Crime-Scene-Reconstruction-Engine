import React, { useState, useRef } from 'react';
import { useApp } from '../store';
import { 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  FileText, 
  UploadCloud, 
  FileCode, 
  ChevronRight,
  ChevronDown,
  Info,
  Check
} from 'lucide-react';
import { ConcernMatrix } from '../components/ConcernMatrix';
import { ParserType } from '../types';

interface ComplianceControl {
  id: string;
  status: 'violation' | 'warning' | 'satisfied';
  description: string;
  hasEvidence: boolean;
  ownerInitials: string;
  ownerColor: string;
  nextReview: string;
  evidenceName?: string;
}

export const Compliance: React.FC = () => {
  const { activeCase, uploadEvidence, evidenceList } = useApp();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [isDragging, setIsDragging] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [selectedControl, setSelectedControl] = useState<ComplianceControl | null>(null);

  const controls: ComplianceControl[] = [
    { id: 'AC-01', status: 'violation', description: 'Define and enforce access policies', hasEvidence: true, ownerInitials: 'AR', ownerColor: 'bg-[#ff7b22]', nextReview: '2025-05-21', evidenceName: 'access_control_policy_v2.pdf' },
    { id: 'AC-02', status: 'warning', description: 'Enforce RBAC across all systems', hasEvidence: false, ownerInitials: 'SM', ownerColor: 'bg-[#e5a00d]', nextReview: '2025-05-17' },
    { id: 'AC-03', status: 'satisfied', description: 'Multi-factor auth for admin users', hasEvidence: true, ownerInitials: 'MA', ownerColor: 'bg-[#ea580c]', nextReview: '2025-05-09', evidenceName: 'yubikey_radius_audit.log' },
    { id: 'AC-04', status: 'warning', description: 'Regular review of user access levels', hasEvidence: false, ownerInitials: 'JD', ownerColor: 'bg-red-500', nextReview: '2025-05-06' },
    { id: 'AC-05', status: 'violation', description: 'Terminate dormant user accounts', hasEvidence: false, ownerInitials: 'SR', ownerColor: 'bg-emerald-600', nextReview: '2025-05-03' },
    { id: 'AC-06', status: 'satisfied', description: 'Enforce RBAC across all systems', hasEvidence: true, ownerInitials: 'AR', ownerColor: 'bg-[#ff7b22]', nextReview: '2025-05-02', evidenceName: 'active_directory_rbac_matrix.json' },
  ];

  const handleFileUpload = async (files: FileList | null) => {
    if (!files || files.length === 0 || !activeCase) return;
    const file = files[0];
    setUploadStatus(`Ingesting ${file.name}... Calculating SHA-256 integrity hash...`);

    let parserType: ParserType = 'generic';
    const lowerName = file.name.toLowerCase();
    if (lowerName.includes('auth') || lowerName.includes('secure')) parserType = 'linux_auth';
    else if (lowerName.includes('access') || lowerName.includes('nginx') || lowerName.includes('apache')) parserType = 'web_server';
    else if (lowerName.endsWith('.evtx')) parserType = 'windows_evtx';
    else if (lowerName.endsWith('.pcap')) parserType = 'pcap_summary';

    try {
      await uploadEvidence(activeCase.id, file, parserType);
      setUploadStatus(`Successfully parsed ${file.name} into forensic case timeline.`);
      setTimeout(() => setUploadStatus(null), 4000);
    } catch {
      setUploadStatus(`Error uploading ${file.name}`);
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Title & Controls */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">
            Compliance
          </h1>
          <p className="text-xs text-neutral-400 mt-1">
            Framework evaluation & digital chain-of-custody evidence registry
          </p>
        </div>
      </div>

      {/* 42% Controls Satisfied Banner (Exact match to Screenshot 2!) */}
      <div className="p-4 rounded-2xl bg-neutral-900/80 border border-neutral-800/80 flex items-center justify-between backdrop-blur-xl">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-xl bg-amber-950/60 border border-amber-800/60 flex items-center justify-center text-amber-400">
            <AlertTriangle className="w-4 h-4" />
          </div>
          <div>
            <div className="text-sm font-bold text-neutral-100 flex items-center gap-2">
              <span>42% Controls Satisfied</span>
              <span className="text-[10px] text-neutral-400 font-normal">· SOC2 Type II / NIST CSF 2.0</span>
            </div>
            <p className="text-xs text-neutral-400">
              4 critical access control gaps identified in current investigation scope
            </p>
          </div>
        </div>

        <button 
          onClick={() => setSelectedControl(controls[0])}
          className="text-xs text-neutral-400 hover:text-white flex items-center gap-1 font-medium transition-colors"
        >
          <span>Click to view detailed breakdown</span>
          <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Controls Table (Exact match to Screenshot 2!) */}
      <div className="rounded-2xl bg-neutral-900/60 border border-neutral-800/80 overflow-hidden backdrop-blur-xl">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#09090c] border-b border-neutral-800/80 text-neutral-500 uppercase tracking-wider text-[10px] font-mono">
            <tr>
              <th className="py-3 px-4">CONTROL ID</th>
              <th className="py-3 px-4">STATUS</th>
              <th className="py-3 px-4">DESCRIPTION</th>
              <th className="py-3 px-4 text-center">EVIDENCE</th>
              <th className="py-3 px-4 text-center">OWNER</th>
              <th className="py-3 px-4 text-right">NEXT REVIEW</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-neutral-800/60 text-neutral-300">
            {controls.map((ctrl) => (
              <tr 
                key={ctrl.id} 
                onClick={() => setSelectedControl(ctrl)}
                className="hover:bg-neutral-850/40 transition-colors cursor-pointer group"
              >
                {/* Control ID */}
                <td className="py-3.5 px-4 font-mono font-semibold text-neutral-200">
                  {ctrl.id}
                </td>

                {/* Status Dot / Icon (Screenshot 2) */}
                <td className="py-3.5 px-4">
                  {ctrl.status === 'violation' && (
                    <span className="inline-flex items-center gap-1.5 text-red-400">
                      <span className="w-2.5 h-2.5 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]" />
                    </span>
                  )}
                  {ctrl.status === 'warning' && (
                    <span className="inline-flex items-center gap-1.5 text-amber-400">
                      <span className="w-2.5 h-2.5 rounded-full bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.6)]" />
                    </span>
                  )}
                  {ctrl.status === 'satisfied' && (
                    <span className="inline-flex items-center gap-1.5 text-emerald-400">
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]" />
                    </span>
                  )}
                </td>

                {/* Description */}
                <td className="py-3.5 px-4 font-medium text-neutral-200 group-hover:text-white">
                  {ctrl.description}
                </td>

                {/* Evidence Icon */}
                <td className="py-3.5 px-4 text-center">
                  {ctrl.hasEvidence ? (
                    <FileText className="w-4 h-4 text-neutral-400 hover:text-[#ff461e] inline transition-colors" />
                  ) : (
                    <span className="text-neutral-600">-</span>
                  )}
                </td>

                {/* Owner Avatar Pill (AR, SM, MA, JD, SR) */}
                <td className="py-3.5 px-4 text-center">
                  <span className={`inline-flex items-center justify-center w-6 h-6 rounded-md text-[10px] font-bold text-white ${ctrl.ownerColor}`}>
                    {ctrl.ownerInitials}
                  </span>
                </td>

                {/* Next Review Date */}
                <td className="py-3.5 px-4 text-right font-mono text-neutral-400">
                  {ctrl.nextReview}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Bottom Section: Evidence Upload + Concern Heatmap Matrix (Matching Screenshot 2!) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Evidence Upload Dropzone */}
        <div className="rounded-2xl bg-neutral-900/60 border border-neutral-800/80 p-5 backdrop-blur-xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-neutral-100">Evidence Upload</h3>
            <span className="text-[10px] font-mono text-neutral-500">SHA-256 Verified</span>
          </div>

          <div
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={(e) => { e.preventDefault(); setIsDragging(false); handleFileUpload(e.dataTransfer.files); }}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-xl p-8 text-center transition-all cursor-pointer flex flex-col items-center justify-center space-y-2.5 ${
              isDragging
                ? 'border-[#ff461e] bg-[#ff461e]/10'
                : 'border-neutral-800 bg-[#08080b]/80 hover:border-neutral-700 hover:bg-neutral-850/30'
            }`}
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={(e) => handleFileUpload(e.target.files)}
              className="hidden"
              multiple
            />
            <div className="w-10 h-10 rounded-xl bg-neutral-900 border border-neutral-800 flex items-center justify-center text-[#ff461e]">
              <UploadCloud className="w-5 h-5" />
            </div>
            <div>
              <p className="text-xs font-semibold text-neutral-200">
                Drag & drop files or <span className="text-[#ff461e] hover:underline">Browse</span>
              </p>
              <p className="text-[10px] text-neutral-500 mt-1 font-mono">
                Supported formats: JPEG, PNG, HTML, PDF, XML, PPT, LOG, EVTX, PCAP
              </p>
            </div>
          </div>

          {uploadStatus && (
            <div className="p-3 bg-neutral-950 border border-neutral-800 rounded-xl text-xs text-neutral-300 font-mono flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#ff461e] animate-pulse" />
              <span>{uploadStatus}</span>
            </div>
          )}

          {/* Quick Evidence Inventory */}
          <div className="space-y-1.5 pt-2">
            <span className="text-[11px] font-mono text-neutral-500 uppercase tracking-wider">
              Enclave Evidence Custody ({evidenceList.length} items)
            </span>
            <div className="max-h-36 overflow-y-auto space-y-1">
              {evidenceList.map((ev) => (
                <div key={ev.id} className="flex items-center justify-between p-2 rounded-lg bg-neutral-950/60 border border-neutral-800/60 text-xs">
                  <div className="flex items-center gap-2 truncate">
                    <FileCode className="w-3.5 h-3.5 text-[#ff8f3d] shrink-0" />
                    <span className="text-neutral-200 font-medium truncate">{ev.filename}</span>
                  </div>
                  <span className="text-[10px] font-mono text-neutral-400 shrink-0">
                    {ev.event_count || ev.eventCount || 0} events
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Concern Matrix (The glowing heatmap from Screenshot 2!) */}
        <div className="rounded-2xl bg-neutral-900/60 border border-neutral-800/80 p-5 backdrop-blur-xl space-y-4">
          <ConcernMatrix />
        </div>

      </div>

    </div>
  );
};
