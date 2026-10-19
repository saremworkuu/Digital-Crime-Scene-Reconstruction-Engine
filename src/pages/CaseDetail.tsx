import React from 'react';
import { useApp } from '../store';
import {
  ArrowLeft,
  FileCheck2,
  Clock,
  GitBranch,
  ShieldAlert,
  FileText,
  Users,
  CheckCircle2,
  Tag
} from 'lucide-react';
import { SeverityTag } from '../components/SeverityTag';
import { MitreBadge } from '../components/MitreBadge';

export const CaseDetail: React.FC = () => {
  const {
    activeCase,
    activeCaseEvidence,
    activeCaseDetections,
    setCurrentPage,
    updateCaseStatus,
    currentUser
  } = useApp();

  if (!activeCase) {
    return (
      <div className="py-12 text-center text-[#a8a29e]">
        <p>No active case selected.</p>
        <button
          onClick={() => setCurrentPage('cases')}
          className="mt-3 text-[#f95721] hover:text-[#fb923c] underline cursor-pointer"
        >
          Return to Cases
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      
      {/* Top Breadcrumb & Actions */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[#282321]">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setCurrentPage('cases')}
            className="p-2 rounded-lg hover:bg-[#25201e] text-[#a8a29e] hover:text-[#fafaf9] transition-colors cursor-pointer"
            title="Back to all cases"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-[#a8a29e]">
              <span>Case ID: {activeCase.id}</span>
              <span>·</span>
              <span className="text-[#f95721] font-semibold">Status: {activeCase.status}</span>
            </div>
            <h1 className="text-xl font-bold tracking-tight text-[#fafaf9] mt-0.5">
              {activeCase.name}
            </h1>
          </div>
        </div>

        {/* Quick jump tabs */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setCurrentPage('evidence')}
            className="px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] text-xs transition-colors flex items-center gap-1.5 border border-[#38312d] cursor-pointer"
          >
            <FileCheck2 className="w-3.5 h-3.5 text-[#f95721]" />
            <span>Evidence ({activeCaseEvidence.length})</span>
          </button>
          <button
            onClick={() => setCurrentPage('timeline')}
            className="px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] text-xs transition-colors flex items-center gap-1.5 border border-[#38312d] cursor-pointer"
          >
            <Clock className="w-3.5 h-3.5 text-[#f95721]" />
            <span>Timeline</span>
          </button>
          <button
            onClick={() => setCurrentPage('attack_graph')}
            className="px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] text-xs transition-colors flex items-center gap-1.5 border border-[#38312d] cursor-pointer"
          >
            <GitBranch className="w-3.5 h-3.5 text-[#f95721]" />
            <span>Attack Graph</span>
          </button>
          <button
            onClick={() => setCurrentPage('reports')}
            className="px-3.5 py-1.5 rounded-lg bg-[#f95721] hover:bg-[#ea580c] text-white font-semibold text-xs transition-all flex items-center gap-1.5 shadow-[0_0_12px_rgba(249,87,33,0.3)] cursor-pointer"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Forensic Report</span>
          </button>
        </div>
      </div>

      {/* Main Metadata Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* Left Column: Scope & Description (2 cols) */}
        <div className="md:col-span-2 space-y-6">
          
          {/* Executive Overview Card */}
          <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-5 space-y-3 shadow-xl backdrop-blur-xl">
            <h3 className="text-xs font-semibold text-[#fafaf9] uppercase font-mono border-b border-[#282321] pb-2 tracking-wider">
              Case Scope & Narrative Summary
            </h3>
            <p className="text-xs text-[#d6d3d1] leading-relaxed whitespace-pre-line">
              {activeCase.description}
            </p>

            {activeCase.tags && activeCase.tags.length > 0 && (
              <div className="pt-2 flex flex-wrap items-center gap-1.5 border-t border-[#282321]">
                <Tag className="w-3.5 h-3.5 text-[#78716c]" />
                {activeCase.tags.map((t) => (
                  <span
                    key={t}
                    className="text-[11px] font-mono text-[#f95721] bg-[#2a140d] border border-[#ea580c]/30 px-2 py-0.5 rounded font-medium"
                  >
                    #{t}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Evidence Files Summary Table */}
          <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-5 space-y-3 shadow-xl backdrop-blur-xl">
            <div className="flex items-center justify-between border-b border-[#282321] pb-2">
              <h3 className="text-xs font-semibold text-[#fafaf9] uppercase font-mono flex items-center gap-2 tracking-wider">
                <FileCheck2 className="w-3.5 h-3.5 text-[#f95721]" />
                <span>Associated Evidence Files ({activeCaseEvidence.length})</span>
              </h3>
              <button
                onClick={() => setCurrentPage('evidence')}
                className="text-xs text-[#f95721] hover:text-[#fb923c] hover:underline font-mono cursor-pointer"
              >
                + Ingest More
              </button>
            </div>

            <div className="space-y-2">
              {activeCaseEvidence.map((ev) => (
                <div
                  key={ev.id}
                  className="p-3 bg-[#100f0e] border border-[#282321] rounded-xl text-xs space-y-1.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="font-semibold text-[#fafaf9] font-mono flex items-center gap-2">
                      <span>{ev.filename}</span>
                      <span className="text-[10px] font-normal uppercase text-[#a8a29e] px-1.5 py-0.5 bg-[#25201e] rounded border border-[#38312d]">
                        {ev.parser_used}
                      </span>
                    </div>
                    <span className="text-[#86efac] font-mono text-[11px] font-semibold">
                      {ev.status} ({ev.event_count} events)
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-[#78716c] pt-1 border-t border-[#1c1917]">
                    <span className="truncate max-w-sm">SHA-256: {ev.sha256_hash}</span>
                    <span>Uploaded by {ev.uploader_name}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Detections Summary */}
          <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-5 space-y-3 shadow-xl backdrop-blur-xl">
            <div className="flex items-center justify-between border-b border-[#282321] pb-2">
              <h3 className="text-xs font-semibold text-[#fafaf9] uppercase font-mono flex items-center gap-2 tracking-wider">
                <ShieldAlert className="w-3.5 h-3.5 text-[#f95721]" />
                <span>Reconstructed Threat Findings ({activeCaseDetections.length})</span>
              </h3>
              <button
                onClick={() => setCurrentPage('detections')}
                className="text-xs text-[#f95721] hover:text-[#fb923c] hover:underline font-mono cursor-pointer"
              >
                View Rules Engine
              </button>
            </div>

            <div className="space-y-2">
              {activeCaseDetections.map((det) => (
                <div
                  key={det.id}
                  className="p-3 bg-[#100f0e] border border-[#282321] rounded-xl text-xs space-y-1"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <SeverityTag severity={det.severity} />
                      <span className="font-semibold text-[#fafaf9]">{det.rule_name}</span>
                    </div>
                    <MitreBadge techniqueId={det.mitre_technique} tactic={det.mitre_tactic} />
                  </div>
                  <p className="text-[#a8a29e] text-[11px] leading-relaxed">
                    {det.description}
                  </p>
                </div>
              ))}
            </div>
          </div>

        </div>

        {/* Right Column: Case Metadata & Chain of Custody (1 col) */}
        <div className="space-y-6">
          
          {/* Metadata Card */}
          <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-5 space-y-4 shadow-xl backdrop-blur-xl">
            <h3 className="text-xs font-semibold text-[#fafaf9] uppercase font-mono border-b border-[#282321] pb-2 tracking-wider">
              Forensic Metadata
            </h3>

            <div className="space-y-3 text-xs font-mono">
              <div>
                <span className="text-[#78716c] block text-[11px]">Investigation Lead / Owner</span>
                <span className="text-[#fafaf9] font-semibold">{activeCase.owner_name}</span>
              </div>

              <div>
                <span className="text-[#78716c] block text-[11px]">Investigation Status</span>
                <select
                  value={activeCase.status}
                  onChange={(e) => updateCaseStatus(activeCase.id, e.target.value as any)}
                  className="mt-1 bg-[#0d0c0c] border border-[#2b2523] rounded-lg px-2.5 py-1 text-[#fafaf9] text-xs focus:outline-none focus:border-[#f95721] cursor-pointer"
                >
                  <option value="Open">Open</option>
                  <option value="In Progress">In Progress</option>
                  <option value="Closed">Closed</option>
                </select>
              </div>

              <div>
                <span className="text-[#78716c] block text-[11px]">Case Created (UTC)</span>
                <span className="text-[#a8a29e]">{activeCase.created_at.replace('T', ' ').replace('Z', '')}</span>
              </div>

              <div>
                <span className="text-[#78716c] block text-[11px]">Last Updated (UTC)</span>
                <span className="text-[#a8a29e]">{activeCase.updated_at.replace('T', ' ').replace('Z', '')}</span>
              </div>

              {activeCase.time_start && (
                <div>
                  <span className="text-[#78716c] block text-[11px]">Incident Timeframe</span>
                  <span className="text-[#f95721]">
                    {activeCase.time_start.slice(0, 16).replace('T', ' ')} → {activeCase.time_end?.slice(0, 16).replace('T', ' ')}
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Assigned Personnel (FR-CASE-7) */}
          <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-5 space-y-3 shadow-xl backdrop-blur-xl">
            <h3 className="text-xs font-semibold text-[#fafaf9] uppercase font-mono border-b border-[#282321] pb-2 flex items-center gap-1.5 tracking-wider">
              <Users className="w-3.5 h-3.5 text-[#f95721]" />
              <span>Assigned Personnel</span>
            </h3>

            <div className="space-y-2">
              {(activeCase.assigned_users || []).map((name: string, i: number) => (
                <div key={i} className="flex items-center gap-2.5 p-2 bg-[#100f0e] border border-[#282321] rounded-xl text-xs">
                  <div className="w-6 h-6 rounded-lg bg-[#24130d] border border-[#ea580c]/40 flex items-center justify-center text-[11px] text-[#f95721] font-bold">
                    {name.charAt(0)}
                  </div>
                  <span className="text-[#fafaf9] font-medium">{name}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Chain of Custody Quick Access */}
          <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-5 space-y-3 shadow-xl backdrop-blur-xl">
            <h3 className="text-xs font-semibold text-[#fafaf9] uppercase font-mono border-b border-[#282321] pb-2 flex items-center gap-1.5 tracking-wider">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#f95721]" />
              <span>Chain of Custody</span>
            </h3>
            <p className="text-xs text-[#a8a29e] leading-relaxed">
              Every evidence upload, hash computation, inspection, and report export is cryptographically recorded in the tamper-evident audit ledger.
            </p>
            <button
              onClick={() => setCurrentPage('audit_log')}
              className="w-full py-2 bg-[#24130d] hover:bg-[#341a12] border border-[#ea580c]/40 text-[#f95721] font-mono text-xs rounded-xl transition-all cursor-pointer font-semibold shadow-sm"
            >
              Inspect Audit Log Trail →
            </button>
          </div>

        </div>

      </div>

    </div>
  );
};
