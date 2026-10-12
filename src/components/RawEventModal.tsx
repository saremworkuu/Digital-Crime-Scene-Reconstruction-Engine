import React, { useState } from 'react';
import { NormalizedEvent } from '../types';
import { SeverityTag } from './SeverityTag';
import { MitreBadge } from './MitreBadge';
import { X, Copy, Check, Terminal, FileCode } from 'lucide-react';

interface RawEventModalProps {
  event: NormalizedEvent | null;
  onClose: () => void;
}

export const RawEventModal: React.FC<RawEventModalProps> = ({ event, onClose }) => {
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);

  if (!event) return null;

  const handleCopyRaw = () => {
    navigator.clipboard.writeText(event.raw);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(event, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-3xl bg-[#161413] border border-[#2b2523] rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#282321] bg-[#12100f]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#24130d] border border-[#ea580c]/40 flex items-center justify-center text-[#f95721]">
              <Terminal className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-[#fafaf9]">Forensic Event Inspector</h3>
                <SeverityTag severity={event.severity} />
                {event.is_attack_path && (
                  <span className="text-[11px] font-mono text-[#f95721] font-semibold uppercase">
                    [Attack Path]
                  </span>
                )}
              </div>
              <div className="text-xs text-[#a8a29e] font-mono tabular-nums mt-0.5">
                ID: {event.id} · Timestamp: {event.timestamp}
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[#a8a29e] hover:text-[#fafaf9] p-1.5 rounded-lg hover:bg-[#25201e] transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-5 text-xs text-[#d6d3d1]">
          
          {/* Action & MITRE Card */}
          <div className="bg-[#100f0e] border border-[#282321] rounded-xl p-4 space-y-2">
            <div className="text-[#a8a29e] text-[11px] uppercase font-mono">Normalized Action & Technique</div>
            <div className="text-sm font-semibold text-[#fafaf9]">{event.action}</div>
            
            {event.mitre_technique && (
              <div className="pt-2 border-t border-[#25201e] flex items-center gap-3">
                <MitreBadge techniqueId={event.mitre_technique} tactic={event.mitre_tactic} />
                {event.attack_phase && (
                  <span className="text-xs font-mono text-[#a8a29e]">
                    Phase: <strong className="text-[#fafaf9]">{event.attack_phase}</strong>
                  </span>
                )}
              </div>
            )}
          </div>

          {/* Key Attributes Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-[#100f0e] border border-[#282321] rounded-xl p-2.5">
              <div className="text-[#78716c] font-mono text-[10px] uppercase">Host System</div>
              <div className="font-mono text-[#fafaf9] font-semibold truncate mt-0.5">{event.host || '-'}</div>
            </div>

            <div className="bg-[#100f0e] border border-[#282321] rounded-xl p-2.5">
              <div className="text-[#78716c] font-mono text-[10px] uppercase">Account / User</div>
              <div className="font-mono text-[#fafaf9] font-semibold truncate mt-0.5">{event.user || '-'}</div>
            </div>

            <div className="bg-[#100f0e] border border-[#282321] rounded-xl p-2.5">
              <div className="text-[#78716c] font-mono text-[10px] uppercase">Source IP / Port</div>
              <div className="font-mono text-[#fafaf9] truncate mt-0.5">
                {event.src_ip ? `${event.src_ip}${event.src_port ? `:${event.src_port}` : ''}` : '-'}
              </div>
            </div>

            <div className="bg-[#100f0e] border border-[#282321] rounded-xl p-2.5">
              <div className="text-[#78716c] font-mono text-[10px] uppercase">Destination IP / Port</div>
              <div className="font-mono text-[#fafaf9] truncate mt-0.5">
                {event.dst_ip ? `${event.dst_ip}${event.dst_port ? `:${event.dst_port}` : ''}` : '-'}
              </div>
            </div>

            <div className="bg-[#100f0e] border border-[#282321] rounded-xl p-2.5">
              <div className="text-[#78716c] font-mono text-[10px] uppercase">Parser Source</div>
              <div className="font-mono text-[#f95721] font-semibold mt-0.5">{event.source_type}</div>
            </div>

            <div className="bg-[#100f0e] border border-[#282321] rounded-xl p-2.5">
              <div className="text-[#78716c] font-mono text-[10px] uppercase">Process / Binary</div>
              <div className="font-mono text-[#fafaf9] truncate mt-0.5">{event.process || '-'}</div>
            </div>

            <div className="bg-[#100f0e] border border-[#282321] rounded-xl p-2.5">
              <div className="text-[#78716c] font-mono text-[10px] uppercase">Protocol</div>
              <div className="font-mono text-[#fafaf9] mt-0.5">{event.protocol || '-'}</div>
            </div>

            <div className="bg-[#100f0e] border border-[#282321] rounded-xl p-2.5">
              <div className="text-[#78716c] font-mono text-[10px] uppercase">Outcome</div>
              <div className={`font-mono uppercase font-semibold mt-0.5 ${
                event.outcome === 'success' ? 'text-[#86efac]' : event.outcome === 'failure' ? 'text-[#fca5a5]' : 'text-[#a8a29e]'
              }`}>
                {event.outcome}
              </div>
            </div>
          </div>

          {/* Raw Log Line (C-1 & FR-TIME-3: Rendered strictly as plain text, no HTML execution) */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[11px] font-mono text-[#a8a29e]">
              <span className="flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-[#78716c]" />
                Raw Source Log Line (Evidence Ref: {event.evidence_id})
              </span>
              <button
                onClick={handleCopyRaw}
                className="flex items-center gap-1 text-[#f95721] hover:text-[#fb923c] py-0.5 px-2 rounded-lg hover:bg-[#25201e] transition-colors cursor-pointer"
              >
                {copiedRaw ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                {copiedRaw ? 'Copied' : 'Copy Raw'}
              </button>
            </div>
            <pre className="p-3.5 bg-[#0d0c0c] border border-[#282321] rounded-xl font-mono text-xs text-[#e7e5e4] overflow-x-auto whitespace-pre-wrap break-all selection:bg-[#f95721]/30">
              {event.raw}
            </pre>
          </div>

          {/* Normalized JSON Representation */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[11px] font-mono text-[#a8a29e]">
              <span>Normalized Schema Representation (JSON)</span>
              <button
                onClick={handleCopyJson}
                className="flex items-center gap-1 text-[#f95721] hover:text-[#fb923c] py-0.5 px-2 rounded-lg hover:bg-[#25201e] transition-colors cursor-pointer"
              >
                {copiedJson ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                {copiedJson ? 'Copied' : 'Copy JSON'}
              </button>
            </div>
            <pre className="p-3.5 bg-[#0d0c0c] border border-[#282321] rounded-xl font-mono text-[11px] text-[#a8a29e] max-h-48 overflow-y-auto overflow-x-auto selection:bg-[#f95721]/30">
              {JSON.stringify(event, null, 2)}
            </pre>
          </div>

        </div>

      </div>
    </div>
  );
};
