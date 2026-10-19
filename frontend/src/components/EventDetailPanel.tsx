import React from 'react';
import { ForensicEvent } from '../types';
import { X, Copy, Terminal } from 'lucide-react';
import { SeverityTag } from './SeverityTag';
import { MitreBadge } from './MitreBadge';

interface EventDetailPanelProps {
  event: ForensicEvent | null;
  onClose: () => void;
}

export const EventDetailPanel: React.FC<EventDetailPanelProps> = ({ event, onClose }) => {
  if (!event) return null;

  return (
    <div className="fixed inset-y-0 right-0 w-full max-w-xl bg-[#161413] border-l border-[#2b2523] shadow-2xl z-50 flex flex-col">
      <div className="flex items-center justify-between p-4 border-b border-[#282321] bg-[#12100f]">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-[#24130d] border border-[#ea580c]/40 flex items-center justify-center text-[#f95721]">
            <Terminal className="w-4 h-4" />
          </div>
          <h3 className="text-sm font-semibold text-[#fafaf9]">Forensic Event Detail</h3>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded-lg text-[#a8a29e] hover:text-[#fafaf9] hover:bg-[#25201e] transition-colors cursor-pointer"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-5 space-y-4 overflow-y-auto flex-1 text-xs text-[#d6d3d1]">
        <div className="flex items-center justify-between">
          <SeverityTag severity={event.severity} />
          {event.mitreTechnique && <MitreBadge techniqueId={event.mitreTechnique} tactic={event.mitreTactic} />}
        </div>

        <div className="space-y-1">
          <label className="text-[11px] font-medium text-[#a8a29e]">Timestamp (UTC)</label>
          <div className="font-mono text-[#f95721] p-2.5 bg-[#0d0c0c] rounded-xl border border-[#2b2523]">
            {event.timestamp}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-[11px] font-medium text-[#a8a29e]">Host</label>
            <div className="font-mono text-[#fafaf9] p-2.5 bg-[#0d0c0c] rounded-xl border border-[#2b2523]">
              {event.host}
            </div>
          </div>
          <div>
            <label className="text-[11px] font-medium text-[#a8a29e]">User</label>
            <div className="font-mono text-[#fafaf9] p-2.5 bg-[#0d0c0c] rounded-xl border border-[#2b2523]">
              {event.user}
            </div>
          </div>
        </div>

        <div className="space-y-1">
          <label className="text-[11px] font-medium text-[#a8a29e]">Action / Summary</label>
          <div className="text-[#fafaf9] p-2.5 bg-[#0d0c0c] rounded-xl border border-[#2b2523]">
            {event.action}
          </div>
        </div>

        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <label className="text-[11px] font-medium text-[#a8a29e]">Raw Log Line (Safe Text)</label>
            <button
              onClick={() => navigator.clipboard.writeText(event.raw)}
              className="text-[10px] text-[#f95721] hover:text-[#fb923c] flex items-center gap-1 font-mono cursor-pointer"
            >
              <Copy className="w-3 h-3" />
              <span>Copy</span>
            </button>
          </div>
          <pre className="font-mono text-[11px] text-[#d6d3d1] p-3.5 bg-[#0d0c0c] rounded-xl border border-[#2b2523] overflow-x-auto whitespace-pre-wrap select-all selection:bg-[#f95721]/30">
            {event.raw}
          </pre>
        </div>
      </div>
    </div>
  );
};
