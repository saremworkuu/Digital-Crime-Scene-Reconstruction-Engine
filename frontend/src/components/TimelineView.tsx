import React, { useState, useMemo } from 'react';
import { NormalizedEvent } from '../types';
import { SeverityTag } from './SeverityTag';
import { MitreBadge } from './MitreBadge';
import { RawEventModal } from './RawEventModal';
import { Download, Clock } from 'lucide-react';
import { useApp } from '../store';

interface TimelineViewProps {
  events: NormalizedEvent[];
}

export const TimelineView: React.FC<TimelineViewProps> = ({ events }) => {
  const { logAuditAction, activeCaseId, theme } = useApp();
  const isLight = theme === 'light';
  const [selectedEvent, setSelectedEvent] = useState<NormalizedEvent | null>(null);
  const [timeZoomLevel, setTimeZoomLevel] = useState<'all' | 'hours' | 'dense'>('all');
  const [searchFilter] = useState('');

  // Sort chronological ascending (FR-TIME-1)
  const sortedEvents = useMemo(() => {
    return [...events].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );
  }, [events]);

  const filteredEvents = useMemo(() => {
    if (!searchFilter.trim()) return sortedEvents;
    const q = searchFilter.toLowerCase();
    return sortedEvents.filter(
      e =>
        e.action.toLowerCase().includes(q) ||
        e.host.toLowerCase().includes(q) ||
        e.user.toLowerCase().includes(q) ||
        (e.src_ip && e.src_ip.includes(q)) ||
        (e.mitre_technique && e.mitre_technique.toLowerCase().includes(q))
    );
  }, [sortedEvents, searchFilter]);

  // Export Timeline as CSV or JSON (FR-TIME-6)
  const exportTimeline = (format: 'csv' | 'json') => {
    let content = '';
    let mimeType = 'text/plain';
    const filename = `dcsre_${activeCaseId}_timeline.${format}`;

    if (format === 'json') {
      content = JSON.stringify(filteredEvents, null, 2);
      mimeType = 'application/json';
    } else {
      const headers = ['Timestamp', 'Severity', 'Host', 'User', 'Action', 'Src_IP', 'Dst_IP', 'MITRE', 'Is_Attack_Path', 'Raw'];
      const rows = filteredEvents.map(e => [
        `"${e.timestamp}"`,
        `"${e.severity}"`,
        `"${e.host}"`,
        `"${e.user}"`,
        `"${e.action.replace(/"/g, '""')}"`,
        `"${e.src_ip || ''}"`,
        `"${e.dst_ip || ''}"`,
        `"${e.mitre_technique || ''}"`,
        e.is_attack_path ? 'TRUE' : 'FALSE',
        `"${e.raw.replace(/"/g, '""')}"`
      ]);
      content = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
      mimeType = 'text/csv';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);

    logAuditAction('TIMELINE_EXPORTED', 'case', activeCaseId, { format, event_count: filteredEvents.length });
  };

  const startTime = sortedEvents.length > 0 ? sortedEvents[0].timestamp : null;
  const endTime = sortedEvents.length > 0 ? sortedEvents[sortedEvents.length - 1].timestamp : null;

  return (
    <div className="space-y-4">
      
      {/* Timeline Controls & Metas */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 bg-[#161413]/90 border border-[#2b2523] rounded-2xl backdrop-blur-xl">
        
        {/* Bounds & Summary */}
        <div className="flex items-center gap-2 text-xs">
          <Clock className="w-4 h-4 text-[#f95721] shrink-0" />
          <div className="font-mono text-[#d6d3d1]">
            {startTime && endTime ? (
              <span>
                <strong className="text-[#fafaf9]">{startTime.slice(0, 16).replace('T', ' ')}</strong> to{' '}
                <strong className="text-[#fafaf9]">{endTime.slice(0, 16).replace('T', ' ')}</strong> UTC
              </span>
            ) : (
              <span>No chronological events loaded</span>
            )}
          </div>
          <span className="text-[#57534e]">·</span>
          <span className="font-mono text-[#a8a29e] tabular-nums">
            {filteredEvents.length} chronological milestones
          </span>
        </div>

        {/* View Options & Export */}
        <div className="flex items-center gap-2 text-xs">
          
          {/* Zoom Level Switcher */}
          <div className="flex items-center p-0.5 bg-[#0d0c0c] border border-[#2b2523] rounded-lg text-xs font-mono">
            <button
              onClick={() => setTimeZoomLevel('all')}
              className={`px-2.5 py-1 rounded-md transition-all cursor-pointer ${
                timeZoomLevel === 'all'
                  ? 'bg-[#2a140d] text-[#f95721] font-semibold border border-[#ea580c]/50 shadow-sm'
                  : 'text-[#a8a29e] hover:text-[#fafaf9]'
              }`}
            >
              Overview
            </button>
            <button
              onClick={() => setTimeZoomLevel('hours')}
              className={`px-2.5 py-1 rounded-md transition-all cursor-pointer ${
                timeZoomLevel === 'hours'
                  ? 'bg-[#2a140d] text-[#f95721] font-semibold border border-[#ea580c]/50 shadow-sm'
                  : 'text-[#a8a29e] hover:text-[#fafaf9]'
              }`}
            >
              Detailed
            </button>
          </div>

          {/* Export Dropdown */}
          <button
            onClick={() => exportTimeline('csv')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] border border-[#38312d] transition-all font-mono text-xs cursor-pointer shadow-sm"
            title="Export filtered timeline to CSV"
          >
            <Download className="w-3.5 h-3.5 text-[#f95721]" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={() => exportTimeline('json')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] border border-[#38312d] transition-all font-mono text-xs cursor-pointer shadow-sm"
            title="Export filtered timeline to JSON"
          >
            <Download className="w-3.5 h-3.5 text-[#f95721]" />
            <span>JSON</span>
          </button>

        </div>

      </div>

      {/* Visual Interactive Chronological Timeline Stream */}
      <div className="relative pl-6 sm:pl-8 before:absolute before:left-2 sm:before:left-3 before:top-3 before:bottom-3 before:w-0.5 before:bg-[#2b2523] space-y-4">
        {filteredEvents.map((evt) => {
          const isCritical = evt.severity === 'critical';
          const isHigh = evt.severity === 'high';
          const isAttack = evt.is_attack_path;

          return (
            <div
              key={evt.id}
              onClick={() => setSelectedEvent(evt)}
              className="relative group cursor-pointer"
            >
              {/* Timeline Node Marker */}
              <div
                className={`absolute -left-6 sm:-left-8 top-3.5 -translate-x-1/2 w-4 h-4 rounded-full border-2 transition-transform group-hover:scale-125 flex items-center justify-center ${
                  isCritical
                    ? 'border-red-500 bg-red-950 text-red-400 shadow-sm shadow-red-500/50'
                    : isHigh
                    ? 'border-[#ea580c] bg-[#2a140d] text-[#f95721]'
                    : isAttack
                    ? 'border-[#f95721] bg-[#2a140d] text-[#f95721] shadow-[0_0_8px_rgba(249,87,33,0.5)]'
                    : 'border-[#38312d] bg-[#1a1716] text-[#78716c]'
                }`}
              >
                <div
                  className={`w-1.5 h-1.5 rounded-full ${
                    isCritical
                      ? 'bg-red-400'
                      : isHigh || isAttack
                      ? 'bg-[#f95721]'
                      : 'bg-[#78716c]'
                  }`}
                />
              </div>

              {/* Event Card Content */}
              <div
                className={`p-4 rounded-2xl border transition-all ${
                  isLight
                    ? isAttack
                      ? 'bg-[#fff7ed] border-[#ea580c] shadow-sm hover:border-[#f95721]'
                      : 'bg-white border-[#e4e4e7] hover:border-[#d4d4d8] shadow-sm'
                    : isAttack
                    ? 'bg-[#1f1511]/90 border-[#ea580c] hover:border-[#f95721] shadow-[0_0_15px_rgba(249,87,33,0.15)]'
                    : 'bg-[#161413]/90 border-[#2b2523] hover:border-[#3a322e]'
                }`}
              >
                {/* Meta Top Row: Timestamp, Severity, Phase */}
                <div className="flex flex-wrap items-center justify-between gap-2 mb-2 text-xs">
                  <div className={`flex items-center gap-2 font-mono ${isLight ? 'text-[#334155]' : 'text-[#d6d3d1]'}`}>
                    <span className="font-semibold text-[#f95721]">
                      {evt.timestamp.replace('T', ' ').replace('Z', '')}
                    </span>
                    <span className={isLight ? 'text-[#94a3b8]' : 'text-[#57534e]'}>·</span>
                    <span className={isLight ? 'text-[#64748b]' : 'text-[#a8a29e]'}>{evt.host}</span>
                    {evt.user && evt.user !== 'unknown' && (
                      <>
                        <span className={isLight ? 'text-[#94a3b8]' : 'text-[#57534e]'}>·</span>
                        <span className={`${isLight ? 'text-[#0f172a]' : 'text-[#fafaf9]'} font-medium`}>user: {evt.user}</span>
                      </>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    {evt.attack_phase && (
                      <span className={`text-[11px] font-mono font-medium px-2 py-0.5 rounded border ${
                        isLight
                          ? 'text-[#c2410c] bg-[#ffedd5] border-[#fed7aa]'
                          : 'text-[#d6d3d1] bg-[#25201e] border-[#38312d]'
                      }`}>
                        {evt.attack_phase}
                      </span>
                    )}
                    <SeverityTag severity={evt.severity} />
                  </div>
                </div>

                {/* Primary Action Description */}
                <div className={`text-sm font-semibold transition-colors ${
                  isLight
                    ? 'text-[#0f172a] group-hover:text-[#ea580c]'
                    : 'text-[#fafaf9] group-hover:text-[#f95721]'
                }`}>
                  {evt.action}
                </div>

                {/* Network / Execution details */}
                <div className={`mt-2 flex flex-wrap items-center gap-3 text-xs font-mono ${
                  isLight ? 'text-[#475569]' : 'text-[#a8a29e]'
                }`}>
                  {evt.src_ip && (
                    <span className={isLight ? 'text-[#334155]' : 'text-[#d6d3d1]'}>
                      Src: <strong className="text-[#f95721] font-normal">{evt.src_ip}</strong>
                      {evt.dst_ip && <span> → Dst: <strong className="text-[#f95721] font-normal">{evt.dst_ip}</strong></span>}
                      {evt.protocol && <span> ({evt.protocol})</span>}
                    </span>
                  )}
                  {evt.process && (
                    <span className={isLight ? 'text-[#334155]' : 'text-[#d6d3d1]'}>
                      Proc: <code className={`px-1.5 py-0.5 rounded border ${
                        isLight
                          ? 'text-[#0f172a] bg-[#f1f5f9] border-[#cbd5e1]'
                          : 'text-[#fafaf9] bg-[#0d0c0c] border-[#2b2523]'
                      }`}>{evt.process}</code>
                    </span>
                  )}
                </div>

                {/* MITRE ATT&CK Tagging */}
                {evt.mitre_technique && (
                  <div className={`mt-2.5 pt-2 border-t flex items-center justify-between ${
                    isLight ? 'border-[#e2e8f0]' : 'border-[#282321]'
                  }`}>
                    <MitreBadge techniqueId={evt.mitre_technique} tactic={evt.mitre_tactic} />
                    <span className={`text-[11px] font-mono ${
                      isLight ? 'text-[#64748b]' : 'text-[#78716c]'
                    }`}>Click to inspect raw log</span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Raw Event Inspection Modal */}
      {selectedEvent && (
        <RawEventModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}

    </div>
  );
};
