import React, { useState, useMemo } from 'react';
import { NormalizedEvent } from '../types';
import { SeverityTag } from './SeverityTag';
import { MitreBadge } from './MitreBadge';
import { RawEventModal } from './RawEventModal';
import { Eye, ArrowUpDown, ChevronLeft, ChevronRight } from 'lucide-react';

interface EventTableProps {
  events: NormalizedEvent[];
}

export const EventTable: React.FC<EventTableProps> = ({ events }) => {
  const [selectedEvent, setSelectedEvent] = useState<NormalizedEvent | null>(null);
  const [sortField, setSortField] = useState<'timestamp' | 'severity' | 'host'>('timestamp');
  const [sortAsc, setSortAsc] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const sortedEvents = useMemo(() => {
    return [...events].sort((a, b) => {
      let valA: any = a[sortField];
      let valB: any = b[sortField];

      if (sortField === 'timestamp') {
        valA = new Date(valA).getTime();
        valB = new Date(valB).getTime();
      }

      if (valA < valB) return sortAsc ? -1 : 1;
      if (valA > valB) return sortAsc ? 1 : -1;
      return 0;
    });
  }, [events, sortField, sortAsc]);

  const totalPages = Math.ceil(sortedEvents.length / pageSize) || 1;
  const pagedEvents = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return sortedEvents.slice(start, start + pageSize);
  }, [sortedEvents, currentPage, pageSize]);

  const toggleSort = (field: 'timestamp' | 'severity' | 'host') => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(true);
    }
  };

  return (
    <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl overflow-hidden flex flex-col shadow-xl backdrop-blur-xl">
      
      {/* Table Container */}
      <div className="overflow-x-auto min-h-[300px]">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-[#282321] bg-[#100f0e] text-[#a8a29e] font-mono text-[11px] select-none">
              <th className="py-2.5 px-3 w-10 text-center">#</th>
              <th
                onClick={() => toggleSort('timestamp')}
                className="py-2.5 px-3 cursor-pointer hover:text-[#fafaf9] transition-colors"
              >
                <div className="flex items-center gap-1">
                  <span>Timestamp (UTC)</span>
                  <ArrowUpDown className="w-3 h-3 text-[#78716c]" />
                </div>
              </th>
              <th
                onClick={() => toggleSort('severity')}
                className="py-2.5 px-3 cursor-pointer hover:text-[#fafaf9] transition-colors w-24"
              >
                <div className="flex items-center gap-1">
                  <span>Severity</span>
                  <ArrowUpDown className="w-3 h-3 text-[#78716c]" />
                </div>
              </th>
              <th
                onClick={() => toggleSort('host')}
                className="py-2.5 px-3 cursor-pointer hover:text-[#fafaf9] transition-colors"
              >
                <div className="flex items-center gap-1">
                  <span>Host</span>
                  <ArrowUpDown className="w-3 h-3 text-[#78716c]" />
                </div>
              </th>
              <th className="py-2.5 px-3">User / Actor</th>
              <th className="py-2.5 px-3">Network Flow (Src → Dst)</th>
              <th className="py-2.5 px-3">Normalized Action & Command</th>
              <th className="py-2.5 px-3">MITRE ATT&CK</th>
              <th className="py-2.5 px-3 w-16 text-center">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#282321]">
            {pagedEvents.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-12 text-center text-[#78716c]">
                  <div className="space-y-1">
                    <p className="font-medium text-[#a8a29e]">No forensic events found</p>
                    <p className="text-xs">Try adjusting active filters or upload evidence files for this case.</p>
                  </div>
                </td>
              </tr>
            ) : (
              pagedEvents.map((evt, idx) => {
                const rowIndex = (currentPage - 1) * pageSize + idx + 1;
                return (
                  <tr
                    key={evt.id}
                    onClick={() => setSelectedEvent(evt)}
                    className={`cursor-pointer transition-colors group ${
                      evt.is_attack_path
                        ? 'bg-[#29130d]/50 hover:bg-[#341810]/70'
                        : 'hover:bg-[#1a1716]'
                    }`}
                  >
                    <td className="py-2 px-3 text-center font-mono text-[#78716c] tabular-nums">
                      {rowIndex}
                    </td>

                    <td className="py-2 px-3 font-mono text-[#d6d3d1] tabular-nums whitespace-nowrap">
                      {evt.timestamp.replace('T', ' ').replace('Z', '')}
                    </td>

                    <td className="py-2 px-3 whitespace-nowrap">
                      <SeverityTag severity={evt.severity} />
                    </td>

                    <td className="py-2 px-3 font-mono text-[#fafaf9] font-medium whitespace-nowrap">
                      {evt.host}
                    </td>

                    <td className="py-2 px-3 font-mono text-[#d6d3d1] whitespace-nowrap">
                      {evt.user !== 'unknown' ? evt.user : <span className="text-[#57534e]">-</span>}
                    </td>

                    <td className="py-2 px-3 font-mono text-[#a8a29e] whitespace-nowrap">
                      {evt.src_ip ? (
                        <span>
                          {evt.src_ip} {evt.dst_ip ? `→ ${evt.dst_ip}` : ''}
                        </span>
                      ) : (
                        <span className="text-[#57534e]">-</span>
                      )}
                    </td>

                    <td className="py-2 px-3 text-[#fafaf9] max-w-md">
                      <div className="truncate font-medium group-hover:text-[#f95721] transition-colors" title={evt.action}>
                        {evt.action}
                      </div>
                      {evt.process && (
                        <div className="text-[11px] font-mono text-[#a8a29e] truncate">
                          bin: {evt.process}
                        </div>
                      )}
                    </td>

                    <td className="py-2 px-3 whitespace-nowrap">
                      {evt.mitre_technique ? (
                        <MitreBadge techniqueId={evt.mitre_technique} tactic={evt.mitre_tactic} showLink={false} />
                      ) : (
                        <span className="text-[#57534e]">-</span>
                      )}
                    </td>

                    <td className="py-2 px-3 text-center">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(evt);
                        }}
                        className="p-1.5 rounded text-[#a8a29e] hover:text-[#f95721] hover:bg-[#25201e] transition-colors cursor-pointer"
                        title="View raw log and normalized event schema"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-[#100f0e] border-t border-[#282321] text-xs">
        <div className="flex items-center gap-2">
          <span className="text-[#a8a29e]">Rows per page:</span>
          <select
            value={pageSize}
            onChange={(e) => {
              setPageSize(Number(e.target.value));
              setCurrentPage(1);
            }}
            className="bg-[#0d0c0c] border border-[#2b2523] rounded-lg px-2 py-1 text-[#fafaf9] text-xs focus:outline-none focus:border-[#f95721] cursor-pointer"
          >
            <option value={15}>15</option>
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
          <span className="font-mono text-[#78716c] tabular-nums">
            Showing {(currentPage - 1) * pageSize + 1}–{Math.min(currentPage * pageSize, sortedEvents.length)} of {sortedEvents.length}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            className="p-1.5 rounded-lg bg-[#241e1b] border border-[#38312d] text-[#d6d3d1] hover:bg-[#342a26] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
          </button>
          
          <span className="font-mono text-[#d6d3d1]">
            Page {currentPage} of {totalPages}
          </span>

          <button
            onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
            disabled={currentPage >= totalPages}
            className="p-1.5 rounded-lg bg-[#241e1b] border border-[#38312d] text-[#d6d3d1] hover:bg-[#342a26] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
          >
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Modal Inspector */}
      {selectedEvent && (
        <RawEventModal event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      )}

    </div>
  );
};
