import React, { useState } from 'react';
import { ChevronDown, ChevronRight, ExternalLink, Network } from 'lucide-react';
import { useApp } from '../store';
import { isBenignExternalNode } from '../utils/graphNodes';
import { formatCaseNameWithId } from '../utils/caseDisplay';

interface ThreatMapProps {
  onOpenReport?: () => void;
}

export const ThreatMap: React.FC<ThreatMapProps> = ({ onOpenReport }) => {
  const { activeCaseGraph, activeCase, graphAttackPathOnly, setGraphAttackPathOnly } = useApp();
  const [expandBenign, setExpandBenign] = useState(false);

  const ipNodes = activeCaseGraph.nodes
    .filter(node => node.type === 'ip' && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(node.label))
    .sort((left, right) => left.label.localeCompare(right.label, undefined, { numeric: true }));

  const priorityIps = ipNodes.filter(node => !isBenignExternalNode(node));
  const benignExternalIps = ipNodes.filter(isBenignExternalNode);

  return (
    <section className="rounded-2xl bg-[#161413]/90 border border-[#2b2523] p-5 space-y-4 shadow-xl">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-[#fafaf9]">
          <Network className="w-4 h-4 text-[#f95721]" />
          <h2 className="text-sm font-semibold">Observed IP addresses</h2>
        </div>
        <label className="flex items-center gap-1.5 text-[11px] font-mono text-[#d6d3d1] cursor-pointer select-none">
          <input
            type="checkbox"
            checked={graphAttackPathOnly}
            onChange={(e) => setGraphAttackPathOnly(e.target.checked)}
            className="rounded border-[#38312d] bg-[#141211] accent-[#f95721] cursor-pointer"
          />
          <span>Attack path only</span>
        </label>
      </div>
      <p className="text-xs text-[#a8a29e]">Addresses recorded in the selected case: {activeCase ? formatCaseNameWithId(activeCase.name, activeCase.id) : 'No case selected'}.</p>

      {priorityIps.length > 0 ? (
        <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {priorityIps.map(address => (
            <li key={address.id} className="flex items-center justify-between rounded-lg bg-[#0f0e0d] border border-[#2b2523] px-3 py-2 text-xs font-mono">
              <span className="text-[#fafaf9]">{address.label}</span>
              <span className="text-[#a8a29e]">{address.event_count} events</span>
            </li>
          ))}
        </ul>
      ) : (
        <div className="text-xs text-[#78716c]">No attack-path IP addresses are available for this case.</div>
      )}

      {!graphAttackPathOnly && benignExternalIps.length > 0 && (
        <div className="rounded-xl border border-[#2b2523] bg-[#0f0e0d]">
          <button
            type="button"
            onClick={() => setExpandBenign(v => !v)}
            className="w-full flex items-center justify-between px-3 py-2 text-xs font-mono text-[#94a3b8] hover:text-[#fafaf9] cursor-pointer"
          >
            <span className="flex items-center gap-1.5">
              {expandBenign ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
              <span>Benign External IPs ({benignExternalIps.length})</span>
            </span>
            <span className="text-[11px]">
              {benignExternalIps.reduce((sum, n) => sum + (n.event_count || 0), 0)} events
            </span>
          </button>
          {expandBenign && (
            <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 p-3 pt-0 max-h-48 overflow-y-auto">
              {benignExternalIps.map(address => (
                <li key={address.id} className="flex items-center justify-between rounded-lg bg-[#161413] border border-[#26211f] px-2.5 py-1.5 text-[11px] font-mono">
                  <span className="text-[#cbd5e1]">{address.label}</span>
                  <span className="text-[#64748b]">{address.event_count} events</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className="flex items-center justify-between gap-3 border-t border-[#2b2523] pt-3">
        <span className="text-[11px] text-[#78716c]">Case evidence only; no geographic attribution.</span>
        <button onClick={onOpenReport} className="px-3 py-2 rounded-lg border border-[#2e2926] text-xs text-[#fafaf9] flex items-center gap-2 cursor-pointer">
          Forensic report <ExternalLink className="w-3.5 h-3.5 text-[#f95721]" />
        </button>
      </div>
    </section>
  );
};
