import React from 'react';
import { ExternalLink, Network } from 'lucide-react';
import { useApp } from '../store';

interface ThreatMapProps {
  onOpenReport?: () => void;
}

export const ThreatMap: React.FC<ThreatMapProps> = ({ onOpenReport }) => {
  const { activeCaseGraph, activeCase } = useApp();
  const addresses = activeCaseGraph.nodes
    .filter(node => node.type === 'ip' && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(node.label))
    .sort((left, right) => left.label.localeCompare(right.label, undefined, { numeric: true }));

  return (
    <section className="rounded-2xl bg-[#161413]/90 border border-[#2b2523] p-5 space-y-4 shadow-xl">
      <div className="flex items-center gap-2 text-[#fafaf9]">
        <Network className="w-4 h-4 text-[#f95721]" />
        <h2 className="text-sm font-semibold">Observed IP addresses</h2>
      </div>
      <p className="text-xs text-[#a8a29e]">Addresses recorded in the selected case: {activeCase?.name || 'No case selected'}.</p>
      {addresses.length ? (
        <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {addresses.map(address => (
            <li key={address.id} className="flex items-center justify-between rounded-lg bg-[#0f0e0d] border border-[#2b2523] px-3 py-2 text-xs font-mono">
              <span className="text-[#fafaf9]">{address.label}</span>
              <span className="text-[#a8a29e]">{address.event_count} events</span>
            </li>
          ))}
        </ul>
      ) : <div className="text-xs text-[#78716c]">No IP addresses are available for this case.</div>}
      <div className="flex items-center justify-between gap-3 border-t border-[#2b2523] pt-3">
        <span className="text-[11px] text-[#78716c]">Case evidence only; no geographic attribution.</span>
        <button onClick={onOpenReport} className="px-3 py-2 rounded-lg border border-[#2e2926] text-xs text-[#fafaf9] flex items-center gap-2">
          Forensic report <ExternalLink className="w-3.5 h-3.5 text-[#f95721]" />
        </button>
      </div>
    </section>
  );
};
