import React, { useState, useMemo } from 'react';
import { useApp } from '../store';
import { FilterBar, FilterState } from '../components/FilterBar';
import { TimelineView } from '../components/TimelineView';
import { EventTable } from '../components/EventTable';
import { correlateAttackChains } from '../services/correlation';
import {
  Clock,
  Table,
  GitCommit,
  Sparkles
} from 'lucide-react';
import { SeverityTag } from '../components/SeverityTag';

export const Timeline: React.FC = () => {
  const { activeCase, activeCaseEvents } = useApp();

  const [activeTab, setActiveTab] = useState<'visual' | 'table'>('visual');
  const [filters, setFilters] = useState<FilterState>({
    search: '',
    severity: 'all',
    host: '',
    user: '',
    sourceType: '',
    onlyAttackPath: false
  });

  // Extract available unique filter options
  const availableHosts = useMemo(() => {
    const set = new Set<string>();
    activeCaseEvents.forEach(e => { if (e.host) set.add(e.host); });
    return Array.from(set).sort();
  }, [activeCaseEvents]);

  const availableUsers = useMemo(() => {
    const set = new Set<string>();
    activeCaseEvents.forEach(e => { if (e.user && e.user !== 'unknown') set.add(e.user); });
    return Array.from(set).sort();
  }, [activeCaseEvents]);

  const availableSourceTypes = useMemo(() => {
    const set = new Set<string>();
    activeCaseEvents.forEach(e => { if (e.source_type) set.add(e.source_type); });
    return Array.from(set).sort();
  }, [activeCaseEvents]);

  // Filter events according to active filter criteria
  const filteredEvents = useMemo(() => {
    return activeCaseEvents.filter(evt => {
      if (filters.severity !== 'all' && evt.severity !== filters.severity) return false;
      if (filters.host && evt.host !== filters.host) return false;
      if (filters.user && evt.user !== filters.user) return false;
      if (filters.sourceType && evt.source_type !== filters.sourceType) return false;
      if (filters.onlyAttackPath && !evt.is_attack_path) return false;

      if (filters.search.trim()) {
        const q = filters.search.toLowerCase();
        const matchesAction = evt.action.toLowerCase().includes(q);
        const matchesHost = evt.host.toLowerCase().includes(q);
        const matchesUser = evt.user.toLowerCase().includes(q);
        const matchesRaw = evt.raw.toLowerCase().includes(q);
        const matchesIp = (evt.src_ip && evt.src_ip.includes(q)) || (evt.dst_ip && evt.dst_ip.includes(q));
        const matchesMitre = evt.mitre_technique && evt.mitre_technique.toLowerCase().includes(q);

        if (!matchesAction && !matchesHost && !matchesUser && !matchesRaw && !matchesIp && !matchesMitre) {
          return false;
        }
      }

      return true;
    });
  }, [activeCaseEvents, filters]);

  // Compute automated correlated attack chains (FR-CORR-1, FR-CORR-2, FR-CORR-3)
  const attackChains = useMemo(() => {
    return correlateAttackChains(activeCaseEvents, 45);
  }, [activeCaseEvents]);

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[#282321]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#fafaf9] flex items-center gap-2.5">
            <Clock className="w-5 h-5 text-[#f95721]" />
            <span>Incident Chronological Timeline Reconstruction</span>
          </h1>
          <p className="text-xs text-[#a8a29e] mt-1">
            Normalized UTC timeline across all digital evidence sources for <strong className="text-[#fafaf9]">{activeCase?.name}</strong>
          </p>
        </div>

        {/* View Mode Switcher (Visual vs Table) */}
        <div className="flex items-center p-1 bg-[#0d0c0c] border border-[#2b2523] rounded-lg text-xs font-mono">
          <button
            onClick={() => setActiveTab('visual')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-all cursor-pointer ${
              activeTab === 'visual'
                ? 'bg-[#2a140d] text-[#f95721] font-semibold border border-[#ea580c]/50 shadow-sm'
                : 'text-[#a8a29e] hover:text-[#fafaf9]'
            }`}
          >
            <GitCommit className="w-3.5 h-3.5" />
            <span>Visual Timeline</span>
          </button>
          <button
            onClick={() => setActiveTab('table')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-all cursor-pointer ${
              activeTab === 'table'
                ? 'bg-[#2a140d] text-[#f95721] font-semibold border border-[#ea580c]/50 shadow-sm'
                : 'text-[#a8a29e] hover:text-[#fafaf9]'
            }`}
          >
            <Table className="w-3.5 h-3.5" />
            <span>Dense Event Table</span>
          </button>
        </div>
      </div>

      {/* Correlated Attack Chains Highlight Banner (FR-CORR-1..3) */}
      {attackChains.length > 0 && (
        <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-5 space-y-3.5 shadow-xl backdrop-blur-xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#f95721]" />
              <h3 className="text-xs font-semibold text-[#fafaf9] uppercase font-mono tracking-wider">
                Automated Correlation Engine: {attackChains.length} Reconstructed Attack Chains
              </h3>
            </div>
            <span className="text-[11px] font-mono text-[#a8a29e]">
              Confidence Score ≥ 0.70 (FR-CORR-3)
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {attackChains.map((chain) => (
              <div
                key={chain.id}
                className="p-3.5 bg-[#100f0e] border border-[#282321] rounded-xl text-xs space-y-2"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <SeverityTag severity={chain.highestSeverity} />
                    <span className="font-semibold text-[#fafaf9] truncate max-w-[240px]">
                      {chain.name}
                    </span>
                  </div>
                  <span className="font-mono text-[11px] text-[#f95721] bg-[#2a140d] px-2 py-0.5 rounded border border-[#ea580c]/30 font-medium">
                    Confidence: {(chain.confidenceScore * 100).toFixed(0)}%
                  </span>
                </div>

                <div className="text-[11px] font-mono text-[#a8a29e] flex items-center justify-between">
                  <span>{chain.events.length} chained forensic events</span>
                  <span>{chain.startTime.slice(11, 19)} → {chain.endTime.slice(11, 19)} UTC</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Multi-Dimensional Filter Bar (FR-TIME-2) */}
      <FilterBar
        filters={filters}
        onFilterChange={setFilters}
        availableHosts={availableHosts}
        availableUsers={availableUsers}
        availableSourceTypes={availableSourceTypes}
        totalCount={activeCaseEvents.length}
        filteredCount={filteredEvents.length}
      />

      {/* Active Tab View */}
      {activeTab === 'visual' ? (
        <TimelineView events={filteredEvents} />
      ) : (
        <EventTable events={filteredEvents} />
      )}

    </div>
  );
};
