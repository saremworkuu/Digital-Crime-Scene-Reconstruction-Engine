import React, { useState, useMemo } from 'react';

import { useApp } from '../store';
import { formatCaseNameWithId } from '../utils/caseDisplay';

import { FilterBar, FilterState } from '../components/FilterBar';

import { TimelineView } from '../components/TimelineView';

import { EventTable } from '../components/EventTable';

import { correlateAttackChains, MIN_CHAIN_CONFIDENCE } from '../services/correlation';

const formatChainUtc = (ts: string): string => {
  if (!ts) return '';
  const parsed = new Date(ts);
  if (!Number.isNaN(parsed.getTime())) {
    return parsed.toISOString().slice(0, 19).replace('T', ' ');
  }
  return ts.slice(0, 19).replace('T', ' ');
};

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

    onlyAttackPath: false,

    showMetrics: false

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



  const isContextEvent = (evt: { category?: string; source_type?: string; metadata?: Record<string, any> }) =>
    evt.category === 'context' || evt.source_type === 'vuln_scan' || evt.metadata?.category === 'context';

  const incidentEvents = useMemo(
    () => activeCaseEvents.filter(e => !isContextEvent(e)),
    [activeCaseEvents]
  );

  const contextEvents = useMemo(
    () => activeCaseEvents.filter(e => isContextEvent(e)),
    [activeCaseEvents]
  );

  // Filter events according to active filter criteria
  const filteredEvents = useMemo(() => {
    return incidentEvents.filter(evt => {
      if (filters.severity !== 'all' && evt.severity !== filters.severity) return false;
      if (filters.host && evt.host !== filters.host) return false;
      if (filters.user && evt.user !== filters.user) return false;
      if (filters.sourceType && evt.source_type !== filters.sourceType) return false;
      if (filters.onlyAttackPath && !evt.is_attack_path) return false;
      // Hide metric events by default unless showMetrics is enabled
      if (!filters.showMetrics && evt.event_type === 'metric') return false;

      if (filters.search.trim()) {
        const q = filters.search.toLowerCase();
        const matchesAction = (evt.action || '').toLowerCase().includes(q);
        const matchesHost = (evt.host || '').toLowerCase().includes(q);
        const matchesUser = (evt.user || '').toLowerCase().includes(q);
        const matchesRaw = (evt.raw || '').toLowerCase().includes(q);
        const matchesIp = (evt.src_ip && evt.src_ip.includes(q)) || (evt.dst_ip && evt.dst_ip.includes(q));
        const matchesMitre = evt.mitre_technique && evt.mitre_technique.toLowerCase().includes(q);

        if (!matchesAction && !matchesHost && !matchesUser && !matchesRaw && !matchesIp && !matchesMitre) {
          return false;
        }
      }

      return true;
    });
  }, [incidentEvents, filters]);

  const filteredContextEvents = useMemo(() => {
    return contextEvents.filter(evt => {
      if (filters.severity !== 'all' && evt.severity !== filters.severity) return false;
      if (filters.host && evt.host !== filters.host) return false;
      if (filters.search.trim()) {
        const q = filters.search.toLowerCase();
        const matchesAction = (evt.action || '').toLowerCase().includes(q);
        const matchesHost = (evt.host || '').toLowerCase().includes(q);
        const matchesTicket = (evt.ticket || evt.metadata?.ticket || '').toLowerCase().includes(q);
        if (!matchesAction && !matchesHost && !matchesTicket) return false;
      }
      return true;
    });
  }, [contextEvents, filters]);

  // Compute automated correlated attack chains (FR-CORR-1, FR-CORR-2, FR-CORR-3)
  const attackChains = useMemo(() => {
    return correlateAttackChains(incidentEvents, 45);
  }, [incidentEvents]);



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

            Normalized UTC timeline across all digital evidence sources for <strong className="text-[#fafaf9]">{activeCase ? formatCaseNameWithId(activeCase.name, activeCase.id) : ''}</strong>

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

              Confidence Score ≥ {MIN_CHAIN_CONFIDENCE.toFixed(2)} (FR-CORR-3)

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



                <div className="text-[11px] font-mono text-[#a8a29e] flex items-center justify-between gap-2">

                  <span>{chain.events.length} chained forensic events</span>

                  <span>{formatChainUtc(chain.startTime)} → {formatChainUtc(chain.endTime)} UTC</span>

                </div>

              </div>

            ))}

          </div>

        </div>

      )}



      {/* Pre-incident exposure lane (context / vuln scan findings, out of main attack chain & range) */}
      {filteredContextEvents.length > 0 && (
        <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-5 space-y-3 shadow-xl backdrop-blur-xl">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-semibold text-[#fafaf9] uppercase font-mono tracking-wider">
              Pre-incident exposure ({filteredContextEvents.length})
            </h3>
            <span className="text-[11px] font-mono text-[#a8a29e]">
              Context baseline · Excluded from incident attack chains &amp; default time range
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {filteredContextEvents.map((evt) => {
              const statusVal = String(evt.status || evt.metadata?.status || 'open').toLowerCase();
              const isClosed = statusVal === 'closed';
              const ticketVal = evt.ticket || evt.metadata?.ticket;
              const dateLabel = evt.first_detected || evt.metadata?.first_detected || (evt.date_only ? evt.timestamp.slice(0, 10) : evt.timestamp.slice(0, 10));
              const titleText = evt.metadata?.extra?.title || evt.action;

              return (
                <div
                  key={evt.id}
                  className={`p-3.5 rounded-xl border text-xs space-y-1.5 ${
                    isClosed
                      ? 'bg-[#100f0e]/60 border-[#26211f] opacity-75'
                      : 'bg-[#100f0e] border-[#282321]'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <SeverityTag severity={evt.severity} />
                      <span className="font-semibold text-[#fafaf9] truncate">
                        {titleText}
                      </span>
                    </div>
                    <span
                      className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border shrink-0 ${
                        isClosed
                          ? 'bg-[#1f1c1a] text-[#a8a29e] border-[#3a322e]'
                          : 'bg-[#2a140d] text-[#fb923c] border-[#ea580c]/40'
                      }`}
                    >
                      {isClosed ? 'closed' : statusVal}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-[#a8a29e] flex flex-wrap items-center gap-3">
                    <span>First detected: <strong className="text-[#fafaf9]">{dateLabel}</strong></span>
                    {evt.host && <span>Host: <strong className="text-[#fafaf9]">{evt.host}</strong></span>}
                    {ticketVal && <span>Ticket: <strong className="text-[#fafaf9]">{ticketVal}</strong></span>}
                  </div>
                </div>
              );
            })}
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

        totalCount={incidentEvents.length}

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

