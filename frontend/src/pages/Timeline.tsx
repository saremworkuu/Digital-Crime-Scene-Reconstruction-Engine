import React, { useState, useMemo } from 'react';

import { useApp } from '../store';

import { FilterBar, FilterState } from '../components/FilterBar';

import { TimelineView } from '../components/TimelineView';

import { EventTable } from '../components/EventTable';

import {

  Clock,

  Table,

  GitCommit

} from 'lucide-react';



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

