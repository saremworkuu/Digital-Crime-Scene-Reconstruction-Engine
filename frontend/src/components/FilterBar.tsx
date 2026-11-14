import React from 'react';
import { EventSeverity } from '../types';
import { Search, X, Filter, ChevronDown, ShieldAlert } from 'lucide-react';

export interface FilterState {
  search: string;
  severity: 'all' | EventSeverity;
  host: string;
  user: string;
  sourceType: string;
  onlyAttackPath: boolean;
  showMetrics: boolean;
}

interface FilterBarProps {
  filters: FilterState;
  onFilterChange: (filters: FilterState) => void;
  availableHosts: string[];
  availableUsers: string[];
  availableSourceTypes: string[];
  totalCount: number;
  filteredCount: number;
}

export const FilterBar: React.FC<FilterBarProps> = ({
  filters,
  onFilterChange,
  availableHosts,
  availableUsers,
  availableSourceTypes,
  totalCount,
  filteredCount
}) => {
  const updateFilter = <K extends keyof FilterState>(key: K, value: FilterState[K]) => {
    onFilterChange({ ...filters, [key]: value });
  };

  const clearFilters = () => {
    onFilterChange({
      search: '',
      severity: 'all',
      host: '',
      user: '',
      sourceType: '',
      onlyAttackPath: false,
      showMetrics: false
    });
  };

  const hasActiveFilters =
    filters.search !== '' ||
    filters.severity !== 'all' ||
    filters.host !== '' ||
    filters.user !== '' ||
    filters.sourceType !== '' ||
    filters.onlyAttackPath ||
    filters.showMetrics;

  return (
    <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-3 sm:p-4 mb-4 space-y-3.5 backdrop-blur-xl shadow-xl">
      {/* Search & Main Toggles Row */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 sm:gap-3">
        
        {/* Search input */}
        <div className="relative flex-1 min-w-[180px] sm:min-w-[240px]">
          <Search className="w-4 h-4 text-[#78716c] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search action, IP, commandline, hash, or raw log..."
            value={filters.search}
            onChange={(e) => updateFilter('search', e.target.value)}
            className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg pl-9 pr-8 py-1.5 text-xs text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]/50 font-mono transition-colors"
          />
          {filters.search && (
            <button
              onClick={() => updateFilter('search', '')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#78716c] hover:text-[#fafaf9] cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Severity Dropdown Filter (compact, saves space) */}
        <div className="relative">
          <div className="flex items-center gap-1.5 bg-[#0d0c0c] border border-[#2b2523] rounded-lg px-2.5 py-1 text-xs font-mono">
            <span className="text-[#78716c] text-[11px]">Severity:</span>
            <select
              value={filters.severity}
              onChange={(e) => updateFilter('severity', e.target.value as FilterState['severity'])}
              className="bg-transparent text-[#fafaf9] focus:outline-none cursor-pointer pr-5 font-semibold text-xs appearance-none"
            >
              <option value="all" className="bg-[#161413] text-[#e7e5e4]">All Severities</option>
              <option value="critical" className="bg-[#161413] text-[#fca5a5]">Critical</option>
              <option value="high" className="bg-[#161413] text-[#f95721]">High</option>
              <option value="medium" className="bg-[#161413] text-[#fbbf24]">Medium</option>
              <option value="low" className="bg-[#161413] text-[#a8a29e]">Low</option>
            </select>
            <ChevronDown className="w-3.5 h-3.5 text-[#78716c] absolute right-2.5 pointer-events-none" />
          </div>
        </div>

        {/* Attack Path Only Checkbox */}
        <label className="flex items-center gap-2 cursor-pointer text-xs text-[#fafaf9] select-none bg-[#0d0c0c] border border-[#2b2523] px-3 py-1.5 rounded-lg hover:border-[#38312d] transition-colors">
          <input
            type="checkbox"
            checked={filters.onlyAttackPath}
            onChange={(e) => updateFilter('onlyAttackPath', e.target.checked)}
            className="rounded border-[#38312d] bg-[#141211] text-[#f95721] accent-[#f95721] cursor-pointer"
          />
          <span className="font-semibold text-[#f95721] font-mono text-xs">Attack Path Only</span>
        </label>

        {/* Show Metrics Checkbox */}
        <label className="flex items-center gap-2 cursor-pointer text-xs text-[#fafaf9] select-none bg-[#0d0c0c] border border-[#2b2523] px-3 py-1.5 rounded-lg hover:border-[#38312d] transition-colors">
          <input
            type="checkbox"
            checked={filters.showMetrics}
            onChange={(e) => updateFilter('showMetrics', e.target.checked)}
            className="rounded border-[#38312d] bg-[#141211] text-[#a8a29e] accent-[#a8a29e] cursor-pointer"
          />
          <span className="font-semibold text-[#a8a29e] font-mono text-xs">Show Metrics</span>
        </label>

      </div>

      {/* Entity Selectors & Meta Row */}
      <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[#282321] text-xs">
        
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[#78716c] flex items-center gap-1 font-mono text-[11px]">
            <Filter className="w-3 h-3 text-[#f95721]" /> Filter by:
          </span>

          {/* Host Dropdown */}
          <select
            value={filters.host}
            onChange={(e) => updateFilter('host', e.target.value)}
            className="bg-[#0d0c0c] border border-[#2b2523] rounded-lg px-2.5 py-1 text-[#fafaf9] focus:outline-none focus:border-[#f95721] text-xs font-mono cursor-pointer"
          >
            <option value="">All Hosts ({availableHosts.length})</option>
            {availableHosts.map((h) => (
              <option key={h} value={h}>{h}</option>
            ))}
          </select>

          {/* User Dropdown */}
          <select
            value={filters.user}
            onChange={(e) => updateFilter('user', e.target.value)}
            className="bg-[#0d0c0c] border border-[#2b2523] rounded-lg px-2.5 py-1 text-[#fafaf9] focus:outline-none focus:border-[#f95721] text-xs font-mono cursor-pointer"
          >
            <option value="">All Users ({availableUsers.length})</option>
            {availableUsers.map((u) => (
              <option key={u} value={u}>{u}</option>
            ))}
          </select>

          {/* Source Type Dropdown */}
          <select
            value={filters.sourceType}
            onChange={(e) => updateFilter('sourceType', e.target.value)}
            className="bg-[#0d0c0c] border border-[#2b2523] rounded-lg px-2.5 py-1 text-[#fafaf9] focus:outline-none focus:border-[#f95721] text-xs font-mono cursor-pointer"
          >
            <option value="">All Evidence Formats ({availableSourceTypes.length})</option>
            {availableSourceTypes.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>

          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="text-xs text-[#f95721] hover:text-[#fb923c] font-medium px-2 py-1 underline underline-offset-2 ml-1 cursor-pointer font-mono"
            >
              Reset Filters
            </button>
          )}
        </div>

        {/* Counter */}
        <div className="text-[#a8a29e] text-xs font-mono tabular-nums">
          Showing <span className="text-[#fafaf9] font-semibold">{filteredCount}</span> of <span className="text-[#d6d3d1]">{totalCount}</span> events
        </div>

      </div>
    </div>
  );
};
