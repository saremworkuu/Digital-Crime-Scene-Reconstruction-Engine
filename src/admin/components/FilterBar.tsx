import React from 'react';
import { Search, X, SlidersHorizontal } from 'lucide-react';

export interface FilterOption {
  key: string;
  label: string;
  value: string;
  options: Array<{ label: string; value: string }>;
  onChange: (value: string) => void;
}

interface FilterBarProps {
  searchQuery?: string;
  onSearchChange?: (val: string) => void;
  searchPlaceholder?: string;
  filters?: FilterOption[];
  onResetFilters?: () => void;
  actions?: React.ReactNode;
}

export const FilterBar: React.FC<FilterBarProps> = ({
  searchQuery,
  onSearchChange,
  searchPlaceholder = 'Search records...',
  filters = [],
  onResetFilters,
  actions
}) => {
  const hasActiveFilters =
    (searchQuery && searchQuery.trim().length > 0) ||
    filters.some((f) => f.value && f.value !== 'all' && f.value !== '');

  return (
    <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3 p-3 rounded-2xl bg-[#141211]/90 border border-[#2b2523] shadow-md backdrop-blur-md">
      {/* Search Bar & Dropdown Selects */}
      <div className="flex flex-1 flex-wrap items-center gap-2.5">
        {onSearchChange && (
          <div className="relative flex-1 min-w-[200px] sm:min-w-[260px]">
            <Search className="w-4 h-4 text-stone-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={searchQuery || ''}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder={searchPlaceholder}
              className="w-full pl-9 pr-8 py-2 rounded-xl text-xs sm:text-sm bg-black/40 border border-[#2e2825] text-white placeholder:text-stone-500 focus:outline-none focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721] transition-all font-sans"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => onSearchChange('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-stone-400 hover:text-white p-0.5 cursor-pointer"
                title="Clear search"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        )}

        {/* Dropdown Filters */}
        {filters.map((f) => (
          <div key={f.key} className="flex items-center gap-1.5 shrink-0">
            <label htmlFor={`filter-${f.key}`} className="text-[11px] font-mono text-stone-400 hidden sm:inline">
              {f.label}:
            </label>
            <select
              id={`filter-${f.key}`}
              value={f.value}
              onChange={(e) => f.onChange(e.target.value)}
              className="px-2.5 py-2 rounded-xl text-xs bg-black/50 border border-[#2e2825] text-stone-200 focus:outline-none focus:border-[#f95721] font-sans cursor-pointer hover:border-[#3d3632]"
            >
              {f.options.map((opt) => (
                <option key={opt.value} value={opt.value} className="bg-[#141211] text-white">
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        ))}

        {/* Reset Filter Button */}
        {hasActiveFilters && onResetFilters && (
          <button
            type="button"
            onClick={onResetFilters}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-mono text-stone-400 hover:text-[#f95721] hover:bg-[#231712] border border-transparent hover:border-[#f95721]/30 transition-all cursor-pointer"
          >
            <SlidersHorizontal className="w-3 h-3" />
            <span>Reset</span>
          </button>
        )}
      </div>

      {/* Action Buttons Slot (Create, Export, etc.) */}
      {actions && <div className="flex items-center gap-2 shrink-0 pt-2 lg:pt-0">{actions}</div>}
    </div>
  );
};
