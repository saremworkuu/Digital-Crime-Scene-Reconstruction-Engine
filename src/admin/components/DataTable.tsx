import React from 'react';
import { Loader2, ChevronLeft, ChevronRight } from 'lucide-react';
import { EmptyState } from './EmptyState';

export interface Column<T> {
  key: string;
  header: string;
  className?: string;
  render?: (row: T) => React.ReactNode;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (row: T) => string;
  isLoading?: boolean;
  emptyTitle?: string;
  emptyMessage?: string;
  pagination?: {
    currentPage: number;
    totalPages: number;
    totalItems: number;
    onPageChange: (page: number) => void;
  };
}

export function DataTable<T>({
  columns,
  data,
  keyExtractor,
  isLoading = false,
  emptyTitle,
  emptyMessage,
  pagination
}: DataTableProps<T>) {
  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center p-16 rounded-2xl bg-[#141211]/90 border border-[#2b2523] space-y-3">
        <Loader2 className="w-7 h-7 text-[#f95721] animate-spin" />
        <span className="text-xs font-mono text-stone-400">Loading forensic records...</span>
      </div>
    );
  }

  if (!data || data.length === 0) {
    return (
      <div className="rounded-2xl bg-[#141211]/90 border border-[#2b2523] p-4">
        <EmptyState title={emptyTitle} message={emptyMessage} />
      </div>
    );
  }

  return (
    <div className="rounded-2xl bg-[#141211]/90 border border-[#2b2523] shadow-xl overflow-hidden backdrop-blur-md">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs sm:text-sm">
          <thead>
            <tr className="border-b border-[#2b2523] bg-black/40 text-[11px] font-mono uppercase tracking-wider text-stone-400 select-none">
              {columns.map((col) => (
                <th key={col.key} className={`py-3.5 px-4 font-semibold ${col.className || ''}`}>
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-[#221c1a]">
            {data.map((row) => (
              <tr
                key={keyExtractor(row)}
                className="hover:bg-white/[0.02] transition-colors group"
              >
                {columns.map((col) => (
                  <td key={col.key} className={`py-3.5 px-4 ${col.className || ''}`}>
                    {col.render ? col.render(row) : (row as any)[col.key]}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      {pagination && pagination.totalPages > 1 && (
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-t border-[#26201e] bg-black/20 text-xs text-stone-400">
          <div className="font-mono">
            Showing Page <strong className="text-white">{pagination.currentPage}</strong> of{' '}
            <strong className="text-white">{pagination.totalPages}</strong> ({pagination.totalItems} records)
          </div>

          <div className="flex items-center gap-1.5">
            <button
              type="button"
              disabled={pagination.currentPage <= 1}
              onClick={() => pagination.onPageChange(pagination.currentPage - 1)}
              className="p-1.5 rounded-lg border border-[#332a26] bg-[#1d1816] text-stone-300 hover:text-white hover:border-[#f95721] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-all"
              aria-label="Previous page"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>

            {Array.from({ length: pagination.totalPages }, (_, i) => i + 1).map((p) => {
              // Only render limited page window for clean display
              if (
                p === 1 ||
                p === pagination.totalPages ||
                (p >= pagination.currentPage - 1 && p <= pagination.currentPage + 1)
              ) {
                const isActive = p === pagination.currentPage;
                return (
                  <button
                    key={p}
                    type="button"
                    onClick={() => pagination.onPageChange(p)}
                    className={`min-w-[28px] h-7 px-2 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${
                      isActive
                        ? 'bg-[#f95721] text-white shadow-[0_0_10px_rgba(249,87,33,0.4)]'
                        : 'border border-[#332a26] bg-[#1d1816] text-stone-300 hover:text-white hover:border-[#f95721]'
                    }`}
                  >
                    {p}
                  </button>
                );
              }
              if (p === pagination.currentPage - 2 || p === pagination.currentPage + 2) {
                return (
                  <span key={p} className="px-1 text-stone-600 font-mono">
                    ...
                  </span>
                );
              }
              return null;
            })}

            <button
              type="button"
              disabled={pagination.currentPage >= pagination.totalPages}
              onClick={() => pagination.onPageChange(pagination.currentPage + 1)}
              className="p-1.5 rounded-lg border border-[#332a26] bg-[#1d1816] text-stone-300 hover:text-white hover:border-[#f95721] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-all"
              aria-label="Next page"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
