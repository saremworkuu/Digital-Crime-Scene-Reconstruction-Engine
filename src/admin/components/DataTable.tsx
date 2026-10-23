import React from 'react';
import { Loader2, ChevronLeft, ChevronRight } from 'lucide-react';
import { EmptyState } from './EmptyState';
import { useApp } from '../../store';

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
  const { theme } = useApp();
  const isLight = theme === 'light';

  if (isLoading) {
    return (
      <div
        className={`flex flex-col items-center justify-center p-16 rounded-2xl border space-y-3 ${
          isLight ? 'bg-white border-slate-200' : 'bg-[#141211]/90 border-[#2b2523]'
        }`}
      >
        <Loader2 className="w-7 h-7 text-[#f95721] animate-spin" />
        <span className={`text-xs font-mono ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
          Loading forensic records...
        </span>
      </div>
    );
  }

  if (!data || data.length === 0) {
    return (
      <div
        className={`rounded-2xl border p-4 ${
          isLight ? 'bg-white border-slate-200' : 'bg-[#141211]/90 border-[#2b2523]'
        }`}
      >
        <EmptyState title={emptyTitle} message={emptyMessage} />
      </div>
    );
  }

  return (
    <div
      className={`rounded-2xl border overflow-hidden backdrop-blur-md ${
        isLight
          ? 'bg-white border-slate-200 shadow-sm text-slate-800'
          : 'bg-[#141211]/90 border-[#2b2523] shadow-xl text-stone-200'
      }`}
    >
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs sm:text-sm">
          <thead>
            <tr
              className={`border-b text-[11px] font-mono uppercase tracking-wider select-none ${
                isLight
                  ? 'border-slate-200 bg-slate-50 text-slate-500 font-bold'
                  : 'border-[#2b2523] bg-black/40 text-stone-400'
              }`}
            >
              {columns.map((col) => (
                <th key={col.key} className={`py-3.5 px-4 font-semibold ${col.className || ''}`}>
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className={isLight ? 'divide-y divide-slate-100' : 'divide-y divide-[#221c1a]'}>
            {data.map((row) => (
              <tr
                key={keyExtractor(row)}
                className={`transition-colors group ${
                  isLight ? 'hover:bg-slate-50/80 text-slate-800' : 'hover:bg-white/[0.02]'
                }`}
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
        <div
          className={`flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-t text-xs ${
            isLight
              ? 'border-slate-200 bg-slate-50 text-slate-600'
              : 'border-[#26201e] bg-black/20 text-stone-400'
          }`}
        >
          <div className="font-mono">
            Showing Page{' '}
            <strong className={isLight ? 'text-slate-900 font-bold' : 'text-white'}>
              {pagination.currentPage}
            </strong>{' '}
            of{' '}
            <strong className={isLight ? 'text-slate-900 font-bold' : 'text-white'}>
              {pagination.totalPages}
            </strong>{' '}
            ({pagination.totalItems} records)
          </div>

          <div className="flex items-center gap-1.5">
            <button
              type="button"
              disabled={pagination.currentPage <= 1}
              onClick={() => pagination.onPageChange(pagination.currentPage - 1)}
              className={`p-1.5 rounded-lg border disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-all ${
                isLight
                  ? 'border-slate-300 bg-white text-slate-700 hover:bg-slate-100 hover:text-slate-900'
                  : 'border-[#332a26] bg-[#1d1816] text-stone-300 hover:text-white hover:border-[#f95721]'
              }`}
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
                        : isLight
                        ? 'border border-slate-300 bg-white text-slate-700 hover:bg-slate-100 hover:border-slate-400'
                        : 'border border-[#332a26] bg-[#1d1816] text-stone-300 hover:text-white hover:border-[#f95721]'
                    }`}
                  >
                    {p}
                  </button>
                );
              }
              if (p === pagination.currentPage - 2 || p === pagination.currentPage + 2) {
                return (
                  <span
                    key={p}
                    className={`px-1 font-mono ${isLight ? 'text-slate-400' : 'text-stone-600'}`}
                  >
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
              className={`p-1.5 rounded-lg border disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-all ${
                isLight
                  ? 'border-slate-300 bg-white text-slate-700 hover:bg-slate-100 hover:text-slate-900'
                  : 'border-[#332a26] bg-[#1d1816] text-stone-300 hover:text-white hover:border-[#f95721]'
              }`}
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
