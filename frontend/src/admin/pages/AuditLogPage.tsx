import React, { useState, useEffect } from 'react';
import {
  History,
  Download,
  Filter,
  Eye,
  Calendar,
  ShieldCheck,
  FileSpreadsheet
} from 'lucide-react';
import { DataTable, Column } from '../components/DataTable';
import { FilterBar } from '../components/FilterBar';
import { auditService } from '../../services/admin';
import { AdminAuditEntry } from '../types';
import { toast } from '../../components/Toast';

export const AuditLogPage: React.FC = () => {
  const [logs, setLogs] = useState<AdminAuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [isLoading, setIsLoading] = useState(true);

  // Filters
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('all');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  // Selected Entry for JSON Details Inspector
  const [inspectEntry, setInspectEntry] = useState<AdminAuditEntry | null>(null);

  const loadLogs = async (targetPage = page) => {
    setIsLoading(true);
    try {
      const res = await auditService.getAuditLogs({
        search,
        action: actionFilter,
        date_from: dateFrom ? new Date(dateFrom).toISOString() : undefined,
        date_to: dateTo ? new Date(dateTo + 'T23:59:59').toISOString() : undefined,
        page: targetPage,
        limit: 12
      });

      setLogs(res.entries);
      setTotal(res.total);
      setPage(res.page);
      setTotalPages(res.totalPages);
    } catch (err: any) {
      toast.error('Failed to query audit trail: ' + err.message);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadLogs(1);
  }, [search, actionFilter, dateFrom, dateTo]);

  const handleExportCsv = () => {
    try {
      const csv = auditService.exportToCsv(logs);
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `dcsre_admin_audit_trail_${new Date().toISOString().slice(0, 10)}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success('Audit trail exported as CSV.');
    } catch (err: any) {
      toast.error('CSV export failed');
    }
  };

  const columns: Column<AdminAuditEntry>[] = [
    {
      key: 'timestamp',
      header: 'Timestamp (UTC)',
      render: (l) => (
        <span className="text-xs font-mono text-stone-300">
          {new Date(l.timestamp).toLocaleString([], { dateStyle: 'short', timeStyle: 'medium' })}
        </span>
      )
    },
    {
      key: 'user_name',
      header: 'User & Role',
      render: (l) => (
        <div className="space-y-0.5">
          <div className="font-bold text-white font-sans text-xs">{l.user_name}</div>
          <div className="text-[10px] font-mono text-stone-400">
            {l.role.toUpperCase()} · IP: {l.ip_address}
          </div>
        </div>
      )
    },
    {
      key: 'action',
      header: 'Action / Event',
      render: (l) => (
        <span className="text-xs font-mono font-bold text-[#ff936b] px-2 py-0.5 rounded bg-black/40 border border-[#3b2b24]">
          {l.action}
        </span>
      )
    },
    {
      key: 'target_id',
      header: 'Target & Scope',
      render: (l) => (
        <div className="space-y-0.5 font-mono text-xs">
          <span className="text-stone-300 font-semibold">{l.target_id}</span>
          <span className="text-[10px] text-stone-500 block">
            Type: {l.target_type} {l.case_id ? `· Case: ${l.case_id}` : ''}
          </span>
        </div>
      )
    },
    {
      key: 'inspect',
      header: 'Details',
      className: 'text-right',
      render: (l) => (
        <button
          type="button"
          onClick={() => setInspectEntry(l)}
          className="px-2.5 py-1 rounded-lg text-xs font-mono text-stone-300 bg-stone-900 hover:bg-stone-800 border border-stone-700 hover:border-[#f95721] transition-colors flex items-center gap-1.5 ml-auto cursor-pointer"
        >
          <Eye className="w-3.5 h-3.5 text-[#f95721]" />
          <span>Inspect</span>
        </button>
      )
    }
  ];

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#282321]">
        <div>
          <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight font-sans flex items-center gap-2.5">
            <History className="w-6 h-6 text-[#f95721]" />
            <span>Audit Trail Ledger (Read-Only)</span>
          </h1>
          <p className="text-xs sm:text-sm text-stone-400 font-sans mt-0.5">
            Cryptographically sealed, append-only chronological log of all administrative and forensic actions
          </p>
        </div>

        <button
          type="button"
          onClick={handleExportCsv}
          className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs sm:text-sm font-semibold text-white bg-stone-900 hover:bg-stone-800 border border-stone-700 hover:border-emerald-600 transition-all cursor-pointer w-fit shadow-md"
        >
          <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
          <span>Export CSV</span>
        </button>
      </div>

      {/* Date Range Bar */}
      <div className="flex flex-wrap items-center gap-3 p-3.5 rounded-2xl bg-[#141211]/90 border border-[#2b2523] text-xs font-sans">
        <div className="flex items-center gap-2 text-stone-400 font-mono text-xs">
          <Calendar className="w-4 h-4 text-[#f95721]" />
          <span>Date Range:</span>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="date"
            value={dateFrom}
            onChange={(e) => setDateFrom(e.target.value)}
            className="px-2.5 py-1.5 rounded-xl bg-black/40 border border-[#2e2623] text-white font-mono text-xs focus:outline-none focus:border-[#f95721]"
          />
          <span className="text-stone-500 font-mono">to</span>
          <input
            type="date"
            value={dateTo}
            onChange={(e) => setDateTo(e.target.value)}
            className="px-2.5 py-1.5 rounded-xl bg-black/40 border border-[#2e2623] text-white font-mono text-xs focus:outline-none focus:border-[#f95721]"
          />
        </div>

        {(dateFrom || dateTo) && (
          <button
            type="button"
            onClick={() => {
              setDateFrom('');
              setDateTo('');
            }}
            className="text-stone-400 hover:text-white text-xs underline cursor-pointer ml-auto"
          >
            Clear dates
          </button>
        )}
      </div>

      {/* Filter Bar */}
      <FilterBar
        searchQuery={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search audit actions, users, targets, details..."
        filters={[
          {
            key: 'action',
            label: 'Action',
            value: actionFilter,
            options: [
              { label: 'All Actions', value: 'all' },
              { label: 'User Login', value: 'USER_LOGIN' },
              { label: 'Evidence Upload', value: 'EVIDENCE_UPLOAD' },
              { label: 'Evidence Verify', value: 'EVIDENCE_VERIFY' },
              { label: 'Case Status', value: 'CASE_STATUS_UPDATE' },
              { label: 'Legal Hold', value: 'CASE_LEGAL_HOLD_SET' },
              { label: 'Sigma Rule', value: 'SIGMA_RULE_ENABLE' },
              { label: 'Message Reply', value: 'MESSAGE_REPLY' }
            ],
            onChange: setActionFilter
          }
        ]}
        onResetFilters={() => {
          setSearch('');
          setActionFilter('all');
          setDateFrom('');
          setDateTo('');
        }}
      />

      {/* Main Audit Table (Strictly NO Edit / Delete Controls) */}
      <DataTable
        columns={columns}
        data={logs}
        keyExtractor={(l) => l.id}
        isLoading={isLoading}
        emptyTitle="No audit logs found"
        emptyMessage="No entries matched the selected filter criteria."
        pagination={{
          currentPage: page,
          totalPages: totalPages,
          totalItems: total,
          onPageChange: (p) => {
            setPage(p);
            loadLogs(p);
          }
        }}
      />

      {/* Detail Modal for Log Inspection */}
      {inspectEntry && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-lg rounded-2xl bg-[#141211] border border-[#2e2623] p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#26201e]">
              <div className="space-y-0.5">
                <span className="text-[10px] font-mono uppercase tracking-wider text-[#f95721] font-bold">
                  Immutable Record
                </span>
                <h3 className="text-base font-bold text-white font-sans">{inspectEntry.id}</h3>
              </div>
              <button
                type="button"
                onClick={() => setInspectEntry(null)}
                className="text-xs font-mono text-stone-400 hover:text-white cursor-pointer"
              >
                Close
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-2.5 rounded-xl bg-black/40 border border-[#28221f]">
                <span className="text-stone-500 block text-[10px]">TIMESTAMP</span>
                <span className="text-white font-semibold">{inspectEntry.timestamp}</span>
              </div>
              <div className="p-2.5 rounded-xl bg-black/40 border border-[#28221f]">
                <span className="text-stone-500 block text-[10px]">USER / OPERATOR</span>
                <span className="text-white font-semibold">{inspectEntry.user_name} ({inspectEntry.role})</span>
              </div>
              <div className="p-2.5 rounded-xl bg-black/40 border border-[#28221f]">
                <span className="text-stone-500 block text-[10px]">ACTION</span>
                <span className="text-[#ff936b] font-bold">{inspectEntry.action}</span>
              </div>
              <div className="p-2.5 rounded-xl bg-black/40 border border-[#28221f]">
                <span className="text-stone-500 block text-[10px]">SOURCE IP</span>
                <span className="text-stone-300 font-semibold">{inspectEntry.ip_address}</span>
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[11px] font-mono text-stone-400 uppercase tracking-wider">
                Full Details Payload (JSON)
              </span>
              <pre className="p-3 rounded-xl bg-black/60 border border-[#2e2623] text-emerald-400 font-mono text-xs overflow-x-auto max-h-56">
                {JSON.stringify(inspectEntry.details, null, 2)}
              </pre>
            </div>

            <div className="pt-2 text-right">
              <button
                type="button"
                onClick={() => setInspectEntry(null)}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-stone-300 bg-stone-900 hover:bg-stone-800 border border-stone-700 cursor-pointer"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
