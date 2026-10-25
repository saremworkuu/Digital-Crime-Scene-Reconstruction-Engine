import React, { useState, useMemo } from 'react';
import { useApp } from '../store';
import {
  FileText,
  Search,
  Download
} from 'lucide-react';

export const AuditLog: React.FC = () => {
  const { auditLogs } = useApp();
  const [searchQuery, setSearchQuery] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const actionOptions = useMemo(() => [...new Set(auditLogs.map(log => log.action).filter(Boolean))].sort(), [auditLogs]);

  const filteredLogs = useMemo(() => {
    return auditLogs.filter(log => {
      const matchesAction = actionFilter === 'ALL' || log.action === actionFilter;
      if (!matchesAction) return false;

      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        log.action.toLowerCase().includes(q) ||
        (log.user_name && log.user_name.toLowerCase().includes(q)) ||
        (log.target_id && log.target_id.toLowerCase().includes(q)) ||
        JSON.stringify(log.details || {}).toLowerCase().includes(q)
      );
    });
  }, [auditLogs, searchQuery, actionFilter]);

  const exportAuditCsv = () => {
    const headers = ['ID', 'Timestamp_UTC', 'User_ID', 'User_Name', 'Role', 'Action', 'Target_Type', 'Target_ID', 'IP_Address', 'Details_JSON'];
    const rows = filteredLogs.map(l => [
      `"${l.id}"`,
      `"${l.timestamp}"`,
      `"${l.user_id}"`,
      `"${l.user_name}"`,
      `"${l.user_role}"`,
      `"${l.action}"`,
      `"${l.target_type}"`,
      `"${l.target_id}"`,
      `"${l.ip_address}"`,
      `"${JSON.stringify(l.details || {}).replace(/"/g, '""')}"`
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dcsre_audit_trail_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[#282321]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#fafaf9] flex items-center gap-2.5">
            <FileText className="w-5 h-5 text-[#f95721]" />
            <span>Cryptographic Chain-of-Custody Audit Trail</span>
          </h1>
          <p className="text-xs text-[#a8a29e] mt-1">
            Immutable audit ledger recording user access, evidence hashing, rule evaluation, and report exports.
          </p>
        </div>

        <button
          onClick={exportAuditCsv}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] text-xs font-mono transition-colors border border-[#38312d] cursor-pointer"
          title="Export audit log to CSV for legal submission"
        >
          <Download className="w-3.5 h-3.5 text-[#f95721]" />
          <span>Export Audit Trail (CSV)</span>
        </button>
      </div>

      {/* Filter bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-[#161413]/90 border border-[#2b2523] rounded-2xl text-xs backdrop-blur-xl">
        
        {/* Search */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-[#78716c] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by action, user, target ID, or payload details..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg pl-9 pr-3 py-1.5 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] font-mono text-xs"
          />
        </div>

        {/* Action Type Dropdown */}
        <div className="flex items-center gap-2">
          <span className="text-[#a8a29e] font-mono text-[11px]">Action:</span>
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="bg-[#0d0c0c] border border-[#2b2523] rounded-lg px-2.5 py-1 text-[#fafaf9] font-mono text-xs focus:outline-none focus:border-[#f95721] cursor-pointer"
          >
            <option value="ALL">All Actions</option>
            {actionOptions.map(action => <option key={action} value={action}>{action.replace(/[._]/g, ' ')}</option>)}
          </select>
        </div>

        <div className="text-xs text-[#a8a29e] font-mono tabular-nums">
          {filteredLogs.length} audit records
        </div>

      </div>

      {/* Audit Log Table */}
      <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl overflow-hidden flex flex-col shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[#282321] bg-[#100f0e] text-[#a8a29e] font-mono text-[11px]">
                <th className="py-2.5 px-4 w-12 text-center">#</th>
                <th className="py-2.5 px-4">Timestamp (UTC)</th>
                <th className="py-2.5 px-4">Investigator / Actor</th>
                <th className="py-2.5 px-4">Action Code</th>
                <th className="py-2.5 px-4">Target Entity</th>
                <th className="py-2.5 px-4">IP Address</th>
                <th className="py-2.5 px-4">Action Payload & Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#282321]">
              {filteredLogs.map((entry, idx) => (
                <tr key={entry.id} className="hover:bg-[#1f1b19]/60 transition-colors font-mono">
                  <td className="py-2.5 px-4 text-center text-[#78716c]">
                    {idx + 1}
                  </td>

                  <td className="py-2.5 px-4 text-[#d6d3d1] whitespace-nowrap">
                    {entry.timestamp.replace('T', ' ').slice(0, 19)}
                  </td>

                  <td className="py-2.5 px-4 whitespace-nowrap">
                    <span className="font-semibold text-[#fafaf9]">{entry.user_name}</span>
                    <span className="text-[10px] text-[#78716c] uppercase ml-1.5">({entry.user_role})</span>
                  </td>

                  <td className="py-2.5 px-4 whitespace-nowrap">
                    <span className="text-[#f95721] font-semibold text-[11px] bg-[#2a140d] border border-[#ea580c]/30 px-2 py-0.5 rounded">
                      {entry.action}
                    </span>
                  </td>

                  <td className="py-2.5 px-4 text-[#d6d3d1] whitespace-nowrap">
                    <span className="text-[#78716c] uppercase text-[10px]">{entry.target_type}:</span> {entry.target_id}
                  </td>

                  <td className="py-2.5 px-4 text-[#a8a29e] whitespace-nowrap">
                    {entry.ip_address}
                  </td>

                  <td className="py-2.5 px-4 text-[#a8a29e] max-w-xs truncate" title={JSON.stringify(entry.details)}>
                    <span className="text-[#d6d3d1] text-[11px]">{JSON.stringify(entry.details)}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
};
