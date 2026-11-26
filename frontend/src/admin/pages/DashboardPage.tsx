import React, { useState, useEffect } from 'react';
import {
  Users,
  FolderLock,
  FileCheck2,
  AlertOctagon,
  Mail,
  ShieldCheck,
  Activity,
  Server,
  ArrowRight,
  RefreshCw
} from 'lucide-react';
import { StatCard } from '../components/StatCard';
import { StatusBadge } from '../components/StatusBadge';
import { toast } from '../../components/Toast';
import { useApp } from '../../store';
import {
  systemService,
  auditService
} from '../../services/admin';
import {
  clearLegacyAdminStorage,
  subscribeAdminCacheInvalidation
} from '../../services/admin/storageHelper';
import { AdminAuditEntry, AdminQueueJob } from '../types';

interface DashboardPageProps {
  onNavigateTab: (tab: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigateTab }) => {
  const { theme } = useApp();
  const isLight = theme === 'light';

  const cachedSummary = systemService.getCachedDashboardSummary();
  const cachedAudit = auditService.getCachedAuditLogs({ limit: 6 });

  const [counts, setCounts] = useState(() => ({
    users: cachedSummary?.users ?? 0,
    cases: cachedSummary?.cases ?? 0,
    evidence: cachedSummary?.evidence ?? 0,
    failures: cachedSummary?.failures ?? 0,
    newMessages: cachedSummary?.new_messages ?? 0,
    failedLogins24h: cachedSummary?.failed_logins_24h ?? 0
  }));

  const [recentAudit, setRecentAudit] = useState<AdminAuditEntry[]>(
    () => cachedAudit?.entries ?? []
  );
  const [queueJobs, setQueueJobs] = useState<AdminQueueJob[]>(
    () => cachedSummary?.queue ?? []
  );
  const [isLoading, setIsLoading] = useState(!(cachedSummary && cachedAudit));

  const loadMetrics = async (force = false) => {
    if (!cachedSummary || force) {
      setIsLoading(true);
    }
    try {
      clearLegacyAdminStorage();
      const [summary, audit] = await Promise.all([
        systemService.getDashboardSummary(force),
        auditService.getAuditLogs({ limit: 6 }, force)
      ]);

      setCounts({
        users: summary.users,
        cases: summary.cases,
        evidence: summary.evidence,
        failures: summary.failures,
        newMessages: summary.new_messages,
        failedLogins24h: summary.failed_logins_24h
      });

      setRecentAudit(audit.entries);
      setQueueJobs(summary.queue);
    } catch (err: any) {
      console.error('[Dashboard] Error loading metrics:', err);
      toast.error('Failed to load admin overview: ' + (err?.message || 'Backend unavailable'));
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadMetrics(false);
    return subscribeAdminCacheInvalidation((prefixes) => {
      if (prefixes.some((p) => p === '*' || p.startsWith('/admin/system') || p.startsWith('/admin/audit'))) {
        loadMetrics(false);
      }
    });
  }, []);

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Header */}
      <div
        className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b ${
          isLight ? 'border-slate-200' : 'border-[#282321]'
        }`}
      >
        <div>
          <h1
            className={`text-xl sm:text-2xl font-black tracking-tight font-sans flex items-center gap-2.5 ${
              isLight ? 'text-slate-900' : 'text-white'
            }`}
          >
            <ShieldCheck className="w-6 h-6 text-[#f95721]" />
            <span>Admin Control Console</span>
          </h1>
          <p className={`text-xs sm:text-sm font-sans mt-0.5 ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
            Telemetry oversight, RBAC enforcement, evidence integrity, and inbox operations
          </p>
        </div>

        <button
          type="button"
          onClick={() => loadMetrics(true)}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-mono transition-all cursor-pointer w-fit ${
            isLight
              ? 'text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 hover:border-[#f95721] shadow-sm'
              : 'text-stone-300 bg-[#1a1715] hover:bg-[#25201d] border border-[#332b27] hover:border-[#f95721]'
          }`}
        >
          <RefreshCw className={`w-3.5 h-3.5 text-[#f95721] ${isLoading ? 'animate-spin' : ''}`} />
          <span>Sync Telemetry</span>
        </button>
      </div>

      {/* 5 Core Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
        <StatCard
          title="Users"
          value={counts.users}
          subtitle="Examiners & Auditors"
          icon={Users}
          onClick={() => onNavigateTab('users')}
        />
        <StatCard
          title="Cases"
          value={counts.cases}
          subtitle="DCSRE Investigations"
          icon={FolderLock}
          onClick={() => onNavigateTab('cases')}
        />
        <StatCard
          title="Evidence Files"
          value={counts.evidence}
          subtitle="EVTX, PCAP, RAW dumps"
          icon={FileCheck2}
          onClick={() => onNavigateTab('evidence')}
        />
        <StatCard
          title="Parsing Failures"
          value={counts.failures}
          subtitle="Requires hex triage"
          icon={AlertOctagon}
          badge={{ text: counts.failures > 0 ? 'Action Needed' : 'Nominal', color: counts.failures > 0 ? 'red' : 'green' }}
          onClick={() => onNavigateTab('evidence')}
        />
        <StatCard
          title="New Messages"
          value={counts.newMessages}
          subtitle="Contact submissions"
          icon={Mail}
          badge={{ text: `${counts.newMessages} Unread`, color: counts.newMessages > 0 ? 'orange' : 'green' }}
          onClick={() => onNavigateTab('messages')}
        />
      </div>

      {/* Split Section: Ingestion Queue Summary & Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Processing Queue & Health Summary */}
        <div
          className={`lg:col-span-5 rounded-2xl border p-5 space-y-4 ${
            isLight
              ? 'bg-white border-slate-200 shadow-sm text-slate-800'
              : 'bg-[#141211]/90 border-[#2b2523] shadow-xl text-stone-200'
          }`}
        >
          <div
            className={`flex items-center justify-between pb-3 border-b ${
              isLight ? 'border-slate-100' : 'border-[#26201e]'
            }`}
          >
            <div
              className={`flex items-center gap-2 font-bold text-sm font-sans ${
                isLight ? 'text-slate-900' : 'text-white'
              }`}
            >
              <Server className="w-4 h-4 text-[#f95721]" />
              <span>Ingestion Queue Summary</span>
            </div>
            <button
              type="button"
              onClick={() => onNavigateTab('health')}
              className="text-xs font-mono text-[#f95721] hover:text-[#fb923c] flex items-center gap-1 cursor-pointer"
            >
              <span>Full Health</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          {/* Quick Metrics */}
          <div className="grid grid-cols-2 gap-2.5">
            <div
              className={`p-3 rounded-xl border space-y-1 ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-black/40 border-[#2e2623]'
              }`}
            >
              <span className={`text-[10px] font-mono uppercase ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
                Failed Logins (24h)
              </span>
              <div className="text-xl font-bold font-mono text-red-500">{counts.failedLogins24h}</div>
            </div>
            <div
              className={`p-3 rounded-xl border space-y-1 ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-black/40 border-[#2e2623]'
              }`}
            >
              <span className={`text-[10px] font-mono uppercase ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
                Queue Jobs Active
              </span>
              <div className="text-xl font-bold font-mono text-amber-500">{queueJobs.length}</div>
            </div>
          </div>

          {/* Queue Jobs List */}
          <div className="space-y-2">
            <span
              className={`text-[11px] font-mono uppercase tracking-wider font-semibold block ${
                isLight ? 'text-slate-500' : 'text-stone-400'
              }`}
            >
              Active Queue Stream
            </span>
            {queueJobs.map((job) => (
              <div
                key={job.id}
                className={`p-2.5 rounded-xl border flex items-center justify-between gap-3 text-xs ${
                  isLight
                    ? 'bg-slate-50 border-slate-200'
                    : 'bg-black/30 border-[#28221f]'
                }`}
              >
                <div className="min-w-0">
                  <div className={`font-mono truncate ${isLight ? 'text-slate-800 font-semibold' : 'text-stone-200'}`}>
                    {job.file_name}
                  </div>
                  <div className={`text-[10px] font-mono ${isLight ? 'text-slate-400' : 'text-stone-500'}`}>
                    Parser: {job.parser_type} · Started: {new Date(job.started_at).toLocaleTimeString()}
                  </div>
                </div>
                <StatusBadge status={job.status} />
              </div>
            ))}
          </div>
        </div>

        {/* Recent Audit Activity */}
        <div
          className={`lg:col-span-7 rounded-2xl border p-5 space-y-4 ${
            isLight
              ? 'bg-white border-slate-200 shadow-sm text-slate-800'
              : 'bg-[#141211]/90 border-[#2b2523] shadow-xl text-stone-200'
          }`}
        >
          <div
            className={`flex items-center justify-between pb-3 border-b ${
              isLight ? 'border-slate-100' : 'border-[#26201e]'
            }`}
          >
            <div
              className={`flex items-center gap-2 font-bold text-sm font-sans ${
                isLight ? 'text-slate-900' : 'text-white'
              }`}
            >
              <Activity className="w-4 h-4 text-[#f95721]" />
              <span>Recent Forensic Actions</span>
            </div>
            <button
              type="button"
              onClick={() => onNavigateTab('audit')}
              className="text-xs font-mono text-[#f95721] hover:text-[#fb923c] flex items-center gap-1 cursor-pointer"
            >
              <span>View Audit Trail</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className={isLight ? 'divide-y divide-slate-100' : 'divide-y divide-[#221c1a]'}>
            {recentAudit.map((log) => (
              <div key={log.id} className="py-2.5 flex items-start justify-between gap-3 text-xs">
                <div className="space-y-0.5 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono font-bold text-[#f95721]">{log.action}</span>
                    <span className={`text-[10px] font-mono ${isLight ? 'text-slate-400' : 'text-stone-500'}`}>
                      by {log.user_name}
                    </span>
                  </div>
                  <p className={`font-mono text-[11px] truncate ${isLight ? 'text-slate-600' : 'text-stone-300'}`}>
                    Target: <strong className={isLight ? 'text-slate-900' : 'text-white'}>{log.target_id}</strong> ({log.target_type})
                  </p>
                </div>
                <span className={`text-[10px] font-mono shrink-0 ${isLight ? 'text-slate-400' : 'text-stone-500'}`}>
                  {new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
