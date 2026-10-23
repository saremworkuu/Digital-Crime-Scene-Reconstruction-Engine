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
import {
  usersService,
  casesService,
  evidenceService,
  messagesService,
  systemService,
  auditService
} from '../../services/admin';
import { AdminAuditEntry, AdminQueueJob } from '../types';

interface DashboardPageProps {
  onNavigateTab: (tab: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigateTab }) => {
  const [counts, setCounts] = useState({
    users: 0,
    cases: 0,
    evidence: 0,
    failures: 0,
    newMessages: 0,
    failedLogins24h: 0
  });

  const [recentAudit, setRecentAudit] = useState<AdminAuditEntry[]>([]);
  const [queueJobs, setQueueJobs] = useState<AdminQueueJob[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const loadMetrics = async () => {
    setIsLoading(true);
    try {
      const [u, c, e, m, health, audit] = await Promise.all([
        usersService.getUsers(),
        casesService.getCases(),
        evidenceService.getEvidence(),
        messagesService.getNewMessagesCount(),
        systemService.getSystemHealth(),
        auditService.getAuditLogs({ limit: 6 })
      ]);

      const failedEvidence = e.filter((item) => item.parsing_status === 'failed').length;

      setCounts({
        users: u.length,
        cases: c.length,
        evidence: e.length,
        failures: failedEvidence,
        newMessages: m,
        failedLogins24h: health.failed_logins_24h
      });

      setRecentAudit(audit.entries);
      setQueueJobs(health.queue);
    } catch (err) {
      console.error('[Dashboard] Error loading metrics:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadMetrics();
  }, []);

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#282321]">
        <div>
          <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight font-sans flex items-center gap-2.5">
            <ShieldCheck className="w-6 h-6 text-[#f95721]" />
            <span>Admin Control Console</span>
          </h1>
          <p className="text-xs sm:text-sm text-stone-400 font-sans mt-0.5">
            Telemetry oversight, RBAC enforcement, evidence integrity, and inbox operations
          </p>
        </div>

        <button
          type="button"
          onClick={loadMetrics}
          className="flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-mono text-stone-300 bg-[#1a1715] hover:bg-[#25201d] border border-[#332b27] hover:border-[#f95721] transition-all cursor-pointer w-fit"
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
        <div className="lg:col-span-5 rounded-2xl bg-[#141211]/90 border border-[#2b2523] p-5 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#26201e]">
            <div className="flex items-center gap-2 text-white font-bold text-sm font-sans">
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
            <div className="p-3 rounded-xl bg-black/40 border border-[#2e2623] space-y-1">
              <span className="text-[10px] font-mono uppercase text-stone-400">Failed Logins (24h)</span>
              <div className="text-xl font-bold font-mono text-red-400">{counts.failedLogins24h}</div>
            </div>
            <div className="p-3 rounded-xl bg-black/40 border border-[#2e2623] space-y-1">
              <span className="text-[10px] font-mono uppercase text-stone-400">Queue Jobs Active</span>
              <div className="text-xl font-bold font-mono text-amber-400">{queueJobs.length}</div>
            </div>
          </div>

          {/* Queue Jobs List */}
          <div className="space-y-2">
            <span className="text-[11px] font-mono text-stone-400 uppercase tracking-wider font-semibold block">
              Active Queue Stream
            </span>
            {queueJobs.map((job) => (
              <div
                key={job.id}
                className="p-2.5 rounded-xl bg-black/30 border border-[#28221f] flex items-center justify-between gap-3 text-xs"
              >
                <div className="min-w-0">
                  <div className="font-mono text-stone-200 truncate">{job.file_name}</div>
                  <div className="text-[10px] text-stone-500 font-mono">
                    Parser: {job.parser_type} · Started: {new Date(job.started_at).toLocaleTimeString()}
                  </div>
                </div>
                <StatusBadge status={job.status} />
              </div>
            ))}
          </div>
        </div>

        {/* Recent Audit Activity */}
        <div className="lg:col-span-7 rounded-2xl bg-[#141211]/90 border border-[#2b2523] p-5 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#26201e]">
            <div className="flex items-center gap-2 text-white font-bold text-sm font-sans">
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

          <div className="divide-y divide-[#221c1a]">
            {recentAudit.map((log) => (
              <div key={log.id} className="py-2.5 flex items-start justify-between gap-3 text-xs">
                <div className="space-y-0.5 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono font-bold text-[#ff936b]">{log.action}</span>
                    <span className="text-[10px] font-mono text-stone-500">by {log.user_name}</span>
                  </div>
                  <p className="text-stone-300 font-mono text-[11px] truncate">
                    Target: <strong className="text-white">{log.target_id}</strong> ({log.target_type})
                  </p>
                </div>
                <span className="text-[10px] font-mono text-stone-500 shrink-0">
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
