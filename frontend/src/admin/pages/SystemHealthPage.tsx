import React, { useState, useEffect } from 'react';
import {
  Activity,
  Server,
  RefreshCw,
  HardDrive,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  RotateCw,
  Cpu,
  Layers,
  FileCode2,
  Radio
} from 'lucide-react';
import { systemService } from '../../services/admin';
import { AdminSystemHealth, AdminParserStatus, AdminQueueJob } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { toast } from '../../components/Toast';
import { useApp } from '../../store';

export const SystemHealthPage: React.FC = () => {
  const { theme } = useApp();
  const isLight = theme === 'light';

  const [health, setHealth] = useState<AdminSystemHealth | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [retryingJobId, setRetryingJobId] = useState<string | null>(null);

  const loadHealth = async () => {
    setIsLoading(true);
    try {
      const data = await systemService.getSystemHealth();
      setHealth(data);
    } catch (err: any) {
      toast.error('Failed to load system health: ' + err.message);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadHealth();
  }, []);

  const handleRetryJob = async (jobId: string) => {
    setRetryingJobId(jobId);
    try {
      await systemService.retryQueueJob(jobId);
      toast.success('Ingestion retry dispatched for job ' + jobId);
      await loadHealth();
    } catch (err: any) {
      toast.error('Retry failed: ' + err.message);
    } finally {
      setRetryingJobId(null);
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const usedPercentage = health
    ? Math.min(100, Math.round((health.storage_used_bytes / health.storage_total_bytes) * 100))
    : 0;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b ${
        isLight ? 'border-slate-200' : 'border-[#2e2926]'
      }`}>
        <div>
          <h1 className={`text-xl font-bold tracking-tight flex items-center gap-2.5 ${
            isLight ? 'text-slate-900' : 'text-[#e7e5e4]'
          }`}>
            <Activity className="w-5 h-5 text-[#f95721]" />
            System Health & Engine Telemetry
          </h1>
          <p className={`text-xs mt-1 ${isLight ? 'text-slate-500' : 'text-[#a8a29e]'}`}>
            Real-time ingestion pipeline status, forensic parser heartbeat, storage utilization, and background worker queues.
          </p>
        </div>
        <button
          onClick={loadHealth}
          disabled={isLoading}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors cursor-pointer self-start sm:self-auto disabled:opacity-50 border ${
            isLight
              ? 'bg-white hover:bg-slate-50 text-slate-700 border-slate-300'
              : 'bg-[#1c1917] hover:bg-[#25201e] text-[#d6d3d1] border-[#332c28]'
          }`}
        >
          <RefreshCw className={`w-3.5 h-3.5 text-[#f95721] ${isLoading ? 'animate-spin' : ''}`} />
          Refresh Metrics
        </button>
      </div>

      {/* Storage and Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Storage Meter */}
        <div className={`md:col-span-2 rounded-xl p-5 space-y-4 border ${
          isLight
            ? 'bg-white border-slate-200 text-slate-800 shadow-sm'
            : 'bg-[#121110] border-[#24201e]'
        }`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className={`w-9 h-9 rounded-lg flex items-center justify-center border ${
                isLight
                  ? 'bg-orange-50 border-orange-200 text-[#f95721]'
                  : 'bg-[#24130d] border-[#ea580c]/30 text-[#f95721]'
              }`}>
                <HardDrive className="w-4 h-4" />
              </div>
              <div>
                <h3 className={`text-sm font-semibold ${isLight ? 'text-slate-900' : 'text-[#e7e5e4]'}`}>Forensic Storage Allocation</h3>
                <p className={`text-xs ${isLight ? 'text-slate-500' : 'text-[#78716c]'}`}>Evidence vaults, indexed WAL partitions & graph databases</p>
              </div>
            </div>
            <div className="text-right">
              <div className={`text-lg font-mono font-bold ${isLight ? 'text-slate-900' : 'text-[#e7e5e4]'}`}>{usedPercentage}%</div>
              <div className={`text-[11px] font-mono ${isLight ? 'text-slate-500' : 'text-[#78716c]'}`}>
                {health ? `${formatBytes(health.storage_used_bytes)} / ${formatBytes(health.storage_total_bytes)}` : '...'}
              </div>
            </div>
          </div>

          {/* Progress Bar */}
          <div className={`w-full rounded-full h-3 overflow-hidden border ${
            isLight ? 'bg-slate-100 border-slate-200' : 'bg-[#1c1917] border-[#2e2926]'
          }`}>
            <div
              className={`h-full transition-all duration-500 ${
                usedPercentage > 85 ? 'bg-red-500' : usedPercentage > 65 ? 'bg-amber-500' : 'bg-[#f95721]'
              }`}
              style={{ width: `${usedPercentage}%` }}
            />
          </div>

          <div className={`flex items-center justify-between text-[11px] pt-1 ${
            isLight ? 'text-slate-500' : 'text-[#78716c]'
          }`}>
            <span>Primary Disk: NVMe Array /opt/dcsre/vault</span>
            <span>Free: {health ? formatBytes(health.storage_total_bytes - health.storage_used_bytes) : '...'}</span>
          </div>
        </div>

        {/* Failed Logins Card */}
        <div className={`rounded-xl p-5 flex flex-col justify-between border ${
          isLight
            ? 'bg-white border-slate-200 text-slate-800 shadow-sm'
            : 'bg-[#121110] border-[#24201e]'
        }`}>
          <div className="flex items-center gap-2.5">
            <div className={`w-9 h-9 rounded-lg flex items-center justify-center border ${
              isLight
                ? 'bg-rose-50 border-rose-200 text-rose-600'
                : 'bg-red-950/40 border-red-500/30 text-red-400'
            }`}>
              <AlertTriangle className="w-4 h-4" />
            </div>
            <div>
              <h3 className={`text-sm font-semibold ${isLight ? 'text-slate-900' : 'text-[#e7e5e4]'}`}>Security Lockouts (24h)</h3>
              <p className={`text-xs ${isLight ? 'text-slate-500' : 'text-[#78716c]'}`}>Failed authentication attempts</p>
            </div>
          </div>

          <div className="my-4">
            <div className={`text-3xl font-mono font-bold ${isLight ? 'text-slate-900' : 'text-[#e7e5e4]'}`}>
              {health?.failed_logins_24h ?? 0}
            </div>
            <p className={`text-xs mt-1 ${isLight ? 'text-slate-500' : 'text-[#a8a29e]'}`}>
              Rate limiting and account lockout auto-trigger at 5 attempts.
            </p>
          </div>

          <div className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5" />
            WAF & Threat Guard Active
          </div>
        </div>
      </div>

      {/* Parser Heartbeats per Type */}
      <div className={`rounded-xl p-5 space-y-4 border ${
        isLight
          ? 'bg-white border-slate-200 text-slate-800 shadow-sm'
          : 'bg-[#121110] border-[#24201e]'
      }`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#f95721]" />
            <h2 className={`text-sm font-semibold ${isLight ? 'text-slate-900' : 'text-[#e7e5e4]'}`}>Evidence Parser Engines (8 Types)</h2>
          </div>
          <span className={`text-[11px] font-mono ${isLight ? 'text-slate-500' : 'text-[#78716c]'}`}>Automated Heuristic Normalizers</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {health?.parsers.map((parser) => (
            <div
              key={parser.type}
              className={`rounded-lg p-3.5 transition-colors space-y-3 border ${
                isLight
                  ? 'bg-slate-50 border-slate-200 hover:border-slate-300'
                  : 'bg-[#181615] border-[#292422] hover:border-[#3d3632]'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                  isLight
                    ? 'bg-orange-50 text-[#f95721] border-orange-200'
                    : 'bg-[#24130d] text-[#f95721] border-[#ea580c]/30'
                }`}>
                  {parser.type}
                </span>
                <StatusBadge status={parser.status} />
              </div>

              <div className={`space-y-1.5 text-xs ${isLight ? 'text-slate-600' : 'text-[#a8a29e]'}`}>
                <div className="flex justify-between">
                  <span className={isLight ? 'text-slate-500' : 'text-[#78716c]'}>Success Rate:</span>
                  <span className={`font-mono font-medium ${isLight ? 'text-slate-900' : 'text-[#e7e5e4]'}`}>{parser.success_rate}</span>
                </div>
                <div className="flex justify-between">
                  <span className={isLight ? 'text-slate-500' : 'text-[#78716c]'}>Avg Latency:</span>
                  <span className={`font-mono ${isLight ? 'text-slate-800' : 'text-[#e7e5e4]'}`}>{parser.avg_latency}</span>
                </div>
                <div className="flex justify-between">
                  <span className={isLight ? 'text-slate-500' : 'text-[#78716c]'}>Processed:</span>
                  <span className={`font-mono ${isLight ? 'text-slate-700' : 'text-[#d6d3d1]'}`}>{parser.files_processed} files</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Ingestion Worker Queue Table */}
      <div className={`rounded-xl p-5 space-y-4 border ${
        isLight
          ? 'bg-white border-slate-200 text-slate-800 shadow-sm'
          : 'bg-[#121110] border-[#24201e]'
      }`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <RotateCw className="w-4 h-4 text-[#f95721]" />
            <h2 className={`text-sm font-semibold ${isLight ? 'text-slate-900' : 'text-[#e7e5e4]'}`}>Background Ingestion Queue</h2>
          </div>
          <span className={`text-[11px] font-mono ${isLight ? 'text-slate-500' : 'text-[#78716c]'}`}>Async Worker Tasks</span>
        </div>

        {health && health.queue.length > 0 ? (
          <div className={`overflow-x-auto rounded-lg border ${
            isLight ? 'border-slate-200' : 'border-[#24201e]'
          }`}>
            <table className="w-full text-left text-xs">
              <thead className={`uppercase font-mono text-[10px] tracking-wider border-b ${
                isLight
                  ? 'bg-slate-50 text-slate-600 border-slate-200'
                  : 'bg-[#181615] text-[#a8a29e] border-[#2e2926]'
              }`}>
                <tr>
                  <th className="py-2.5 px-3">Job ID</th>
                  <th className="py-2.5 px-3">Target File</th>
                  <th className="py-2.5 px-3">Parser</th>
                  <th className="py-2.5 px-3">Queued At</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Diagnostic Error</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className={`font-sans divide-y ${
                isLight ? 'divide-slate-100' : 'divide-[#24201e]'
              }`}>
                {health.queue.map((job) => (
                  <tr key={job.id} className={`transition-colors ${
                    isLight ? 'hover:bg-slate-50/80' : 'hover:bg-[#1a1816]'
                  }`}>
                    <td className="py-3 px-3 font-mono text-[#f95721] font-medium">{job.id}</td>
                    <td className={`py-3 px-3 font-medium flex items-center gap-1.5 ${
                      isLight ? 'text-slate-900' : 'text-[#e7e5e4]'
                    }`}>
                      <FileCode2 className={`w-3.5 h-3.5 ${isLight ? 'text-slate-400' : 'text-[#78716c]'}`} />
                      {job.file_name}
                    </td>
                    <td className={`py-3 px-3 font-mono ${isLight ? 'text-slate-600' : 'text-[#a8a29e]'}`}>{job.parser_type}</td>
                    <td className={`py-3 px-3 font-mono ${isLight ? 'text-slate-500' : 'text-[#78716c]'}`}>
                      {new Date(job.started_at).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-3">
                      <StatusBadge status={job.status} />
                    </td>
                    <td className={`py-3 px-3 max-w-xs truncate ${isLight ? 'text-slate-600' : 'text-[#a8a29e]'}`}>
                      {job.error ? (
                        <span className="text-red-500 dark:text-red-400 font-mono text-[11px] flex items-center gap-1">
                          <XCircle className="w-3 h-3 shrink-0" />
                          {job.error}
                        </span>
                      ) : (
                        <span className={`italic ${isLight ? 'text-slate-400' : 'text-[#78716c]'}`}>None</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-right">
                      {job.status === 'failed' && (
                        <button
                          onClick={() => handleRetryJob(job.id)}
                          disabled={retryingJobId === job.id}
                          className={`px-2.5 py-1 text-xs rounded font-medium border transition-colors cursor-pointer disabled:opacity-50 inline-flex items-center gap-1.5 ${
                            isLight
                              ? 'bg-orange-50 text-[#f95721] hover:bg-orange-100 border-orange-200'
                              : 'bg-[#24130d] text-[#f95721] hover:bg-[#33170e] border-[#ea580c]/40'
                          }`}
                        >
                          <RefreshCw className={`w-3 h-3 ${retryingJobId === job.id ? 'animate-spin' : ''}`} />
                          Retry
                        </button>
                      )}
                      {job.status === 'processing' && (
                        <span className="text-[11px] text-amber-500 dark:text-amber-400 font-mono flex items-center gap-1 justify-end">
                          <RotateCw className="w-3 h-3 animate-spin" /> In Progress
                        </span>
                      )}
                      {job.status === 'completed' && (
                        <span className="text-[11px] text-emerald-600 dark:text-emerald-400 font-mono flex items-center gap-1 justify-end">
                          <CheckCircle2 className="w-3 h-3" /> Done
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className={`text-center py-6 text-xs ${isLight ? 'text-slate-400' : 'text-[#78716c]'}`}>No active background queue jobs.</div>
        )}
      </div>

      {/* Recent Engine Errors Log */}
      <div className={`rounded-xl p-5 space-y-4 border ${
        isLight
          ? 'bg-white border-slate-200 text-slate-800 shadow-sm'
          : 'bg-[#121110] border-[#24201e]'
      }`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-500" />
            <h2 className={`text-sm font-semibold ${isLight ? 'text-slate-900' : 'text-[#e7e5e4]'}`}>Recent Ingestion Errors & Core Exceptions</h2>
          </div>
          <span className={`text-[11px] font-mono ${isLight ? 'text-slate-500' : 'text-[#78716c]'}`}>Last 24 Hours</span>
        </div>

        {health && health.recent_errors.length > 0 ? (
          <div className="space-y-2">
            {health.recent_errors.map((err, idx) => (
              <div
                key={idx}
                className={`p-3 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs border ${
                  isLight
                    ? 'bg-slate-50 border-slate-200'
                    : 'bg-[#181615] border-[#292422]'
                }`}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <XCircle className="w-4 h-4 text-red-500 dark:text-red-400 shrink-0" />
                  <span className={`font-mono text-[11px] px-1.5 py-0.5 rounded border shrink-0 ${
                    isLight
                      ? 'bg-orange-50 text-[#f95721] border-orange-200'
                      : 'bg-[#24130d] text-[#f95721] border-[#ea580c]/30'
                  }`}>
                    {err.component}
                  </span>
                  <span className={`font-mono truncate ${isLight ? 'text-slate-800' : 'text-[#e7e5e4]'}`}>{err.message}</span>
                </div>
                <span className={`text-[11px] font-mono shrink-0 self-end sm:self-auto ${
                  isLight ? 'text-slate-500' : 'text-[#78716c]'
                }`}>
                  {new Date(err.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className={`text-center py-6 text-xs ${isLight ? 'text-slate-400' : 'text-[#78716c]'}`}>No engine errors logged.</div>
        )}
      </div>
    </div>
  );
};
