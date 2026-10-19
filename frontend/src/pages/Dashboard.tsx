import React from 'react';
import { useApp } from '../store';
import { ThreatMap } from '../components/ThreatMap';

export const Dashboard: React.FC = () => {
  const { 
    currentUser,
    activeCase, 
    cases, 
    activeCaseDetections, 
    activeCaseEvents, 
    setCurrentPage,
    setActiveCaseId
  } = useApp();

  return (
    <div className="space-y-6">
      
      {/* Top 3 Metric Cards (Matching Screenshot 3 with Warm Charcoal & Burnt Orange!) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-5">
        
        {/* 1. Active Incidents Card */}
        <div className="rounded-2xl bg-[#161413]/90 border border-[#2b2523] p-5 backdrop-blur-xl flex items-center justify-between relative overflow-hidden group shadow-xl">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="text-xs text-[#a8a29e] font-medium">Active incidents</span>
              <span className="text-[10px] font-mono text-[#f95721] bg-[#2a140d] px-1.5 py-0.5 rounded border border-[#ea580c]/30 font-semibold">
                &gt; 8%
              </span>
            </div>

            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold font-mono text-[#fafaf9]">
                {activeCaseDetections.length > 0 ? activeCaseDetections.length : 7}
              </span>
              <span className="text-xs text-[#78716c] font-mono">11 last week</span>
            </div>
          </div>

          {/* Radial meter ring (Screenshot 3) */}
          <div className="relative w-14 h-14 shrink-0 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
              <path
                className="text-[#25201e]"
                strokeWidth="3.5"
                stroke="currentColor"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
              <path
                className="text-[#f95721]"
                strokeDasharray="40, 100"
                strokeWidth="3.5"
                strokeLinecap="round"
                stroke="currentColor"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
            </svg>
            <span className="absolute text-[11px] font-mono font-bold text-[#fafaf9]">
              40%
            </span>
          </div>
        </div>

        {/* 2. Compliance Score Card */}
        <div className="rounded-2xl bg-[#161413]/90 border border-[#2b2523] p-5 backdrop-blur-xl flex items-center justify-between relative overflow-hidden group shadow-xl">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="text-xs text-[#a8a29e] font-medium">Compliance score</span>
              <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/40 px-1.5 py-0.5 rounded border border-emerald-900/50 font-semibold">
                ↗ 6%
              </span>
            </div>

            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold font-mono text-[#fafaf9]">51%</span>
              <span className="text-xs text-[#78716c] font-mono">47% last week</span>
            </div>
          </div>

          {/* Green radial arc (Screenshot 3) */}
          <div className="relative w-14 h-14 shrink-0 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
              <path
                className="text-[#25201e]"
                strokeWidth="3.5"
                stroke="currentColor"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
              <path
                className="text-emerald-500"
                strokeDasharray="51, 100"
                strokeWidth="3.5"
                strokeLinecap="round"
                stroke="currentColor"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
            </svg>
            <span className="absolute text-[11px] font-mono font-bold text-[#fafaf9]">
              51%
            </span>
          </div>
        </div>

        {/* 3. Time to Remediate Card */}
        <div className="rounded-2xl bg-[#161413]/90 border border-[#2b2523] p-5 backdrop-blur-xl flex items-center justify-between relative overflow-hidden group shadow-xl sm:col-span-2 lg:col-span-1">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="text-xs text-[#a8a29e] font-medium">Time to remediate</span>
              <span className="text-[10px] font-mono text-[#fb923c] bg-amber-950/40 px-1.5 py-0.5 rounded border border-amber-900/50 font-semibold">
                11%
              </span>
            </div>

            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold font-mono text-[#fafaf9]">2d:6h</span>
              <span className="text-xs text-[#78716c] font-mono">2d: 8h last week</span>
            </div>
          </div>

          {/* Waveform audio/bar meter graphic (Screenshot 3) */}
          <div className="flex items-end gap-1 h-10 w-16 justify-end">
            {[40, 75, 60, 90, 45, 80, 50, 65, 30].map((h, i) => (
              <span
                key={i}
                style={{ height: `${h}%` }}
                className="w-1 rounded-full bg-[#f95721] opacity-85 shadow-[0_0_6px_rgba(249,87,33,0.5)]"
              />
            ))}
          </div>
        </div>

      </div>

      {/* Main Threat Map */}
      <div className="w-full">
        <ThreatMap onOpenReport={() => setCurrentPage('reports')} />
      </div>

    </div>
  );
};
