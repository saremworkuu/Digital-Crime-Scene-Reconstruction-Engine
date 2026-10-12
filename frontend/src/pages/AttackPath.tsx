import React, { useState, useMemo } from 'react';
import { useApp } from '../store';
import { GraphView } from '../components/GraphView';
import {
  GitBranch,
  ShieldAlert,
  ArrowRight,
  Server,
  Globe,
  User,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Sparkles,
  FileCode,
  Terminal,
  ChevronRight,
  Filter,
  Activity,
  Lock,
  Network
} from 'lucide-react';
import { MitreBadge } from '../components/MitreBadge';
import { SeverityTag } from '../components/SeverityTag';
import { NormalizedEvent, GraphNode } from '../types';

export const AttackPath: React.FC = () => {
  const { activeCase, activeCaseGraph, activeCaseEvents, theme } = useApp();
  const isLight = theme === 'light';

  const [activeTab, setActiveTab] = useState<'timeline' | 'topology'>('timeline');
  const [selectedPhase, setSelectedPhase] = useState<string>('all');
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  // Extract events that belong to the adversary attack path
  const attackPathEvents = useMemo(() => {
    const list = activeCaseEvents.filter(e => e.is_attack_path || e.severity === 'critical' || e.severity === 'high');
    return [...list].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  }, [activeCaseEvents]);

  // Extract distinct attack phases / tactics
  const phases = useMemo(() => {
    const set = new Set<string>();
    attackPathEvents.forEach(e => {
      if (e.attack_phase) set.add(e.attack_phase);
      else if (e.mitre_tactic) set.add(e.mitre_tactic);
    });
    return Array.from(set);
  }, [attackPathEvents]);

  // Filtered list based on selected phase
  const filteredEvents = useMemo(() => {
    if (selectedPhase === 'all') return attackPathEvents;
    return attackPathEvents.filter(e => e.attack_phase === selectedPhase || e.mitre_tactic === selectedPhase);
  }, [attackPathEvents, selectedPhase]);

  // Selected event for deep forensic inspection
  const selectedEvent = useMemo(() => {
    if (!selectedEventId) return attackPathEvents[0] || null;
    return attackPathEvents.find(e => e.id === selectedEventId) || attackPathEvents[0] || null;
  }, [selectedEventId, attackPathEvents]);

  // Compromised nodes along attack trajectory
  const pathNodes = useMemo(() => {
    return activeCaseGraph.nodes.filter(n => n.is_attack_path || n.is_compromised);
  }, [activeCaseGraph.nodes]);

  // Filtered graph data containing only attack path entities
  const attackGraphData = useMemo(() => {
    const nodeIds = new Set(pathNodes.map(n => n.id));
    return {
      nodes: pathNodes,
      edges: activeCaseGraph.edges.filter(
        e => (e.is_attack_path || false) && nodeIds.has(e.source) && nodeIds.has(e.target)
      )
    };
  }, [pathNodes, activeCaseGraph.edges]);

  // Calculate dwell time / propagation duration
  const propagationDuration = useMemo(() => {
    if (attackPathEvents.length < 2) return 'Real-time incident';
    const first = new Date(attackPathEvents[0].timestamp).getTime();
    const last = new Date(attackPathEvents[attackPathEvents.length - 1].timestamp).getTime();
    const diffMinutes = Math.round((last - first) / (1000 * 60));
    if (diffMinutes < 60) return `${diffMinutes} minutes`;
    const hours = (diffMinutes / 60).toFixed(1);
    return `${hours} hours`;
  }, [attackPathEvents]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[#282321]">
        <div>
          <div className="text-[11px] font-mono text-[#a8a29e] mb-1 flex items-center gap-1.5">
            <span>&gt;</span>
            <span className="text-[#d6d3d1]">Forensic Reconstruction</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-[#fafaf9] flex items-center gap-2.5">
            <GitBranch className="w-5 h-5 text-[#f95721]" />
            <span>Adversary Attack Path Trajectory</span>
          </h1>
          <p className="text-xs text-[#a8a29e] mt-0.5">
            Case: <strong className="text-[#fafaf9]">{activeCase?.name}</strong> · Chronological kill-chain hops, lateral movement progression, and adversary dwell time
          </p>
        </div>

        {/* View Mode Toggle */}
        <div className="flex items-center gap-3">
          <div className="inline-flex items-center p-1 bg-[#191716] border border-[#2c2724] rounded-lg text-xs font-mono">
            <button
              onClick={() => setActiveTab('timeline')}
              className={`px-3 py-1.5 rounded-md transition-all flex items-center gap-1.5 font-medium cursor-pointer ${
                activeTab === 'timeline'
                  ? 'bg-[#f95721] text-white shadow-[0_0_12px_rgba(249,87,33,0.35)]'
                  : 'text-[#a8a29e] hover:text-[#d6d3d1]'
              }`}
            >
              <Clock className="w-3.5 h-3.5" />
              <span>Kill-Chain Sequence</span>
            </button>
            <button
              onClick={() => setActiveTab('topology')}
              className={`px-3 py-1.5 rounded-md transition-all flex items-center gap-1.5 font-medium cursor-pointer ${
                activeTab === 'topology'
                  ? 'bg-[#f95721] text-white shadow-[0_0_12px_rgba(249,87,33,0.35)]'
                  : 'text-[#a8a29e] hover:text-[#d6d3d1]'
              }`}
            >
              <Network className="w-3.5 h-3.5" />
              <span>Path Topology</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      {activeTab === 'topology' ? (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-[#191716] border border-[#2e2825] flex items-center justify-between text-xs font-mono text-[#a8a29e]">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#f95721] animate-pulse" />
              <span>Isolated Adversary Propagation Graph · Traversal from Ingress to Exfiltration Target</span>
            </div>
            <span className="text-[#f95721] font-semibold">{attackGraphData.nodes.length} Vertices · {attackGraphData.edges.length} Hops</span>
          </div>

          <div className={`rounded-2xl overflow-hidden border ${isLight ? 'border-slate-200 bg-white' : 'border-[#2b2523] bg-[#141211]'}`}>
            <GraphView graphData={attackGraphData} />
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left Column: Kill-Chain Step Sequence (7 cols) */}
          <div className="lg:col-span-7 space-y-4">
            {/* Phase Filters */}
            {phases.length > 0 && (
              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs font-mono">
                <button
                  type="button"
                  onClick={() => setSelectedPhase('all')}
                  className={`px-2.5 py-1 rounded-lg border transition-colors cursor-pointer shrink-0 ${
                    selectedPhase === 'all'
                      ? 'bg-[#2a140d] text-[#f95721] border-[#ea580c]/60 font-semibold'
                      : 'bg-[#161413] text-[#a8a29e] border-[#2b2523] hover:text-[#fafaf9]'
                  }`}
                >
                  All Stages ({attackPathEvents.length})
                </button>
                {phases.map(p => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setSelectedPhase(p)}
                    className={`px-2.5 py-1 rounded-lg border transition-colors cursor-pointer shrink-0 ${
                      selectedPhase === p
                        ? 'bg-[#2a140d] text-[#f95721] border-[#ea580c]/60 font-semibold'
                        : 'bg-[#161413] text-[#a8a29e] border-[#2b2523] hover:text-[#fafaf9]'
                    }`}
                  >
                    {p}
                  </button>
                ))}
              </div>
            )}

            {/* Step-by-Step Vertical Progression Timeline */}
            <div className="space-y-3">
              {filteredEvents.map((evt, idx) => {
                const isSelected = (selectedEvent?.id === evt.id);
                const stepNum = idx + 1;

                return (
                  <div
                    key={evt.id}
                    onClick={() => setSelectedEventId(evt.id)}
                    className={`p-4 rounded-xl border transition-all cursor-pointer relative group ${
                      isSelected
                        ? 'bg-[#22130d] border-[#ea580c] shadow-[0_0_16px_rgba(249,87,33,0.18)]'
                        : 'bg-[#151312] border-[#282321] hover:border-[#3a322e] hover:bg-[#191716]'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-start gap-3 min-w-0">
                        {/* Hop Sequence Number */}
                        <div className={`w-7 h-7 rounded-lg shrink-0 flex items-center justify-center font-mono font-bold text-xs ${
                          isSelected
                            ? 'bg-[#f95721] text-white shadow-md'
                            : 'bg-[#261711] text-[#ff8d60] border border-[#7c2d12]'
                        }`}>
                          {stepNum}
                        </div>

                        <div className="min-w-0 space-y-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-xs font-bold text-[#fafaf9] group-hover:text-[#f95721] transition-colors truncate">
                              {evt.action}
                            </span>
                            {evt.outcome === 'success' ? (
                              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-700/50">
                                EXECUTED
                              </span>
                            ) : (
                              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-amber-950/80 text-amber-300 border border-amber-700/50">
                                PROBE
                              </span>
                            )}
                          </div>

                          {/* Phase & Entity Traversal */}
                          <div className="text-[11px] font-mono text-[#a8a29e] flex flex-wrap items-center gap-2">
                            {evt.attack_phase && (
                              <span className="text-[#f95721] font-medium">{evt.attack_phase}</span>
                            )}
                            {evt.host && (
                              <span>Host: <strong className="text-[#fafaf9]">{evt.host}</strong></span>
                            )}
                            {evt.user && evt.user !== 'SYSTEM' && (
                              <span>User: <strong className="text-[#fafaf9]">{evt.user}</strong></span>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Right Tag: Severity & Technique */}
                      <div className="shrink-0 text-right space-y-1">
                        <SeverityTag severity={evt.severity} />
                        {evt.mitre_technique && (
                          <div className="pt-0.5">
                            <MitreBadge techniqueId={evt.mitre_technique} />
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="mt-2 pt-2 border-t border-[#241e1c] flex items-center justify-between text-[10px] font-mono text-[#78716c]">
                      <span>TIMESTAMP: {new Date(evt.timestamp).toUTCString()}</span>
                      <span className="text-[#f95721] group-hover:underline flex items-center gap-0.5">
                        Inspect Hop <ChevronRight className="w-3 h-3" />
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Column: Deep Forensic Evidence Inspector (5 cols) */}
          <div className="lg:col-span-5 sticky top-[75px] space-y-4">
            {selectedEvent ? (
              <div className="p-5 rounded-2xl bg-[#161413] border border-[#2e2825] shadow-xl space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-[#282321]">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-[#f95721]" />
                    <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-[#fafaf9]">
                      Forensic Hop Deep Dive
                    </h3>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#2a140d] text-[#f95721] border border-[#ea580c]/40 font-semibold">
                    {selectedEvent.id}
                  </span>
                </div>

                <div className="space-y-3 text-xs">
                  <div>
                    <span className="text-[#78716c] text-[11px] block font-mono">ADVERSARY ACTION:</span>
                    <strong className="text-[#fafaf9] text-sm block mt-0.5">{selectedEvent.action}</strong>
                  </div>

                  <div className="grid grid-cols-2 gap-2 pt-2 border-t border-[#25201e] text-[11px] font-mono">
                    <div>
                      <span className="text-[#78716c] block">HOST TARGET:</span>
                      <strong className="text-[#fafaf9]">{selectedEvent.host || 'N/A'}</strong>
                    </div>
                    <div>
                      <span className="text-[#78716c] block">USER CONTEXT:</span>
                      <strong className="text-[#fafaf9]">{selectedEvent.user || 'N/A'}</strong>
                    </div>
                    <div>
                      <span className="text-[#78716c] block">INGRESS IP:</span>
                      <strong className="text-[#ff8d60]">{selectedEvent.src_ip || 'External C2'}</strong>
                    </div>
                    <div>
                      <span className="text-[#78716c] block">TARGET IP / PORT:</span>
                      <strong className="text-[#fafaf9]">{selectedEvent.dst_ip ? `${selectedEvent.dst_ip}:${selectedEvent.dst_port || 0}` : 'Local Process'}</strong>
                    </div>
                  </div>

                  {selectedEvent.process && (
                    <div className="pt-2 border-t border-[#25201e]">
                      <span className="text-[#78716c] text-[11px] block font-mono">SPAWNED PROCESS:</span>
                      <code className="text-[#fb923c] font-mono text-[11px] bg-[#0d0c0c] px-2 py-1 rounded block mt-0.5 border border-[#29221f]">
                        {selectedEvent.process}
                      </code>
                    </div>
                  )}

                  {/* MITRE Mapping */}
                  <div className="pt-2 border-t border-[#25201e] flex items-center justify-between text-xs">
                    <span className="text-[#78716c] font-mono">TACTIC / ATT&CK:</span>
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-[#fb923c]">{selectedEvent.mitre_tactic || 'Execution'}</span>
                      {selectedEvent.mitre_technique && (
                        <MitreBadge techniqueId={selectedEvent.mitre_technique} />
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-8 rounded-2xl bg-[#161413] border border-[#2e2825] text-center text-[#78716c] text-xs font-mono">
                Select an attack path hop to inspect forensic attributes.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
