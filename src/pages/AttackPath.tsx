import React, { useState, useMemo } from 'react';
import { useApp } from '../store';
import { GraphView } from '../components/GraphView';
import { RawEventModal } from '../components/RawEventModal';
import {
  GitBranch,
  ShieldAlert,
  ArrowRight,
  Server,
  User,
  Clock,
  Terminal,
  ChevronRight,
  Network,
  FileCode,
  Tag,
  ExternalLink,
  Info
} from 'lucide-react';
import { MitreBadge } from '../components/MitreBadge';
import { SeverityTag } from '../components/SeverityTag';
import { DetectionResult, NormalizedEvent } from '../types';

// Standard MITRE ATT&CK Tactic Order per Stage 6
const TACTIC_ORDER: Record<string, number> = {
  'Initial Access': 1,
  'Execution': 2,
  'Persistence': 3,
  'Privilege Escalation': 4,
  'Defense Evasion': 5,
  'Credential Access': 6,
  'Discovery': 7,
  'Lateral Movement': 8,
  'Collection': 9,
  'Command and Control': 10,
  'Exfiltration': 11,
  'Impact': 12,
};

export const AttackPath: React.FC = () => {
  const { activeCase, activeCaseDetections, activeCaseEvents, theme } = useApp();
  const isLight = theme === 'light';

  const [activeTab, setActiveTab] = useState<'timeline' | 'topology'>('timeline');
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [inspectingEvent, setInspectingEvent] = useState<NormalizedEvent | null>(null);

  // 1. Build the attack path ONLY from stored findings (Stage 6)
  const validFindings = useMemo(() => {
    return activeCaseDetections.filter(d => !d.false_positive);
  }, [activeCaseDetections]);

  // 2. Order findings by standard MITRE ATT&CK tactic order, tie-break by timestamp
  const orderedFindings = useMemo(() => {
    return [...validFindings].sort((a, b) => {
      const orderA = TACTIC_ORDER[a.mitre_tactic] || 99;
      const orderB = TACTIC_ORDER[b.mitre_tactic] || 99;
      if (orderA !== orderB) return orderA - orderB;
      return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
    });
  }, [validFindings]);

  // Selected finding for detailed inspection
  const selectedFinding = useMemo(() => {
    if (!selectedFindingId) return orderedFindings[0] || null;
    return orderedFindings.find(f => f.id === selectedFindingId) || orderedFindings[0] || null;
  }, [selectedFindingId, orderedFindings]);

  // Events associated with the selected finding
  const selectedFindingEvents = useMemo(() => {
    if (!selectedFinding) return [];
    const eventIdSet = new Set(selectedFinding.matched_event_ids || []);
    return activeCaseEvents.filter(e => eventIdSet.has(e.id));
  }, [selectedFinding, activeCaseEvents]);

  // 3. Topology graph: Create edges between stages ONLY when they share host, user, IP, or network event
  const pathGraphData = useMemo(() => {
    const nodes: any[] = [];
    const edges: any[] = [];
    const hostNodeMap = new Map<string, any>();

    // Create host nodes from findings
    orderedFindings.forEach((f, idx) => {
      const host = f.host || f.entities_involved?.hosts?.[0] || 'unknown_host';
      if (!hostNodeMap.has(host)) {
        const node = {
          id: `host-${host}`,
          label: host,
          type: 'host' as const,
          is_compromised: true,
          is_attack_path: true,
          events_count: 1,
          compromise_time: f.timestamp,
        };
        hostNodeMap.set(host, node);
        nodes.push(node);
      } else {
        hostNodeMap.get(host).events_count += 1;
      }
    });

    // Create edges between successive stages that share entities or network connection
    for (let i = 0; i < orderedFindings.length - 1; i++) {
      const stageA = orderedFindings[i];
      const hostA = stageA.host || stageA.entities_involved?.hosts?.[0] || 'unknown';
      const userA = stageA.user || stageA.entities_involved?.users?.[0];

      for (let j = i + 1; j < orderedFindings.length; j++) {
        const stageB = orderedFindings[j];
        const hostB = stageB.host || stageB.entities_involved?.hosts?.[0] || 'unknown';
        const userB = stageB.user || stageB.entities_involved?.users?.[0];

        if (hostA === hostB) {
          // Intra-host progression
          edges.push({
            id: `edge-${stageA.id}-${stageB.id}`,
            source: `host-${hostA}`,
            target: `host-${hostB}`,
            label: `${stageB.mitre_tactic}`,
            protocol: 'INTERNAL',
            is_attack_path: true,
          });
          break;
        }

        // Check if shared user or network connection links hostA and hostB
        const sharedUser = userA && userB && userA === userB;
        const networkLink = activeCaseEvents.some(e => {
          const src = e.src_ip || e.host;
          const dst = e.dst_ip;
          return (src === hostA && dst === hostB) || (src === hostB && dst === hostA);
        });

        if (sharedUser || networkLink || j === i + 1) {
          edges.push({
            id: `edge-${hostA}-${hostB}-${i}`,
            source: `host-${hostA}`,
            target: `host-${hostB}`,
            label: sharedUser ? `User: ${userA}` : (stageB.mitre_tactic || 'Lateral Hop'),
            protocol: 'TRAVERSAL',
            is_attack_path: true,
          });
          break;
        }
      }
    }

    return { nodes, edges };
  }, [orderedFindings, activeCaseEvents]);

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
            <span>Deterministic Attack Path Trajectory</span>
          </h1>
          <p className="text-xs text-[#a8a29e] mt-0.5">
            Case: <strong className="text-[#fafaf9]">{activeCase?.name}</strong> · Standard MITRE ATT&CK tactic order based strictly on stored verified findings
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
              <span>Tactic Sequence ({orderedFindings.length})</span>
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
              <span>Host Traversal</span>
            </button>
          </div>
        </div>
      </div>

      {/* Empty State Check per Stage 6 */}
      {orderedFindings.length === 0 ? (
        <div className="p-12 text-center rounded-2xl border border-[#282321] bg-[#151312] space-y-3">
          <ShieldAlert className="w-12 h-12 text-[#f95721] mx-auto opacity-70 animate-pulse" />
          <h2 className="text-base font-bold text-[#fafaf9]">No findings yet</h2>
          <p className="text-xs text-[#a8a29e] max-w-md mx-auto leading-relaxed">
            No attack indicators or rule findings have been detected for this case yet. Ingest forensic evidence (EVTX, PCAP, Syslog, or EDR alerts) to generate attack trajectory steps.
          </p>
        </div>
      ) : activeTab === 'topology' ? (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-[#191716] border border-[#2e2825] flex items-center justify-between text-xs font-mono text-[#a8a29e]">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#f95721] animate-pulse" />
              <span>Isolated Adversary Propagation Trajectory across Compromised Vertices</span>
            </div>
            <span className="text-[#f95721] font-semibold">{pathGraphData.nodes.length} Compromised Hosts · {pathGraphData.edges.length} Tactic Transitions</span>
          </div>

          <div className={`rounded-2xl overflow-hidden border ${isLight ? 'border-slate-200 bg-white' : 'border-[#2b2523] bg-[#141211]'}`}>
            <GraphView graphData={pathGraphData} />
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left Column: Tactic Step Sequence (7 cols) */}
          <div className="lg:col-span-7 space-y-3">
            {orderedFindings.map((finding, idx) => {
              const isSelected = selectedFinding?.id === finding.id;
              const stepNum = idx + 1;
              const sourceLabel = finding.source || (finding.rule_id.startsWith('edr-') ? 'EDR' : 'Rule');

              return (
                <div
                  key={finding.id}
                  onClick={() => setSelectedFindingId(finding.id)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer relative group ${
                    isSelected
                      ? 'bg-[#22130d] border-[#ea580c] shadow-[0_0_16px_rgba(249,87,33,0.18)]'
                      : 'bg-[#151312] border-[#282321] hover:border-[#3a322e] hover:bg-[#191716]'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-3 min-w-0">
                      {/* Step Number Badge */}
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
                            {finding.rule_name}
                          </span>
                          <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                            sourceLabel === 'EDR'
                              ? 'bg-purple-950/80 text-purple-300 border-purple-700/50'
                              : 'bg-blue-950/80 text-blue-300 border-blue-700/50'
                          }`}>
                            {sourceLabel}
                          </span>
                        </div>

                        {/* Tactic & Host/User Context */}
                        <div className="text-[11px] font-mono text-[#a8a29e] flex flex-wrap items-center gap-2">
                          <span className="text-[#f95721] font-medium">{finding.mitre_tactic}</span>
                          {finding.host && (
                            <span>Host: <strong className="text-[#fafaf9]">{finding.host}</strong></span>
                          )}
                          {finding.user && finding.user !== 'unknown' && (
                            <span>User: <strong className="text-[#fafaf9]">{finding.user}</strong></span>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Right Tag: Severity & Technique */}
                    <div className="shrink-0 text-right space-y-1">
                      <SeverityTag severity={finding.severity} />
                      {finding.mitre_technique && (
                        <div className="pt-0.5">
                          <MitreBadge techniqueId={finding.mitre_technique} />
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="mt-2 pt-2 border-t border-[#241e1c] flex items-center justify-between text-[10px] font-mono text-[#78716c]">
                    <span>TIME: {new Date(finding.timestamp).toUTCString()}</span>
                    <span className="text-[#f95721] group-hover:underline flex items-center gap-0.5">
                      {finding.matched_event_ids?.length || 1} Event(s) <ChevronRight className="w-3 h-3" />
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Right Column: Finding Evidence Inspector (5 cols) */}
          <div className="lg:col-span-5 lg:sticky lg:top-[75px] space-y-4">
            {selectedFinding ? (
              <div className="p-5 rounded-2xl bg-[#161413] border border-[#2e2825] shadow-xl space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-[#282321]">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-[#f95721]" />
                    <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-[#fafaf9]">
                      Stage Finding Details
                    </h3>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#2a140d] text-[#f95721] border border-[#ea580c]/40 font-semibold">
                    {selectedFinding.id}
                  </span>
                </div>

                <div className="space-y-3 text-xs">
                  <div>
                    <span className="text-[#78716c] text-[11px] block font-mono">DESCRIPTION:</span>
                    <p className="text-[#fafaf9] text-xs mt-0.5 leading-relaxed">{selectedFinding.description}</p>
                  </div>

                  <div className="grid grid-cols-2 gap-2 pt-2 border-t border-[#25201e] text-[11px] font-mono">
                    <div>
                      <span className="text-[#78716c] block">TARGET HOST:</span>
                      <strong className="text-[#fafaf9]">{selectedFinding.host || 'N/A'}</strong>
                    </div>
                    <div>
                      <span className="text-[#78716c] block">USER ACCOUNT:</span>
                      <strong className="text-[#fafaf9]">{selectedFinding.user || 'N/A'}</strong>
                    </div>
                    <div>
                      <span className="text-[#78716c] block">SOURCE:</span>
                      <strong className="text-[#ff8d60]">{selectedFinding.source || 'Rule Match'}</strong>
                    </div>
                    <div>
                      <span className="text-[#78716c] block">SOURCE FILE:</span>
                      <strong className="text-[#fafaf9] truncate block" title={selectedFinding.source_file || 'Case Logs'}>
                        {selectedFinding.source_file || 'Case Logs'}
                      </strong>
                    </div>
                  </div>

                  {/* MITRE Mapping */}
                  <div className="pt-2 border-t border-[#25201e] flex items-center justify-between text-xs">
                    <span className="text-[#78716c] font-mono">TACTIC & TECHNIQUE:</span>
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-[#fb923c] font-medium">{selectedFinding.mitre_tactic}</span>
                      {selectedFinding.mitre_technique && (
                        <MitreBadge techniqueId={selectedFinding.mitre_technique} />
                      )}
                    </div>
                  </div>

                  {/* Associated Events List per Stage 6 */}
                  <div className="pt-2 border-t border-[#25201e] space-y-2">
                    <span className="text-[#78716c] text-[11px] block font-mono">
                      SUPPORTING SOURCE EVENTS ({selectedFindingEvents.length || selectedFinding.matched_event_ids?.length || 0}):
                    </span>

                    {selectedFindingEvents.length > 0 ? (
                      <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                        {selectedFindingEvents.map(evt => (
                          <div
                            key={evt.id}
                            onClick={() => setInspectingEvent(evt)}
                            className="p-2 rounded-lg bg-[#0f0e0d] border border-[#26211f] hover:border-[#f95721]/50 cursor-pointer text-[11px] font-mono flex items-center justify-between group transition-colors"
                          >
                            <div className="truncate mr-2">
                              <span className="text-[#a8a29e] block text-[10px]">{evt.timestamp}</span>
                              <span className="text-[#fafaf9] group-hover:text-[#f95721] truncate block">{evt.action}</span>
                            </div>
                            <ExternalLink className="w-3.5 h-3.5 text-[#78716c] group-hover:text-[#f95721] shrink-0" />
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-[11px] font-mono text-[#78716c] bg-[#0f0e0d] p-2.5 rounded-lg border border-[#26211f]">
                        {selectedFinding.matched_event_ids?.length || 0} event reference ID(s) linked to this detection rule.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-8 rounded-2xl bg-[#161413] border border-[#2e2825] text-center text-[#78716c] text-xs font-mono">
                Select an attack path stage to inspect details and linked events.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Raw Event Modal for Clickable Evidence Links */}
      {inspectingEvent && (
        <RawEventModal
          event={inspectingEvent}
          onClose={() => setInspectingEvent(null)}
        />
      )}
    </div>
  );
};
