import React, { useState } from 'react';
import { useApp } from '../store';
import { DetectionResult, DetectionRule, EventSeverity } from '../types';
import { SeverityTag } from '../components/SeverityTag';
import { MitreBadge } from '../components/MitreBadge';
import { CyberThreatGlobe } from '../components/CyberThreatGlobe';
import {
  ShieldAlert,
  FileCode,
  CheckCircle,
  XCircle,
  Plus,
  RefreshCw,
  Eye,
  X,
  Code2,
  AlertTriangle,
  Globe2,
  ListFilter,
  Layers,
  Sparkles
} from 'lucide-react';

export const Detections: React.FC = () => {
  const {
    activeCase,
    activeCaseDetections,
    rules,
    toggleFalsePositive,
    addSigmaRule,
    reloadSigmaRules,
    currentUser
  } = useApp();

  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [showFalsePositives, setShowFalsePositives] = useState(false);
  const [activeTab, setActiveTab] = useState<'findings' | 'rules' | 'sphere'>('findings');
  const [globeMode, setGlobeMode] = useState<'default' | 'advanced'>('default');

  // Modal states
  const [selectedRuleView, setSelectedRuleView] = useState<DetectionRule | null>(null);
  const [isAddRuleOpen, setIsAddRuleOpen] = useState(false);
  const [newRuleName, setNewRuleName] = useState('');
  const [newRuleDesc, setNewRuleDesc] = useState('');
  const [newRuleSeverity, setNewRuleSeverity] = useState<EventSeverity>('high');
  const [newRuleTechnique, setNewRuleTechnique] = useState('T1059.001');
  const [newRuleTactic, setNewRuleTactic] = useState('Execution');
  const [newRuleYaml, setNewRuleYaml] = useState('');

  // False positive dialog
  const [fpTargetId, setFpTargetId] = useState<string | null>(null);
  const [fpReason, setFpReason] = useState('');

  const filteredDetections = activeCaseDetections.filter(d => {
    if (!showFalsePositives && d.false_positive) return false;
    if (filterSeverity !== 'all' && d.severity !== filterSeverity) return false;
    return true;
  });

  const handleAddRuleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleName.trim()) return;

    addSigmaRule({
      name: newRuleName.trim(),
      description: newRuleDesc.trim(),
      severity: newRuleSeverity,
      mitre_technique: newRuleTechnique.trim(),
      mitre_tactic: newRuleTactic.trim(),
      author: currentUser?.name || 'Security Analyst',
      status: 'active',
      yaml_content: newRuleYaml.trim() || `title: ${newRuleName}\nid: custom-rule\nstatus: production\nlevel: ${newRuleSeverity}`
    });

    setIsAddRuleOpen(false);
    setNewRuleName('');
    setNewRuleDesc('');
    setNewRuleYaml('');
  };

  const handleConfirmFP = () => {
    if (fpTargetId) {
      toggleFalsePositive(fpTargetId, fpReason);
      setFpTargetId(null);
      setFpReason('');
    }
  };

  const isAdmin = currentUser?.role === 'admin';

  return (
    <div className="space-y-6">
      
      {/* Header & Breadcrumb matching Screenshot 1 */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[#282321]">
        <div>
          <div className="text-[11px] font-mono text-[#a8a29e] mb-1 flex items-center gap-1.5">
            <span>&gt;</span>
            <span className="text-[#d6d3d1]">Findings</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-[#fafaf9] flex items-center gap-2.5">
            <ShieldAlert className="w-5 h-5 text-[#f95721]" />
            <span>Findings & Threat Detections</span>
          </h1>
          <p className="text-xs text-[#a8a29e] mt-0.5">
            Case: <strong className="text-[#fafaf9]">{activeCase?.name}</strong> · Continuous rule evaluation with Sigma syntax matching and MITRE taxonomy tagging
          </p>
        </div>

        {/* Tab switch & Actions */}
        <div className="flex items-center gap-2.5 flex-wrap">
          <div className="flex items-center p-1 bg-[#191716] border border-[#2c2724] rounded-lg text-xs font-mono">
            <button
              onClick={() => setActiveTab('findings')}
              className={`px-3 py-1.5 rounded-md transition-all font-medium ${
                activeTab === 'findings'
                  ? 'bg-[#292422] text-[#fafaf9] shadow-sm'
                  : 'text-[#a8a29e] hover:text-[#d6d3d1]'
              }`}
            >
              Findings ({activeCaseDetections.length})
            </button>
            <button
              onClick={() => setActiveTab('sphere')}
              className={`px-3 py-1.5 rounded-md transition-all font-medium flex items-center gap-1.5 ${
                activeTab === 'sphere'
                  ? 'bg-[#f95721] text-white shadow-[0_0_12px_rgba(249,87,33,0.4)]'
                  : 'text-[#a8a29e] hover:text-[#d6d3d1]'
              }`}
            >
              <Globe2 className="w-3.5 h-3.5" />
              <span>3D Cyber Sphere</span>
            </button>
            <button
              onClick={() => setActiveTab('rules')}
              className={`px-3 py-1.5 rounded-md transition-all font-medium ${
                activeTab === 'rules'
                  ? 'bg-[#292422] text-[#fafaf9] shadow-sm'
                  : 'text-[#a8a29e] hover:text-[#d6d3d1]'
              }`}
            >
              Sigma Rules ({rules.length})
            </button>
          </div>

          {isAdmin && (
            <button
              onClick={() => setIsAddRuleOpen(true)}
              className="px-3.5 py-1.5 rounded-lg bg-[#f95721] hover:bg-[#ff6738] text-white font-semibold text-xs transition-all flex items-center gap-1.5 shadow-[0_0_12px_rgba(249,87,33,0.35)]"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New task +</span>
            </button>
          )}

          <button
            onClick={() => reloadSigmaRules()}
            className="p-1.5 rounded-lg bg-[#191716] hover:bg-[#23201e] border border-[#2c2724] text-[#a8a29e] text-xs transition-colors hover:text-[#f95721]"
            title="Reload and re-evaluate detection rules (Admin)"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {activeTab === 'sphere' ? (
        /* Dedicated 3D Cyber Sphere Topology View */
        <div className="rounded-2xl bg-[#161413]/90 border border-[#2b2523] p-8 backdrop-blur-xl flex flex-col items-center justify-center space-y-6 shadow-2xl relative overflow-hidden min-h-[500px]">
          <div className="text-center space-y-1.5 max-w-md z-10">
            <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[#2a140d] border border-[#ea580c]/30 text-[#f95721] text-[11px] font-mono font-medium">
              <Sparkles className="w-3 h-3" />
              <span>Three.js Spatial Threat Surface</span>
            </div>
            <h3 className="text-lg font-bold text-[#fafaf9]">Forensic Geodesic Node Topology</h3>
            <p className="text-xs text-[#a8a29e]">
              3D interactive visualization of attack paths, compromised endpoints, and C2 beacons mapped across the global threat surface.
            </p>
          </div>

          {/* Interactive 3D Cyber Threat Globe (Screenshot 1) */}
          <CyberThreatGlobe
            height={320}
            threatPointsCount={64}
            interactive={true}
            mode={globeMode}
            onModeChange={setGlobeMode}
            showControls={true}
            caption="Drag to orbit · Real-time cryptographic node correlation"
            className="w-full max-w-xl"
          />

          <div className="flex items-center gap-3 z-10 pt-2">
            <button
              onClick={() => setActiveTab('findings')}
              className="px-4 py-2 rounded-xl bg-[#1a1817] hover:bg-[#24201e] border border-[#2e2926] text-xs font-semibold text-[#fafaf9] transition-colors"
            >
              Return to Findings List
            </button>
            <button
              onClick={() => reloadSigmaRules()}
              className="px-4 py-2 rounded-xl bg-[#f95721] hover:bg-[#ff6738] text-white text-xs font-semibold flex items-center gap-2 shadow-[0_0_12px_rgba(249,87,33,0.35)] transition-all"
            >
              <span>Scan Active Vectors</span>
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      ) : activeTab === 'findings' ? (
        /* Findings Tab */
        <div className="space-y-4">
          
          {/* Filter Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 bg-[#161413]/90 border border-[#2b2523] rounded-xl text-xs shadow-lg">
            
            <div className="flex items-center gap-2">
              <span className="text-[#78716c] font-mono text-[11px]">Filter Severity:</span>
              <div className="flex items-center p-0.5 bg-[#121110] border border-[#2c2724] rounded-lg">
                {(['all', 'critical', 'high', 'medium', 'low'] as const).map(sev => (
                  <button
                    key={sev}
                    onClick={() => setFilterSeverity(sev)}
                    className={`px-2.5 py-1 rounded-md capitalize transition-all font-mono text-xs ${
                      filterSeverity === sev
                        ? 'bg-[#f95721] text-white font-medium shadow-[0_0_8px_rgba(249,87,33,0.3)]'
                        : 'text-[#a8a29e] hover:text-[#fafaf9]'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            </div>

            {/* False Positives Toggle */}
            <label className="flex items-center gap-2 cursor-pointer text-[#d6d3d1] select-none bg-[#121110] border border-[#2c2724] px-3 py-1.5 rounded-lg hover:border-[#38322e] transition-colors">
              <input
                type="checkbox"
                checked={showFalsePositives}
                onChange={(e) => setShowFalsePositives(e.target.checked)}
                className="rounded border-[#38322e] bg-[#1a1817] text-[#f95721] focus:ring-[#f95721]/30 accent-[#f95721]"
              />
              <span>Show False Positives</span>
            </label>

          </div>

          {/* Detections List */}
          <div className="space-y-3">
            {filteredDetections.length === 0 ? (
              /* Empty State matching Screenshot 1 exactly: 3D Globe + "Nice, no findings match these filters!" + "New scan +" button */
              <div className="py-8 px-6 rounded-2xl bg-[#161413]/90 border border-[#2b2523] flex flex-col items-center justify-center text-center shadow-xl space-y-4">
                <CyberThreatGlobe
                  height={280}
                  threatPointsCount={44}
                  interactive={true}
                  mode="default"
                  showControls={true}
                  className="w-full max-w-md"
                />

                <div className="space-y-3 pt-2">
                  <h3 className="text-base font-semibold text-[#fafaf9] tracking-tight">
                    Nice, no findings match these filters!
                  </h3>
                  <p className="text-xs text-[#a8a29e] max-w-sm mx-auto">
                    All ingested forensic events are compliant with current severity baseline filters.
                  </p>

                  <div className="pt-2">
                    <button
                      onClick={() => {
                        setFilterSeverity('all');
                        setShowFalsePositives(false);
                      }}
                      className="px-5 py-2.5 rounded-xl bg-[#f95721] hover:bg-[#ff6738] text-white text-xs font-semibold flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(249,87,33,0.4)] transition-all mx-auto"
                    >
                      <span>New scan +</span>
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              filteredDetections.map((det) => (
                <div
                  key={det.id}
                  className={`p-4 rounded-xl border transition-all space-y-3 shadow-lg ${
                    det.false_positive
                      ? 'bg-[#141211]/60 border-[#282321] opacity-75'
                      : det.severity === 'critical'
                      ? 'bg-[#181514] border-[#f95721]/50 shadow-[0_0_15px_rgba(249,87,33,0.12)]'
                      : 'bg-[#161413] border-[#2b2523] hover:border-[#3a322e]'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-2.5">
                      <SeverityTag severity={det.severity} />
                      <h3 className="text-sm font-semibold text-[#fafaf9]">{det.rule_name}</h3>
                      {det.false_positive && (
                        <span className="text-[10px] font-mono uppercase bg-[#24201e] text-[#a8a29e] px-2 py-0.5 rounded border border-[#332c28]">
                          False Positive
                        </span>
                      )}
                    </div>

                    <MitreBadge techniqueId={det.mitre_technique} tactic={det.mitre_tactic} />
                  </div>

                  <p className="text-xs text-[#d6d3d1] leading-relaxed">
                    {det.description}
                  </p>

                  {/* False Positive Reason if marked */}
                  {det.false_positive && det.false_positive_reason && (
                    <div className="p-2.5 bg-[#110f0e] border border-[#2b2523] rounded-lg text-xs font-mono text-[#a8a29e]">
                      <strong className="text-[#fafaf9]">Dismissal Justification:</strong> {det.false_positive_reason} (Marked by: {det.false_positive_marked_by || 'Analyst'})
                    </div>
                  )}

                  {/* Entities involved & Action bar */}
                  <div className="flex flex-wrap items-center justify-between gap-3 pt-2.5 border-t border-[#26211f] text-xs">
                    <div className="flex flex-wrap items-center gap-4 text-[11px] font-mono text-[#a8a29e]">
                      <span>Detected: {det.timestamp.replace('T', ' ').slice(0, 19)} UTC</span>
                      {det.entities_involved.hosts && (
                        <span>Hosts: <strong className="text-[#fafaf9]">{det.entities_involved.hosts.join(', ')}</strong></span>
                      )}
                      {det.entities_involved.users && (
                        <span>Users: <strong className="text-[#fafaf9]">{det.entities_involved.users.join(', ')}</strong></span>
                      )}
                      <span>Matched Events: <strong className="text-[#f95721]">{det.matched_event_ids.length}</strong></span>
                    </div>

                    {/* False positive toggle button */}
                    <button
                      onClick={() => {
                        if (det.false_positive) {
                          toggleFalsePositive(det.id);
                        } else {
                          setFpTargetId(det.id);
                        }
                      }}
                      className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-colors ${
                        det.false_positive
                          ? 'bg-[#221e1c] text-[#d6d3d1] hover:bg-[#2c2724]'
                          : 'bg-[#121110] border border-[#2e2926] text-[#a8a29e] hover:text-[#fafaf9] hover:border-[#f95721]/50'
                      }`}
                    >
                      {det.false_positive ? 'Unmark False Positive' : 'Mark as False Positive'}
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      ) : (
        /* Rules Directory Tab */
        <div className="bg-[#161413]/90 border border-[#2b2523] rounded-xl overflow-hidden shadow-xl">
          <div className="px-5 py-3 border-b border-[#2b2523] bg-[#121110] flex items-center justify-between">
            <h3 className="text-xs font-semibold text-[#fafaf9] uppercase font-mono">
              Active Sigma Detection Signatures
            </h3>
            <span className="text-[11px] font-mono text-[#78716c]">
              Loaded in rules engine
            </span>
          </div>

          <div className="divide-y divide-[#26211f]">
            {rules.map((rule) => (
              <div key={rule.id} className="p-4 hover:bg-[#1c1918] transition-colors space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <SeverityTag severity={rule.severity} />
                    <span className="text-sm font-semibold text-[#fafaf9]">{rule.name}</span>
                    <span className="text-[10px] font-mono text-[#78716c]">({rule.id})</span>
                  </div>
                  
                  <div className="flex items-center gap-2">
                    <MitreBadge techniqueId={rule.mitre_technique} tactic={rule.mitre_tactic} />
                    <button
                      onClick={() => setSelectedRuleView(rule)}
                      className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-[#121110] border border-[#2e2926] text-xs font-mono text-[#f95721] hover:text-[#ff7847]"
                    >
                      <Code2 className="w-3.5 h-3.5" />
                      <span>View YAML</span>
                    </button>
                  </div>
                </div>

                <p className="text-xs text-[#a8a29e]">
                  {rule.description}
                </p>

                <div className="flex items-center gap-3 text-[11px] font-mono text-[#78716c] pt-1">
                  <span>Author: {rule.author}</span>
                  <span>·</span>
                  <span>Status: <strong className="text-emerald-400 font-normal">{rule.status}</strong></span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* View Rule YAML Modal */}
      {selectedRuleView && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-2xl bg-[#161413] border border-[#2b2523] rounded-2xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#2b2523]">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-[#f95721]" />
                <h3 className="text-sm font-semibold text-[#fafaf9] font-mono">
                  {selectedRuleView.name} (YAML Definition)
                </h3>
              </div>
              <button
                onClick={() => setSelectedRuleView(null)}
                className="text-[#78716c] hover:text-[#fafaf9]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <pre className="p-4 bg-[#0e0d0d] border border-[#2b2523] rounded-xl font-mono text-xs text-[#fb923c] overflow-x-auto whitespace-pre-wrap max-h-96">
              {selectedRuleView.yaml_content}
            </pre>

            <div className="flex justify-end pt-2 border-t border-[#2b2523]">
              <button
                onClick={() => setSelectedRuleView(null)}
                className="px-4 py-1.5 rounded-lg bg-[#221f1d] hover:bg-[#2d2825] text-[#d6d3d1] text-xs font-semibold transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Custom Sigma Rule Modal (Admin) */}
      {isAddRuleOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-lg bg-[#161413] border border-[#2b2523] rounded-2xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#2b2523]">
              <h3 className="text-sm font-semibold text-[#fafaf9] flex items-center gap-2">
                <FileCode className="w-4 h-4 text-[#f95721]" />
                <span>Add Detection Rule (Sigma Format)</span>
              </h3>
              <button
                onClick={() => setIsAddRuleOpen(false)}
                className="text-[#78716c] hover:text-[#fafaf9]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleAddRuleSubmit} className="space-y-4 text-xs">
              <div className="space-y-1">
                <label className="text-[#d6d3d1] font-medium">Rule Name *</label>
                <input
                  type="text"
                  required
                  value={newRuleName}
                  onChange={(e) => setNewRuleName(e.target.value)}
                  placeholder="e.g. Cobalt Strike Malleable C2 Beacon"
                  className="w-full bg-[#100f0e] border border-[#2e2926] rounded-lg px-3 py-2 text-[#fafaf9] focus:outline-none focus:border-[#f95721] font-mono text-xs"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-[#d6d3d1] font-medium">Severity</label>
                  <select
                    value={newRuleSeverity}
                    onChange={(e) => setNewRuleSeverity(e.target.value as EventSeverity)}
                    className="w-full bg-[#100f0e] border border-[#2e2926] rounded-lg px-3 py-2 text-[#fafaf9] focus:outline-none focus:border-[#f95721] text-xs capitalize"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-[#d6d3d1] font-medium">Technique ID</label>
                  <input
                    type="text"
                    required
                    value={newRuleTechnique}
                    onChange={(e) => setNewRuleTechnique(e.target.value)}
                    placeholder="T1059.001"
                    className="w-full bg-[#100f0e] border border-[#2e2926] rounded-lg px-3 py-2 text-[#fafaf9] focus:outline-none focus:border-[#f95721] font-mono text-xs"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-[#d6d3d1] font-medium">Description</label>
                <textarea
                  rows={2}
                  value={newRuleDesc}
                  onChange={(e) => setNewRuleDesc(e.target.value)}
                  placeholder="Rule description and forensic context..."
                  className="w-full bg-[#100f0e] border border-[#2e2926] rounded-lg px-3 py-2 text-[#fafaf9] focus:outline-none focus:border-[#f95721] text-xs"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[#d6d3d1] font-medium">YAML Rule Definition (Optional)</label>
                <textarea
                  rows={4}
                  value={newRuleYaml}
                  onChange={(e) => setNewRuleYaml(e.target.value)}
                  placeholder="title: ...&#10;logsource: ...&#10;detection: ..."
                  className="w-full bg-[#100f0e] border border-[#2e2926] rounded-lg px-3 py-2 text-[#fafaf9] focus:outline-none focus:border-[#f95721] font-mono text-xs"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-[#2b2523]">
                <button
                  type="button"
                  onClick={() => setIsAddRuleOpen(false)}
                  className="px-3 py-1.5 rounded-lg border border-[#2e2926] text-[#a8a29e] hover:bg-[#1f1b19] transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-[#f95721] hover:bg-[#ff6738] text-white font-semibold shadow-[0_0_12px_rgba(249,87,33,0.35)] transition-all"
                >
                  Deploy Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* False Positive Confirmation Dialog */}
      {fpTargetId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-md bg-[#161413] border border-[#2b2523] rounded-2xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-full bg-[#2a140d] border border-[#ea580c]/40 flex items-center justify-center text-[#f95721] shrink-0">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-[#fafaf9]">
                  Mark Detection as False Positive
                </h3>
                <p className="text-xs text-[#a8a29e]">
                  Overrides rule evaluation for this event in current case audit logs.
                </p>
              </div>
            </div>

            <div className="space-y-1.5 text-xs">
              <label className="text-[#d6d3d1] font-medium">Justification / Reason (Audited)</label>
              <textarea
                rows={3}
                value={fpReason}
                onChange={(e) => setFpReason(e.target.value)}
                placeholder="Authorized penetration testing activity / maintenance window..."
                className="w-full bg-[#100f0e] border border-[#2e2926] rounded-lg px-3 py-2 text-[#fafaf9] focus:outline-none focus:border-[#f95721] text-xs"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-[#2b2523]">
              <button
                type="button"
                onClick={() => setFpTargetId(null)}
                className="px-3.5 py-1.5 rounded-lg border border-[#2e2926] text-[#a8a29e] hover:bg-[#1f1b19] text-xs transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmFP}
                className="px-4 py-1.5 rounded-lg bg-[#f95721] hover:bg-[#ff6738] text-white font-semibold text-xs shadow-[0_0_12px_rgba(249,87,33,0.35)] transition-all"
              >
                Confirm Override
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
