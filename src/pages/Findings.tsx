import React, { useState } from 'react';
import { useApp } from '../store';
import { 
  Filter, 
  Plus, 
  Download, 
  Grid, 
  List, 
  CheckCircle2, 
  Search, 
  ShieldAlert, 
  ChevronRight,
  Sparkles,
  RefreshCw,
  SlidersHorizontal,
  ChevronDown
} from 'lucide-react';
import { CyberGlobe3D } from '../components/CyberGlobe3D';
import { SeverityTag } from '../components/SeverityTag';
import { MitreBadge } from '../components/MitreBadge';

export const Findings: React.FC = () => {
  const { 
    currentUser,
    activeCase, 
    activeCaseDetections, 
    activeCaseEvents, 
    setCurrentPage,
    reloadSigmaRules
  } = useApp();

  const [globeMode, setGlobeMode] = useState<'default' | 'advanced'>('default');
  const [filterMenuOpen, setFilterMenuOpen] = useState(false);
  const [selectedTeam, setSelectedTeam] = useState('Cyfocus Primary');
  const [activeSubmenu, setActiveSubmenu] = useState<string | null>('Team');
  const [viewFormat, setViewFormat] = useState<'globe' | 'list'>('globe');
  const [isScanning, setIsScanning] = useState(false);
  const [scanComplete, setScanComplete] = useState(false);

  const teams = ['Team_1', 'Cyfocus Secondary', 'Cyfocus Primary', 'Demo team'];

  const filterOptions = [
    { id: 'Team', label: 'Team', hasSub: true },
    { id: 'Status', label: 'Status', count: '3 active' },
    { id: 'Assignee', label: 'Assignee', val: 'Anna Gunn' },
    { id: 'Priority', label: 'Priority', val: 'P0 - Critical' },
    { id: 'CVSS', label: '# CVSS', val: '7.5 - 10.0' },
    { id: 'Duplicates', label: 'Duplicates', count: '0' },
    { id: 'Parent issues', label: 'Parent issues', count: '2' },
    { id: 'Sub-issues', label: 'Sub-issues', count: '7' },
    { id: 'Blocked issues', label: 'Blocked issues', count: '1' },
    { id: 'Blocking issues', label: 'Blocking issues', count: '0' },
    { id: 'Issues with references', label: 'Issues with references', count: '4' },
    { id: 'Fix date', label: 'Fix date', val: 'Q4 2026' },
    { id: 'Created date', label: 'Created date', val: 'Past 30d' },
    { id: 'Updated date', label: 'Updated date', val: 'Today' },
  ];

  const handleRunScan = () => {
    setIsScanning(true);
    setScanComplete(false);
    setTimeout(() => {
      reloadSigmaRules();
      setIsScanning(false);
      setScanComplete(true);
      setTimeout(() => setScanComplete(false), 4000);
    }, 1200);
  };

  const handleExportCsv = () => {
    const csvContent = "data:text/csv;charset=utf-8," + 
      "Rule,Severity,MITRE_Tactic,MITRE_Technique,Matched_Events\n" +
      activeCaseDetections.map(d => `"${d.rule_name}","${d.severity}","${d.mitre_tactic}","${d.mitre_technique}",${d.matched_event_ids.length}`).join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `findings_${activeCase?.id || 'case'}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="relative min-h-[calc(100vh-6rem)] flex flex-col justify-between space-y-6">
      
      {/* Top Breadcrumb & Control Bar (Matching Screenshot 1!) */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-1.5 text-xs text-neutral-400 font-mono">
            <button onClick={() => setCurrentPage(currentUser?.role === 'admin' ? 'dashboard' : 'cases')} className="hover:text-neutral-200 transition-colors">
              ⌂
            </button>
            <ChevronRight className="w-3.5 h-3.5 text-neutral-600" />
            <span className="text-neutral-200 font-medium">Findings</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white mt-1">
            Findings
          </h1>
        </div>

        {/* View Switchers & Export (Matching Top Right of Screenshot 1) */}
        <div className="flex items-center gap-2">
          <div className="flex items-center p-1 rounded-xl bg-neutral-900 border border-neutral-800">
            <button
              onClick={() => setViewFormat('globe')}
              className={`p-1.5 rounded-lg text-xs transition-colors cursor-pointer ${
                viewFormat === 'globe' ? 'bg-neutral-800 text-white' : 'text-neutral-400 hover:text-neutral-200'
              }`}
              title="3D Globe View"
            >
              <Grid className="w-4 h-4" />
            </button>
            <button
              onClick={() => setViewFormat('list')}
              className={`p-1.5 rounded-lg text-xs transition-colors cursor-pointer ${
                viewFormat === 'list' ? 'bg-neutral-800 text-white' : 'text-neutral-400 hover:text-neutral-200'
              }`}
              title="Table View"
            >
              <List className="w-4 h-4" />
            </button>
          </div>

          <button
            onClick={handleExportCsv}
            className="px-3.5 py-2 rounded-xl bg-neutral-900 hover:bg-neutral-850 border border-neutral-800 text-xs font-semibold text-neutral-200 flex items-center gap-2 transition-all hover:border-[#ff461e]/40 cursor-pointer shadow-sm"
          >
            <span>Export</span>
            <Download className="w-3.5 h-3.5 text-[#ff461e]" />
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="relative flex-1 flex flex-col items-center justify-center min-h-[460px]">
        
        {/* Filter Trigger Button (Screenshot 1) */}
        <div className="absolute top-0 left-0 z-30">
          <button
            onClick={() => setFilterMenuOpen(!filterMenuOpen)}
            className={`px-3.5 py-2 rounded-xl border text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer ${
              filterMenuOpen
                ? 'bg-neutral-800 border-[#ff461e]/50 text-white shadow-[0_0_15px_rgba(255,70,30,0.2)]'
                : 'bg-neutral-900/90 hover:bg-neutral-850 border-neutral-800 text-neutral-200'
            }`}
          >
            <SlidersHorizontal className="w-3.5 h-3.5 text-[#ff461e]" />
            <span>Filter</span>
            <ChevronDown className="w-3 h-3 text-neutral-500" />
          </button>

          {/* Floating Glassmorphic Filter Dropdown Panel (Exact match to Screenshot 1!) */}
          {filterMenuOpen && (
            <div className="absolute top-12 left-0 w-72 rounded-2xl bg-[#101014]/95 border border-neutral-800/90 shadow-[0_20px_50px_rgba(0,0,0,0.8)] backdrop-blur-2xl p-2 z-40 space-y-1">
              {/* Search in filters */}
              <div className="p-2 border-b border-neutral-800/80 flex items-center justify-between">
                <input
                  type="text"
                  placeholder="Filter..."
                  className="bg-transparent text-xs text-neutral-200 placeholder-neutral-500 focus:outline-none w-full"
                />
                <span className="text-[10px] font-mono text-neutral-500 px-1.5 py-0.5 rounded bg-neutral-800">F</span>
              </div>

              {/* Filter List */}
              <div className="max-h-72 overflow-y-auto space-y-0.5 py-1">
                {filterOptions.map((opt) => {
                  const isTeam = opt.id === 'Team';
                  return (
                    <div key={opt.id} className="relative">
                      <button
                        onClick={() => setActiveSubmenu(activeSubmenu === opt.id ? null : opt.id)}
                        className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs transition-colors cursor-pointer ${
                          activeSubmenu === opt.id 
                            ? 'bg-neutral-800 text-white' 
                            : 'text-neutral-300 hover:bg-neutral-850 hover:text-white'
                        }`}
                      >
                        <span>{opt.label}</span>
                        {isTeam ? (
                          <div className="flex items-center gap-1.5 text-neutral-400">
                            <span className="text-[11px] text-[#ff8f3d]">{selectedTeam}</span>
                            <ChevronRight className="w-3 h-3" />
                          </div>
                        ) : (
                          <span className="text-[10px] text-neutral-500 font-mono">{opt.val || opt.count}</span>
                        )}
                      </button>

                      {/* Submenu for Team */}
                      {isTeam && activeSubmenu === 'Team' && (
                        <div className="absolute left-full top-0 ml-1.5 w-44 rounded-xl bg-[#141418] border border-neutral-800 shadow-2xl p-1.5 z-50 space-y-0.5">
                          {teams.map((t) => (
                            <button
                              key={t}
                              onClick={() => {
                                setSelectedTeam(t);
                                setActiveSubmenu(null);
                              }}
                              className={`w-full text-left px-2.5 py-1.5 rounded-lg text-xs transition-colors cursor-pointer ${
                                selectedTeam === t 
                                  ? 'bg-[#ff461e]/20 text-[#ff8f3d] font-semibold' 
                                  : 'text-neutral-300 hover:bg-neutral-800'
                              }`}
                            >
                              {t}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* 3D Cyber Globe Display */}
        {viewFormat === 'globe' ? (
          <div className="w-full flex flex-col items-center justify-center my-auto">
            <div className="w-full max-w-2xl h-[300px] sm:h-[360px] md:h-[400px] lg:h-[420px]">
              <CyberGlobe3D mode={globeMode} />
            </div>

            {/* Segmented Control: Default vs Advanced (Screenshot 1) */}
            <div className="flex items-center p-1 rounded-xl bg-neutral-900/90 border border-neutral-800/80 backdrop-blur-md mt-2 z-20">
              <button
                onClick={() => setGlobeMode('default')}
                className={`px-4 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  globeMode === 'default'
                    ? 'bg-neutral-800 text-white shadow-sm'
                    : 'text-neutral-400 hover:text-neutral-200'
                }`}
              >
                Default
              </button>
              <button
                onClick={() => setGlobeMode('advanced')}
                className={`px-4 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  globeMode === 'advanced'
                    ? 'bg-gradient-to-r from-[#ff461e] to-[#ff5722] text-white shadow-[0_0_15px_rgba(255,70,30,0.4)]'
                    : 'text-neutral-400 hover:text-neutral-200'
                }`}
              >
                Advanced
              </button>
            </div>

            {/* Center Status readout (Screenshot 1: "Nice, no findings match these filters!") */}
            <div className="text-center space-y-3 mt-4 z-20">
              <p className="text-sm font-medium text-neutral-300">
                {activeCaseDetections.length === 0
                  ? 'Nice, no findings match these filters!'
                  : `${activeCaseDetections.length} threat indicators detected in active attack mesh`}
              </p>

              {/* Vibrant Orange "New scan +" button (Screenshot 1) */}
              <button
                onClick={handleRunScan}
                disabled={isScanning}
                className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-[#ff461e] to-[#ff5722] hover:from-[#ff5722] hover:to-[#ff6a3d] text-white font-semibold text-xs tracking-wide transition-all shadow-[0_0_20px_rgba(255,70,30,0.35)] hover:shadow-[0_0_30px_rgba(255,70,30,0.5)] inline-flex items-center gap-2 cursor-pointer active:scale-95 disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
                <span>{isScanning ? 'Executing Threat Correlation...' : 'New scan +'}</span>
              </button>

              {scanComplete && (
                <div className="text-[11px] text-emerald-400 font-mono flex items-center justify-center gap-1.5 animate-fadeIn">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Threat mesh updated successfully across {activeCaseEvents.length} events</span>
                </div>
              )}
            </div>
          </div>
        ) : (
          /* Table / List View */
          <div className="w-full bg-neutral-900/60 border border-neutral-800 rounded-2xl overflow-hidden mt-12 backdrop-blur-xl">
            <div className="p-4 border-b border-neutral-800 flex items-center justify-between">
              <span className="text-xs font-semibold text-neutral-200">
                Active Detections ({activeCaseDetections.length})
              </span>
              <span className="text-[11px] text-neutral-400 font-mono">Team: {selectedTeam}</span>
            </div>

            <div className="divide-y divide-neutral-800/80">
              {activeCaseDetections.map((detection) => (
                <div key={detection.id} className="p-4 hover:bg-neutral-850/40 transition-colors flex items-center justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <SeverityTag severity={detection.severity} />
                      <span className="text-xs font-semibold text-neutral-100">{detection.rule_name}</span>
                    </div>
                    <p className="text-xs text-neutral-400">{detection.description}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <MitreBadge techniqueId={detection.mitre_technique} tactic={detection.mitre_tactic} />
                    <button
                      onClick={() => setCurrentPage('incidents')}
                      className="px-3 py-1.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-200 text-xs font-medium transition-colors"
                    >
                      Investigate
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>
    </div>
  );
};
