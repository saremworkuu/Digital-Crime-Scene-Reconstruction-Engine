import React, { useState, useRef, useEffect, useMemo } from 'react';
import { AttackGraphData, GraphNode, GraphEdge, EntityType } from '../types';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  Download,
  Server,
  User as UserIcon,
  Globe,
  FileCode,
  ShieldAlert,
  X,
  Layers,
  Activity
} from 'lucide-react';
import { useApp } from '../store';

interface GraphViewProps {
  graphData: AttackGraphData;
}

type LayoutType = 'hierarchical' | 'force' | 'circular';

export const GraphView: React.FC<GraphViewProps> = ({ graphData }) => {
  const { activeCaseId, activeCaseEvents, theme } = useApp();
  const isLight = theme === 'light';
  const svgRef = useRef<SVGSVGElement>(null);

  const [layout, setLayout] = useState<LayoutType>('hierarchical');
  const [onlyAttackPath, setOnlyAttackPath] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);

  // Position state for nodes
  const [nodePositions, setNodePositions] = useState<Record<string, { x: number; y: number }>>({});

  // Filter nodes & edges
  const filteredNodes = useMemo(() => {
    if (!onlyAttackPath) return graphData.nodes;
    return graphData.nodes.filter(n => n.is_attack_path || n.is_compromised);
  }, [graphData.nodes, onlyAttackPath]);

  const activeNodeIds = useMemo(() => new Set(filteredNodes.map(n => n.id)), [filteredNodes]);

  const filteredEdges = useMemo(() => {
    return graphData.edges.filter(
      e => activeNodeIds.has(e.source) && activeNodeIds.has(e.target) && (!onlyAttackPath || e.is_attack_path)
    );
  }, [graphData.edges, activeNodeIds, onlyAttackPath]);

  // Compute node layouts
  useEffect(() => {
    const width = 840;
    const height = 520;
    const positions: Record<string, { x: number; y: number }> = {};
    const nodes = filteredNodes;

    if (layout === 'hierarchical') {
      // Stratify by role / type with clear left-to-right progression:
      // Level 1: External IPs & Adversary Infrastructure
      // Level 2: Ingress Workstations & Edge Gateways (WS-HR-12, mailgw, etc.)
      // Level 3: Compromised / Active User Accounts
      // Level 4: Core Domain Controllers & High-Value Target Servers (DC-01, SRV-FS-02, SRV-BKP-01)
      const levels: Record<string, GraphNode[]> = {
        lvl1: [],
        lvl2: [],
        lvl3: [],
        lvl4: []
      };

      nodes.forEach(n => {
        const lbl = n.label.toLowerCase();
        const isExtIp = n.type === 'ip' && !lbl.startsWith('10.') && !lbl.startsWith('192.168.') && !lbl.startsWith('172.');
        if (isExtIp) {
          levels.lvl1.push(n);
        } else if (n.type === 'user') {
          levels.lvl3.push(n);
        } else if (lbl.includes('dc-') || lbl.includes('srv-') || lbl.includes('domain') || lbl.includes('file')) {
          levels.lvl4.push(n);
        } else {
          levels.lvl2.push(n);
        }
      });

      const tierKeys = ['lvl1', 'lvl2', 'lvl3', 'lvl4'];
      const tierWidth = (width - 120) / tierKeys.length;

      tierKeys.forEach((tier, colIdx) => {
        const tierNodes = levels[tier];
        const count = tierNodes.length;
        tierNodes.forEach((node, rowIdx) => {
          const x = 75 + colIdx * tierWidth;
          const y = (height / (count + 1)) * (rowIdx + 1);
          positions[node.id] = { x, y };
        });
      });
    } else if (layout === 'circular') {
      const centerX = width / 2;
      const centerY = height / 2;
      const radius = Math.min(width, height) * 0.38;
      const angleStep = (2 * Math.PI) / nodes.length;

      nodes.forEach((node, i) => {
        const angle = i * angleStep;
        positions[node.id] = {
          x: centerX + radius * Math.cos(angle),
          y: centerY + radius * Math.sin(angle)
        };
      });
    } else {
      // Force-directed approximation / grid
      const cols = Math.ceil(Math.sqrt(nodes.length));
      const cellW = width / (cols + 1);
      const cellH = height / (cols + 1);

      nodes.forEach((node, i) => {
        const col = i % cols;
        const row = Math.floor(i / cols);
        positions[node.id] = {
          x: 100 + col * cellW + (Math.sin(i) * 20),
          y: 70 + row * cellH + (Math.cos(i) * 20)
        };
      });
    }

    setNodePositions(positions);
  }, [filteredNodes, layout]);

  // Selected Node Object
  const selectedNode = useMemo(() => {
    return graphData.nodes.find(n => n.id === selectedNodeId) || null;
  }, [graphData.nodes, selectedNodeId]);

  // Events related to selected node
  const nodeEvents = useMemo(() => {
    if (!selectedNode) return [];
    const label = selectedNode.label.toLowerCase();
    return activeCaseEvents.filter(e => {
      if (selectedNode.type === 'host' && e.host && label.includes(e.host.toLowerCase())) return true;
      if (selectedNode.type === 'user' && e.user && label.includes(e.user.toLowerCase())) return true;
      if (selectedNode.type === 'ip') {
        if (e.src_ip && label.includes(e.src_ip)) return true;
        if (e.dst_ip && label.includes(e.dst_ip)) return true;
      }
      return false;
    });
  }, [selectedNode, activeCaseEvents]);

  // Mouse pan handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).tagName === 'svg') {
      setIsPanning(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isPanning) {
      setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    } else if (draggingNodeId) {
      const rect = svgRef.current?.getBoundingClientRect();
      if (!rect) return;
      const x = (e.clientX - rect.left - pan.x) / zoom;
      const y = (e.clientY - rect.top - pan.y) / zoom;
      setNodePositions(prev => ({
        ...prev,
        [draggingNodeId]: { x, y }
      }));
    }
  };

  const handleMouseUp = () => {
    setIsPanning(false);
    setDraggingNodeId(null);
  };

  const getNodeIcon = (type: EntityType) => {
    switch (type) {
      case 'host': return <Server className="w-3.5 h-3.5" />;
      case 'user': return <UserIcon className="w-3.5 h-3.5" />;
      case 'ip': return <Globe className="w-3.5 h-3.5" />;
      case 'file': return <FileCode className="w-3.5 h-3.5" />;
      default: return <Activity className="w-3.5 h-3.5" />;
    }
  };

  // Export SVG (FR-GRAPH-5)
  const exportSvg = () => {
    if (!svgRef.current) return;
    const serializer = new XMLSerializer();
    const source = serializer.serializeToString(svgRef.current);
    const blob = new Blob([source], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dcsre_${activeCaseId}_attack_graph.svg`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="relative bg-[#161413]/95 border border-[#2b2523] rounded-2xl overflow-hidden flex flex-col min-h-[620px] shadow-2xl backdrop-blur-xl">
      
      {/* Top Controls Bar (Warm Brown & Cyber-Orange styling matching Dashboard & Login) */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 bg-[#12100f] border-b border-[#282321] z-10">
        
        {/* Layout Algorithms (FR-GRAPH-4) */}
        <div className="flex items-center gap-2.5 text-xs">
          <span className="text-[#a8a29e] font-mono text-[11px] flex items-center gap-1.5 font-medium">
            <Layers className="w-3.5 h-3.5 text-[#f95721]" /> Layout:
          </span>
          <div className="flex items-center p-0.5 bg-[#0d0c0c] border border-[#2b2523] rounded-lg">
            <button
              onClick={() => setLayout('hierarchical')}
              className={`px-3 py-1 rounded-md transition-all text-xs font-mono cursor-pointer ${
                layout === 'hierarchical'
                  ? 'bg-[#2a140d] text-[#f95721] font-semibold border border-[#ea580c]/50 shadow-[0_0_10px_rgba(249,87,33,0.2)]'
                  : 'text-[#a8a29e] hover:text-[#fafaf9]'
              }`}
            >
              Progression Pipeline
            </button>
            <button
              onClick={() => setLayout('force')}
              className={`px-3 py-1 rounded-md transition-all text-xs font-mono cursor-pointer ${
                layout === 'force'
                  ? 'bg-[#2a140d] text-[#f95721] font-semibold border border-[#ea580c]/50 shadow-[0_0_10px_rgba(249,87,33,0.2)]'
                  : 'text-[#a8a29e] hover:text-[#fafaf9]'
              }`}
            >
              Force / Mesh
            </button>
            <button
              onClick={() => setLayout('circular')}
              className={`px-3 py-1 rounded-md transition-all text-xs font-mono cursor-pointer ${
                layout === 'circular'
                  ? 'bg-[#2a140d] text-[#f95721] font-semibold border border-[#ea580c]/50 shadow-[0_0_10px_rgba(249,87,33,0.2)]'
                  : 'text-[#a8a29e] hover:text-[#fafaf9]'
              }`}
            >
              Concentric
            </button>
          </div>
        </div>

        {/* Attack Path Toggle & View Controls */}
        <div className="flex items-center gap-3 text-xs">
          
          {/* Toggle: Attack Path Highlighting (FR-GRAPH-2) */}
          <label className="flex items-center gap-2 cursor-pointer text-xs text-[#fafaf9] select-none bg-[#0d0c0c] border border-[#2b2523] px-3 py-1.5 rounded-lg hover:border-[#38312d] transition-colors">
            <input
              type="checkbox"
              checked={onlyAttackPath}
              onChange={(e) => setOnlyAttackPath(e.target.checked)}
              className="rounded border-[#38312d] bg-[#141211] text-[#f95721] accent-[#f95721] cursor-pointer"
            />
            <span className="font-semibold text-[#f95721] font-mono text-xs">Attack Path Focus</span>
          </label>

          {/* Zoom & Pan Controls */}
          <div className="flex items-center gap-1 bg-[#0d0c0c] border border-[#2b2523] rounded-lg p-0.5">
            <button
              onClick={() => setZoom(z => Math.max(0.4, z - 0.15))}
              className="p-1 rounded text-[#a8a29e] hover:text-[#fafaf9] hover:bg-[#25201e] transition-colors cursor-pointer"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <span className="text-[11px] font-mono text-[#d6d3d1] px-1.5 tabular-nums">
              {Math.round(zoom * 100)}%
            </span>
            <button
              onClick={() => setZoom(z => Math.min(2.5, z + 0.15))}
              className="p-1 rounded text-[#a8a29e] hover:text-[#fafaf9] hover:bg-[#25201e] transition-colors cursor-pointer"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}
              className="p-1 rounded text-[#a8a29e] hover:text-[#fafaf9] hover:bg-[#25201e] transition-colors cursor-pointer"
              title="Fit to Window"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Export SVG Button */}
          <button
            onClick={exportSvg}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] border border-[#38312d] transition-all font-mono text-xs cursor-pointer shadow-sm"
            title="Export vector SVG graph"
          >
            <Download className="w-3.5 h-3.5 text-[#f95721]" />
            <span>Export SVG</span>
          </button>

        </div>

      </div>

      {/* SVG Canvas Viewport */}
      <div
        className={`flex-1 relative overflow-hidden ${isLight ? 'bg-slate-50' : 'bg-[#0c0b0a]'} cursor-grab active:cursor-grabbing select-none transition-colors`}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
      >
        <svg
          ref={svgRef}
          className="w-full h-[540px]"
          viewBox="0 0 840 520"
        >
          <defs>
            {/* Subtle background grid pattern for light mode */}
            {isLight && (
              <pattern id="grid-light" width="28" height="28" patternUnits="userSpaceOnUse">
                <circle cx="2" cy="2" r="1" fill="#cbd5e1" opacity="0.6" />
              </pattern>
            )}

            {/* Arrow marker for attack edges */}
            <marker
              id="arrow-attack"
              viewBox="0 0 10 10"
              refX="18"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill={isLight ? '#c2410c' : '#f95721'} />
            </marker>

            {/* Arrow marker for benign edges */}
            <marker
              id="arrow-benign"
              viewBox="0 0 10 10"
              refX="18"
              refY="5"
              markerWidth="5"
              markerHeight="5"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill={isLight ? '#94a3b8' : '#57534e'} />
            </marker>
          </defs>

          {isLight && <rect width="100%" height="100%" fill="url(#grid-light)" />}

          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            
            {/* Directed Relationship Edges (FR-GRAPH-1, FR-GRAPH-2) */}
            {filteredEdges.map((edge) => {
              const srcPos = nodePositions[edge.source];
              const tgtPos = nodePositions[edge.target];
              if (!srcPos || !tgtPos) return null;

              const isAttack = edge.is_attack_path;
              const midX = (srcPos.x + tgtPos.x) / 2;
              const midY = (srcPos.y + tgtPos.y) / 2;

              return (
                <g key={edge.id} className="transition-opacity">
                  <line
                    x1={srcPos.x}
                    y1={srcPos.y}
                    x2={tgtPos.x}
                    y2={tgtPos.y}
                    stroke={isAttack ? (isLight ? '#ea580c' : '#f95721') : (isLight ? '#cbd5e1' : '#38312d')}
                    strokeWidth={isAttack ? 2.5 : 1.2}
                    strokeDasharray={isAttack ? 'none' : '3 3'}
                    markerEnd={isAttack ? 'url(#arrow-attack)' : 'url(#arrow-benign)'}
                    className={isAttack ? 'animate-pulse' : ''}
                  />

                  {/* Edge label badge */}
                  <g transform={`translate(${midX}, ${midY})`}>
                    <rect
                      x="-55"
                      y="-9"
                      width="110"
                      height="18"
                      rx="4"
                      fill={isLight ? '#ffffff' : '#141211'}
                      stroke={isAttack ? (isLight ? '#ea580c' : '#ea580c') : (isLight ? '#cbd5e1' : '#2b2523')}
                      strokeWidth="1"
                    />
                    <text
                      x="0"
                      y="3.5"
                      textAnchor="middle"
                      fill={isAttack ? (isLight ? '#c2410c' : '#fb923c') : (isLight ? '#475569' : '#a8a29e')}
                      fontSize="9"
                      fontFamily="JetBrains Mono, monospace"
                      fontWeight={isAttack ? '600' : '400'}
                    >
                      {edge.label.length > 20 ? edge.label.slice(0, 18) + '..' : edge.label}
                    </text>
                  </g>
                </g>
              );
            })}

            {/* Entity Nodes (FR-GRAPH-1, FR-GRAPH-3) */}
            {filteredNodes.map((node) => {
              const pos = nodePositions[node.id] || { x: 400, y: 250 };
              const isSelected = selectedNodeId === node.id;
              const isCompromised = node.is_compromised;

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  className="cursor-pointer"
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedNodeId(node.id);
                  }}
                  onMouseDown={(e) => {
                    e.stopPropagation();
                    setDraggingNodeId(node.id);
                  }}
                >
                  {/* Distinct visual styles per Stage 7: internal host, external IP, user, compromised */}
                  {(() => {
                    const lbl = node.label.toLowerCase();
                    const isExtIp = node.type === 'ip' && !lbl.startsWith('10.') && !lbl.startsWith('192.168.') && !lbl.startsWith('172.');
                    const isUser = node.type === 'user';
                    
                    let strokeColor = isLight ? '#0284c7' : '#38bdf8';
                    let fillColor = isLight ? '#f0f9ff' : '#082f49';
                    let markerText = 'HOST';
                    let textColor = isLight ? '#0369a1' : '#38bdf8';

                    if (isCompromised) {
                      strokeColor = isLight ? '#ea580c' : '#f95721';
                      fillColor = isLight ? '#ffedd5' : '#2e140d';
                      markerText = 'COMP';
                      textColor = isLight ? '#c2410c' : '#fb923c';
                    } else if (isExtIp) {
                      strokeColor = isLight ? '#7c3aed' : '#a855f7';
                      fillColor = isLight ? '#f5f3ff' : '#2e1065';
                      markerText = 'EXT';
                      textColor = isLight ? '#6d28d9' : '#c084fc';
                    } else if (isUser) {
                      strokeColor = isLight ? '#059669' : '#10b981';
                      fillColor = isLight ? '#ecfdf5' : '#064e3b';
                      markerText = 'USER';
                      textColor = isLight ? '#047857' : '#34d399';
                    }

                    if (isSelected) {
                      strokeColor = isLight ? '#c2410c' : '#f95721';
                    }

                    return (
                      <>
                        {isCompromised && (
                          <circle
                            r="24"
                            fill={isLight ? '#ea580c' : '#f95721'}
                            opacity={isLight ? '0.25' : '0.2'}
                            className="animate-ping"
                          />
                        )}
                        <circle
                          r="17"
                          fill={fillColor}
                          stroke={strokeColor}
                          strokeWidth={isSelected ? 3.5 : isCompromised ? 2.5 : 1.8}
                        />
                        <text
                          x="0"
                          y="3.5"
                          textAnchor="middle"
                          fill={textColor}
                          fontSize="8"
                          fontFamily="JetBrains Mono, monospace"
                          fontWeight="bold"
                        >
                          {markerText}
                        </text>
                      </>
                    );
                  })()}

                  {/* Node Label Below */}
                  <text
                    x="0"
                    y="28"
                    textAnchor="middle"
                    fill={isSelected ? (isLight ? '#c2410c' : '#f95721') : (isLight ? '#0f172a' : '#e7e5e4')}
                    fontSize="11"
                    fontFamily="JetBrains Mono, monospace"
                    fontWeight={isSelected ? 'bold' : '600'}
                  >
                    {node.label.length > 22 ? node.label.slice(0, 20) + '..' : node.label}
                  </text>

                  {/* Event count micro-tag */}
                  <text
                    x="0"
                    y="40"
                    textAnchor="middle"
                    fill={isLight ? '#64748b' : '#78716c'}
                    fontSize="9"
                    fontFamily="JetBrains Mono, monospace"
                  >
                    {node.event_count} events
                  </text>
                </g>
              );
            })}

          </g>
        </svg>

        {/* Legend Overlay */}
        <div className={`absolute bottom-3 left-3 ${isLight ? 'bg-white/95 border-slate-200 text-slate-800' : 'bg-[#161413]/90 border-[#2b2523] text-[#d6d3d1]'} rounded-xl p-3 text-[11px] font-mono space-y-2 backdrop-blur-md pointer-events-none shadow-xl border`}>
          <div className={`text-[10px] ${isLight ? 'text-slate-500' : 'text-[#a8a29e]'} uppercase font-semibold`}>Graph Legend</div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#f95721] border border-[#ea580c] shadow-[0_0_8px_rgba(249,87,33,0.5)]" />
            <span>Compromised Entity / Attack Path</span>
          </div>
          <div className="flex items-center gap-2">
            <span className={`w-2.5 h-2.5 rounded-full ${isLight ? 'bg-slate-200 border-slate-300' : 'bg-[#241f1d] border-[#3a322e]'}`} />
            <span>Uncompromised System Asset</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-4 h-0.5 bg-[#f95721]" />
            <span>Malicious Attack Edge (RCE / Exfil / Sudo)</span>
          </div>
        </div>

      </div>

      {/* Node Detail Inspector Drawer (FR-GRAPH-3) */}
      {selectedNode && (
        <div className={`absolute top-14 right-0 bottom-0 w-80 ${isLight ? 'bg-white border-l border-slate-200 text-slate-800' : 'bg-[#161413] border-l border-[#2b2523] text-[#e7e5e4]'} shadow-2xl p-5 overflow-y-auto z-20 space-y-4`}>
          <div className="flex items-center justify-between pb-3 border-b border-[#282321]">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-[#24130d] border border-[#ea580c]/40 flex items-center justify-center text-[#f95721]">
                {getNodeIcon(selectedNode.type)}
              </div>
              <div>
                <h4 className="text-xs font-bold text-[#fafaf9] font-mono">{selectedNode.label}</h4>
                <div className="text-[10px] font-mono text-[#78716c] uppercase">Entity Type: {selectedNode.type}</div>
              </div>
            </div>
            <button
              onClick={() => setSelectedNodeId(null)}
              className="text-[#a8a29e] hover:text-[#fafaf9] p-1 cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Compromise Status */}
          <div className={`p-3 rounded-xl border text-xs font-mono ${
            selectedNode.is_compromised
              ? 'bg-[#29130d] border-[#ea580c]/60 text-[#fca5a5]'
              : 'bg-[#100f0e] border-[#2b2523] text-[#d6d3d1]'
          }`}>
            <div className="font-semibold flex items-center gap-1.5">
              {selectedNode.is_compromised && <ShieldAlert className="w-3.5 h-3.5 text-[#f95721]" />}
              <span>{selectedNode.is_compromised ? 'COMPROMISED ASSET' : 'BENIGN / UNCOMPROMISED'}</span>
            </div>
            <div className="text-[11px] text-[#a8a29e] mt-1">
              Part of reconstructive attack chain: {selectedNode.is_attack_path ? 'YES' : 'NO'}
            </div>
          </div>

          {/* Details & Metadata */}
          {selectedNode.details && (
            <div className="space-y-1.5 text-xs">
              <div className="text-[11px] font-mono text-[#78716c] uppercase">Entity Metadata</div>
              <div className="bg-[#0d0c0c] border border-[#2b2523] rounded-xl p-3 space-y-1.5 font-mono text-[11px]">
                {Object.entries(selectedNode.details).map(([k, v]) => (
                  <div key={k} className="flex justify-between text-[#a8a29e]">
                    <span className="text-[#78716c]">{k}:</span>
                    <span className="text-[#fafaf9] font-medium">{String(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Associated Timeline Events */}
          <div className="space-y-2">
            <div className="text-[11px] font-mono text-[#78716c] uppercase flex justify-between items-center">
              <span>Associated Events</span>
              <span className="font-semibold text-[#f95721] font-mono tabular-nums">{nodeEvents.length}</span>
            </div>

            <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
              {nodeEvents.map(evt => (
                <div
                  key={evt.id}
                  className="p-2.5 bg-[#0d0c0c] border border-[#282321] rounded-xl text-xs space-y-1"
                >
                  <div className="flex items-center justify-between text-[10px] font-mono text-[#78716c]">
                    <span className="text-[#f95721] font-semibold">{evt.timestamp.slice(11, 19)} UTC</span>
                    <span className="uppercase text-[#fca5a5] font-semibold">{evt.severity}</span>
                  </div>
                  <div className="text-[#fafaf9] font-medium truncate">{evt.action}</div>
                </div>
              ))}
            </div>
          </div>

        </div>
      )}

    </div>
  );
};
