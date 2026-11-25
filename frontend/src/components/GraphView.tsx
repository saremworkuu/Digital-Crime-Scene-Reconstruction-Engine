import React, { useState, useRef, useEffect, useMemo } from 'react';
import { AttackGraphData, GraphNode, EntityType } from '../types';
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
import {
  BENIGN_EXTERNAL_GROUP_ID,
  ROLE_PALETTE,
  VisualNodeRole,
  buildNodeRoleIndex,
  classifyVisualNodeRole,
  groupBenignExternalGraph,
} from '../utils/graphNodes';

interface GraphViewProps {
  graphData: AttackGraphData;
  onlyAttackPath?: boolean;
  onToggleAttackPath?: (onlyAttackPath: boolean) => void;
}

type LayoutType = 'hierarchical' | 'force' | 'circular';

const LEGEND_ROLES: VisualNodeRole[] = [
  'victim_host',
  'user',
  'attacker_c2',
  'payload_host',
  'exfil_destination',
  'mining_pool',
  'benign_external',
];

function computeCanvasAndPositions(
  nodes: GraphNode[],
  edges: { source: string; target: string }[],
  layout: LayoutType,
  roleById: Map<string, VisualNodeRole>
): { width: number; height: number; positions: Record<string, { x: number; y: number }> } {
  const positions: Record<string, { x: number; y: number }> = {};
  if (nodes.length === 0) {
    return { width: 880, height: 520, positions };
  }

  if (layout === 'hierarchical') {
    const tiers: Record<number, GraphNode[]> = { 0: [], 1: [], 2: [], 3: [], 4: [] };
    for (const n of nodes) {
      const role = roleById.get(n.id) || 'internal_host';
      if (role === 'attacker_c2' || role === 'benign_external' || role === 'benign_external_group') {
        tiers[0].push(n);
      } else if (role === 'payload_host') {
        tiers[1].push(n);
      } else if (role === 'victim_host' || role === 'internal_host') {
        tiers[2].push(n);
      } else if (role === 'user') {
        tiers[3].push(n);
      } else {
        tiers[4].push(n);
      }
    }

    const activeCols = [0, 1, 2, 3, 4].filter(idx => tiers[idx].length > 0);
    const maxRows = Math.max(1, ...activeCols.map(idx => tiers[idx].length));
    const width = Math.max(880, activeCols.length * 210 + 120);
    const height = Math.max(520, maxRows * 96 + 90);
    const stepX = (width - 180) / Math.max(1, activeCols.length - 1 || 1);

    activeCols.forEach((tierIdx, colPos) => {
      const colNodes = tiers[tierIdx];
      const x = activeCols.length === 1 ? width / 2 : 90 + colPos * stepX;
      const spacingY = (height - 80) / (colNodes.length + 1);
      colNodes.forEach((node, rowIdx) => {
        positions[node.id] = { x, y: 40 + spacingY * (rowIdx + 1) };
      });
    });

    return { width, height, positions };
  }

  if (layout === 'circular') {
    const minRadius = 190;
    const radius = Math.max(minRadius, (nodes.length * 115) / (2 * Math.PI));
    const size = Math.max(560, Math.ceil(radius * 2 + 180));
    const width = Math.max(880, size);
    const height = size;
    const cx = width / 2;
    const cy = height / 2;
    const angleStep = (2 * Math.PI) / nodes.length;

    nodes.forEach((node, i) => {
      const angle = i * angleStep - Math.PI / 2;
      positions[node.id] = {
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      };
    });
    return { width, height, positions };
  }

  // Iterative force-directed layout with explicit minimum separation to prevent overlaps
  const cols = Math.max(2, Math.ceil(Math.sqrt(nodes.length)));
  const width = Math.max(880, cols * 165 + 160);
  const height = Math.max(540, Math.ceil(nodes.length / cols) * 145 + 160);
  const cx = width / 2;
  const cy = height / 2;
  const initRadius = Math.max(150, Math.min(width, height) * 0.34);

  const coords = nodes.map((_, idx) => {
    const a = (2 * Math.PI * idx) / nodes.length;
    return { x: cx + initRadius * Math.cos(a), y: cy + initRadius * Math.sin(a) };
  });
  const indexById = new Map(nodes.map((n, i) => [n.id, i]));
  const idealK = 155;
  const minSeparation = 115;

  for (let iter = 0; iter < 120; iter++) {
    const disp = nodes.map(() => ({ x: 0, y: 0 }));

    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        let dx = coords[i].x - coords[j].x;
        let dy = coords[i].y - coords[j].y;
        let dist = Math.hypot(dx, dy);
        if (dist < 1) {
          dx = ((i + 1) % 3) - 1 || 1;
          dy = ((j + 1) % 3) - 1 || 1;
          dist = Math.hypot(dx, dy);
        }
        const rep = (idealK * idealK) / dist;
        const fx = (dx / dist) * rep;
        const fy = (dy / dist) * rep;
        disp[i].x += fx;
        disp[i].y += fy;
        disp[j].x -= fx;
        disp[j].y -= fy;
      }
    }

    for (const edge of edges) {
      const si = indexById.get(edge.source);
      const ti = indexById.get(edge.target);
      if (si === undefined || ti === undefined || si === ti) continue;
      const dx = coords[ti].x - coords[si].x;
      const dy = coords[ti].y - coords[si].y;
      const dist = Math.max(1, Math.hypot(dx, dy));
      const att = (dist * dist) / (idealK * 1.4);
      const fx = (dx / dist) * att;
      const fy = (dy / dist) * att;
      disp[si].x += fx;
      disp[si].y += fy;
      disp[ti].x -= fx;
      disp[ti].y -= fy;
    }

    const temp = Math.max(4, 28 * (1 - iter / 120));
    for (let i = 0; i < nodes.length; i++) {
      disp[i].x += (cx - coords[i].x) * 0.04;
      disp[i].y += (cy - coords[i].y) * 0.04;
      const d = Math.hypot(disp[i].x, disp[i].y) || 1;
      const step = Math.min(d, temp);
      coords[i].x = Math.min(width - 80, Math.max(80, coords[i].x + (disp[i].x / d) * step));
      coords[i].y = Math.min(height - 70, Math.max(60, coords[i].y + (disp[i].y / d) * step));
    }
  }

  // Final overlap-resolution pass
  for (let pass = 0; pass < 15; pass++) {
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = coords[j].x - coords[i].x;
        const dy = coords[j].y - coords[i].y;
        const dist = Math.hypot(dx, dy) || 0.5;
        if (dist < minSeparation) {
          const push = (minSeparation - dist) * 0.52;
          const ux = dx / dist;
          const uy = dy / dist;
          coords[i].x = Math.min(width - 75, Math.max(75, coords[i].x - ux * push));
          coords[i].y = Math.min(height - 65, Math.max(55, coords[i].y - uy * push));
          coords[j].x = Math.min(width - 75, Math.max(75, coords[j].x + ux * push));
          coords[j].y = Math.min(height - 65, Math.max(55, coords[j].y + uy * push));
        }
      }
    }
  }

  nodes.forEach((n, idx) => {
    positions[n.id] = coords[idx];
  });
  return { width, height, positions };
}

export const GraphView: React.FC<GraphViewProps> = ({
  graphData,
  onlyAttackPath: controlledOnlyAttackPath,
  onToggleAttackPath,
}) => {
  const { activeCaseId, activeCaseEvents, activeCaseDetections, theme } = useApp();
  const isLight = theme === 'light';
  const svgRef = useRef<SVGSVGElement>(null);

  const [layout, setLayout] = useState<LayoutType>('hierarchical');
  const [localOnlyAttackPath, setLocalOnlyAttackPath] = useState(true);
  const onlyAttackPath =
    controlledOnlyAttackPath !== undefined ? controlledOnlyAttackPath : localOnlyAttackPath;
  const setOnlyAttackPath = (val: boolean) => {
    if (onToggleAttackPath) onToggleAttackPath(val);
    else setLocalOnlyAttackPath(val);
  };

  const [expandBenignGroup, setExpandBenignGroup] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [hoveredEdgeId, setHoveredEdgeId] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const [nodePositions, setNodePositions] = useState<Record<string, { x: number; y: number }>>({});

  const roleIndex = useMemo(
    () => buildNodeRoleIndex(activeCaseDetections, activeCaseEvents),
    [activeCaseDetections, activeCaseEvents]
  );

  // Filter nodes & edges and collapse benign external IPs when showing full topology
  const { filteredNodes, filteredEdges, benignExternalCount } = useMemo(() => {
    const baseNodes = onlyAttackPath
      ? graphData.nodes.filter(n => n.is_attack_path || n.is_compromised)
      : graphData.nodes;
    const baseIds = new Set(baseNodes.map(n => n.id));
    const baseEdges = graphData.edges.filter(
      e => baseIds.has(e.source) && baseIds.has(e.target) && (!onlyAttackPath || e.is_attack_path)
    );

    if (onlyAttackPath) {
      return { filteredNodes: baseNodes, filteredEdges: baseEdges, benignExternalCount: 0 };
    }

    const grouped = groupBenignExternalGraph(baseNodes, baseEdges, expandBenignGroup);
    return {
      filteredNodes: grouped.nodes,
      filteredEdges: grouped.edges,
      benignExternalCount: grouped.benignCount,
    };
  }, [graphData.nodes, graphData.edges, onlyAttackPath, expandBenignGroup]);

  const roleById = useMemo(() => {
    const map = new Map<string, VisualNodeRole>();
    for (const node of filteredNodes) {
      map.set(node.id, classifyVisualNodeRole(node, roleIndex));
    }
    return map;
  }, [filteredNodes, roleIndex]);

  const [canvasSize, setCanvasSize] = useState({ width: 880, height: 520 });

  useEffect(() => {
    const computed = computeCanvasAndPositions(filteredNodes, filteredEdges, layout, roleById);
    setCanvasSize({ width: computed.width, height: computed.height });
    setNodePositions(computed.positions);
  }, [filteredNodes, filteredEdges, layout, roleById]);

  const selectedNode = useMemo(() => {
    if (!selectedNodeId) return null;
    return filteredNodes.find(n => n.id === selectedNodeId)
      || graphData.nodes.find(n => n.id === selectedNodeId)
      || null;
  }, [filteredNodes, graphData.nodes, selectedNodeId]);

  const hoveredNode = useMemo(() => {
    if (!hoveredNodeId) return null;
    return filteredNodes.find(n => n.id === hoveredNodeId) || null;
  }, [filteredNodes, hoveredNodeId]);

  const nodeEvents = useMemo(() => {
    if (!selectedNode || selectedNode.id === BENIGN_EXTERNAL_GROUP_ID) return [];
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

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.12 : 0.89;
    setZoom(z => Math.min(3, Math.max(0.35, Number((z * factor).toFixed(2)))));
  };

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
      const scaleX = canvasSize.width / rect.width;
      const scaleY = canvasSize.height / rect.height;
      const x = ((e.clientX - rect.left) * scaleX - pan.x) / zoom;
      const y = ((e.clientY - rect.top) * scaleY - pan.y) / zoom;
      setNodePositions(prev => ({
        ...prev,
        [draggingNodeId]: { x, y },
      }));
    }
  };

  const handleMouseUp = () => {
    setIsPanning(false);
    setDraggingNodeId(null);
  };

  const handleTouchStart = (e: React.TouchEvent) => {
    if (e.touches.length === 1) {
      const touch = e.touches[0];
      if ((e.target as HTMLElement).tagName === 'svg') {
        setIsPanning(true);
        setDragStart({ x: touch.clientX - pan.x, y: touch.clientY - pan.y });
      }
    }
  };

  const handleTouchMove = (e: React.TouchEvent) => {
    if (e.touches.length === 1) {
      const touch = e.touches[0];
      if (isPanning) {
        setPan({ x: touch.clientX - dragStart.x, y: touch.clientY - dragStart.y });
      } else if (draggingNodeId) {
        const rect = svgRef.current?.getBoundingClientRect();
        if (!rect) return;
        const scaleX = canvasSize.width / rect.width;
        const scaleY = canvasSize.height / rect.height;
        const x = ((touch.clientX - rect.left) * scaleX - pan.x) / zoom;
        const y = ((touch.clientY - rect.top) * scaleY - pan.y) / zoom;
        setNodePositions(prev => ({
          ...prev,
          [draggingNodeId]: { x, y },
        }));
      }
    }
  };

  const handleTouchEnd = () => {
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

  const edgeKeySet = useMemo(
    () => new Set(filteredEdges.map(e => `${e.source}->${e.target}`)),
    [filteredEdges]
  );

  return (
    <div className="relative bg-[#161413]/95 border border-[#2b2523] rounded-2xl overflow-hidden flex flex-col min-h-[460px] sm:min-h-[560px] md:min-h-[640px] shadow-2xl backdrop-blur-xl">

      {/* Top Controls Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 sm:gap-3 p-2.5 sm:p-3.5 bg-[#12100f] border-b border-[#282321] z-10 text-xs">

        {/* Layout Algorithms */}
        <div className="flex items-center gap-1.5 sm:gap-2.5">
          <span className="text-[#a8a29e] font-mono text-[10px] sm:text-[11px] flex items-center gap-1 sm:gap-1.5 font-medium">
            <Layers className="w-3.5 h-3.5 text-[#f95721]" /> Layout:
          </span>
          <div className="flex items-center p-0.5 bg-[#0d0c0c] border border-[#2b2523] rounded-lg">
            {([
              { key: 'hierarchical', label: 'Layered' },
              { key: 'force', label: 'Force-Directed' },
              { key: 'circular', label: 'Concentric' },
            ] as const).map(opt => (
              <button
                key={opt.key}
                onClick={() => setLayout(opt.key)}
                className={`px-2 sm:px-3 py-1 rounded-md transition-all text-[11px] sm:text-xs font-mono cursor-pointer ${
                  layout === opt.key
                    ? 'bg-[#2a140d] text-[#f95721] font-semibold border border-[#ea580c]/50 shadow-[0_0_10px_rgba(249,87,33,0.2)]'
                    : 'text-[#a8a29e] hover:text-[#fafaf9]'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        {/* Attack Path Toggle, Benign Group Control & View Controls */}
        <div className="flex flex-wrap items-center gap-2 sm:gap-3 text-xs">

          <label className="flex items-center gap-1.5 sm:gap-2 cursor-pointer text-xs text-[#fafaf9] select-none bg-[#0d0c0c] border border-[#2b2523] px-2.5 sm:px-3 py-1 sm:py-1.5 rounded-lg hover:border-[#38312d] transition-colors">
            <input
              type="checkbox"
              checked={onlyAttackPath}
              onChange={(e) => setOnlyAttackPath(e.target.checked)}
              className="rounded border-[#38312d] bg-[#141211] text-[#f95721] accent-[#f95721] cursor-pointer"
            />
            <span className="font-semibold text-[#f95721] font-mono text-[11px] sm:text-xs">Attack Path Only</span>
          </label>

          {!onlyAttackPath && benignExternalCount > 1 && (
            <button
              type="button"
              onClick={() => setExpandBenignGroup(v => !v)}
              className="px-2.5 py-1 rounded-lg bg-[#1e293b] border border-[#475569] text-[#e2e8f0] hover:bg-[#334155] font-mono text-[11px] cursor-pointer transition-colors"
            >
              {expandBenignGroup
                ? `Collapse Benign IPs (${benignExternalCount})`
                : `Expand Benign IPs (${benignExternalCount})`}
            </button>
          )}

          {/* Zoom & Pan Controls */}
          <div className="flex items-center gap-0.5 sm:gap-1 bg-[#0d0c0c] border border-[#2b2523] rounded-lg p-0.5">
            <button
              onClick={() => setZoom(z => Math.max(0.35, Number((z - 0.15).toFixed(2))))}
              className="p-1 rounded text-[#a8a29e] hover:text-[#fafaf9] hover:bg-[#25201e] transition-colors cursor-pointer"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <span className="text-[10px] sm:text-[11px] font-mono text-[#d6d3d1] px-1 sm:px-1.5 tabular-nums">
              {Math.round(zoom * 100)}%
            </span>
            <button
              onClick={() => setZoom(z => Math.min(3, Number((z + 0.15).toFixed(2))))}
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
            className="flex items-center gap-1.5 px-2.5 sm:px-3 py-1 sm:py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] border border-[#38312d] transition-all font-mono text-[11px] sm:text-xs cursor-pointer shadow-sm"
            title="Export vector SVG graph"
          >
            <Download className="w-3.5 h-3.5 text-[#f95721]" />
            <span className="hidden sm:inline">Export SVG</span>
          </button>

        </div>

      </div>

      {/* SVG Canvas Viewport */}
      <div
        className={`flex-1 relative overflow-hidden ${isLight ? 'bg-slate-50' : 'bg-[#0c0b0a]'} cursor-grab active:cursor-grabbing select-none transition-colors touch-none`}
        onWheel={handleWheel}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onTouchStart={handleTouchStart}
        onTouchMove={handleTouchMove}
        onTouchEnd={handleTouchEnd}
      >
        <svg
          ref={svgRef}
          className="w-full h-[380px] sm:h-[460px] md:h-[520px]"
          viewBox={`0 0 ${canvasSize.width} ${canvasSize.height}`}
        >
          <defs>
            {isLight && (
              <pattern id="grid-light" width="28" height="28" patternUnits="userSpaceOnUse">
                <circle cx="2" cy="2" r="1" fill="#cbd5e1" opacity="0.6" />
              </pattern>
            )}

            <marker
              id="arrow-attack"
              viewBox="0 0 10 10"
              refX="20"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill={isLight ? '#dc2626' : '#ef4444'} />
            </marker>

            <marker
              id="arrow-benign"
              viewBox="0 0 10 10"
              refX="20"
              refY="5"
              markerWidth="5"
              markerHeight="5"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill={isLight ? '#64748b' : '#57534e'} />
            </marker>
          </defs>

          {isLight && <rect width="100%" height="100%" fill="url(#grid-light)" />}

          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>

            {/* Directed Relationship Edges — labels appear on hover only so edges never stack */}
            {filteredEdges.map((edge) => {
              const srcPos = nodePositions[edge.source];
              const tgtPos = nodePositions[edge.target];
              if (!srcPos || !tgtPos) return null;

              const isAttack = Boolean(edge.is_attack_path);
              const isHovered =
                hoveredEdgeId === edge.id ||
                hoveredNodeId === edge.source ||
                hoveredNodeId === edge.target;
              const hasReverse = edgeKeySet.has(`${edge.target}->${edge.source}`);

              const dx = tgtPos.x - srcPos.x;
              const dy = tgtPos.y - srcPos.y;
              const len = Math.hypot(dx, dy) || 1;
              const curveOffset = hasReverse ? 24 : 0;
              const midX = (srcPos.x + tgtPos.x) / 2 - (dy / len) * curveOffset;
              const midY = (srcPos.y + tgtPos.y) / 2 + (dx / len) * curveOffset;
              const pathD = hasReverse
                ? `M ${srcPos.x} ${srcPos.y} Q ${midX} ${midY} ${tgtPos.x} ${tgtPos.y}`
                : `M ${srcPos.x} ${srcPos.y} L ${tgtPos.x} ${tgtPos.y}`;

              const labelText = edge.label.length > 26 ? edge.label.slice(0, 24) + '..' : edge.label;
              const labelWidth = Math.max(76, labelText.length * 6.4 + 18);

              return (
                <g
                  key={edge.id}
                  onMouseEnter={() => setHoveredEdgeId(edge.id)}
                  onMouseLeave={() => setHoveredEdgeId(prev => (prev === edge.id ? null : prev))}
                >
                  <title>{`${edge.label} (${edge.count} events)`}</title>
                  {/* Wide transparent hover target */}
                  <path
                    d={pathD}
                    fill="none"
                    stroke="transparent"
                    strokeWidth={14}
                    className="cursor-pointer"
                  />
                  <path
                    d={pathD}
                    fill="none"
                    stroke={
                      isHovered
                        ? (isLight ? '#c2410c' : '#fbbf24')
                        : isAttack
                          ? (isLight ? '#dc2626' : '#ef4444')
                          : (isLight ? '#94a3b8' : '#475569')
                    }
                    strokeWidth={isHovered ? 3 : isAttack ? 2.2 : 1.2}
                    strokeDasharray={isAttack ? 'none' : '4 3'}
                    markerEnd={isAttack ? 'url(#arrow-attack)' : 'url(#arrow-benign)'}
                  />

                  {isHovered && (
                    <g transform={`translate(${midX}, ${midY})`} className="pointer-events-none">
                      <rect
                        x={-labelWidth / 2}
                        y="-10"
                        width={labelWidth}
                        height="20"
                        rx="5"
                        fill={isLight ? '#ffffff' : '#141211'}
                        stroke={isAttack ? '#ef4444' : '#64748b'}
                        strokeWidth="1.2"
                      />
                      <text
                        x="0"
                        y="3.5"
                        textAnchor="middle"
                        fill={isLight ? '#0f172a' : '#fafaf9'}
                        fontSize="9.5"
                        fontFamily="JetBrains Mono, monospace"
                        fontWeight="600"
                      >
                        {labelText}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}

            {/* Entity Nodes */}
            {filteredNodes.map((node) => {
              const pos = nodePositions[node.id] || { x: canvasSize.width / 2, y: canvasSize.height / 2 };
              const isSelected = selectedNodeId === node.id;
              const isHovered = hoveredNodeId === node.id;
              const isGroup = node.id === BENIGN_EXTERNAL_GROUP_ID;
              const visualRole = roleById.get(node.id) || 'internal_host';
              const palette = ROLE_PALETTE[visualRole];
              const fillColor = isLight ? palette.fillLight : palette.fillDark;
              const textColor = isLight ? palette.textLight : palette.textDark;
              const shortLabel = node.label.length > 18 ? node.label.slice(0, 16) + '..' : node.label;

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  className="cursor-pointer"
                  onMouseEnter={() => setHoveredNodeId(node.id)}
                  onMouseLeave={() => setHoveredNodeId(prev => (prev === node.id ? null : prev))}
                  onClick={(e) => {
                    e.stopPropagation();
                    if (isGroup) {
                      setExpandBenignGroup(true);
                      return;
                    }
                    setSelectedNodeId(node.id);
                  }}
                  onMouseDown={(e) => {
                    e.stopPropagation();
                    setDraggingNodeId(node.id);
                  }}
                >
                  <title>{`${node.label} (${palette.label}) · ${node.event_count} events`}</title>

                  {(visualRole === 'victim_host' || visualRole === 'attacker_c2') && (
                    <circle
                      r="24"
                      fill={palette.stroke}
                      opacity={isLight ? '0.16' : '0.18'}
                    />
                  )}

                  {isGroup ? (
                    <rect
                      x="-24"
                      y="-18"
                      width="48"
                      height="36"
                      rx="10"
                      fill={fillColor}
                      stroke={palette.stroke}
                      strokeWidth={isHovered ? 2.8 : 2}
                      strokeDasharray="4 2"
                    />
                  ) : (
                    <circle
                      r="18"
                      fill={fillColor}
                      stroke={isHovered || isSelected ? '#ffffff' : palette.stroke}
                      strokeWidth={isSelected || isHovered ? 3 : 2}
                    />
                  )}

                  <text
                    x="0"
                    y="3.5"
                    textAnchor="middle"
                    fill={textColor}
                    fontSize="7.5"
                    fontFamily="JetBrains Mono, monospace"
                    fontWeight="bold"
                  >
                    {palette.badge}
                  </text>

                  <text
                    x="0"
                    y="31"
                    textAnchor="middle"
                    fill={isSelected ? palette.stroke : (isLight ? '#0f172a' : '#e7e5e4')}
                    fontSize="10.5"
                    fontFamily="JetBrains Mono, monospace"
                    fontWeight={isSelected ? 'bold' : '600'}
                  >
                    {shortLabel}
                  </text>

                  <text
                    x="0"
                    y="43"
                    textAnchor="middle"
                    fill={isLight ? '#64748b' : '#78716c'}
                    fontSize="9"
                    fontFamily="JetBrains Mono, monospace"
                  >
                    {isGroup ? 'Click to expand' : `${node.event_count} events`}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>

        {/* Full-Label Hover Tooltip (bottom-right non-occluding readout) */}
        {hoveredNode && (
          <div className={`absolute top-3 left-3 max-w-xs rounded-xl px-3 py-2 text-[11px] font-mono shadow-lg border pointer-events-none z-10 ${
            isLight ? 'bg-white/95 border-slate-300 text-slate-900' : 'bg-[#161413]/95 border-[#3a322e] text-[#fafaf9]'
          }`}>
            <div className="font-bold break-all">{hoveredNode.label}</div>
            <div className="text-[10px] text-[#a8a29e] mt-0.5">
              Role: {ROLE_PALETTE[roleById.get(hoveredNode.id) || 'internal_host'].label} · {hoveredNode.event_count} event(s)
            </div>
            {hoveredNode.id === BENIGN_EXTERNAL_GROUP_ID && Array.isArray(hoveredNode.details?.sample_ips) && (
              <div className="text-[10px] text-[#94a3b8] mt-1">
                Includes: {hoveredNode.details.sample_ips.join(', ')}... (click node to expand)
              </div>
            )}
          </div>
        )}
      </div>

      {/* Dedicated Non-Overlapping Legend Footer */}
      <div className={`px-4 py-2.5 border-t text-[11px] font-mono flex flex-wrap items-center gap-x-5 gap-y-2 ${
        isLight ? 'bg-white border-slate-200 text-slate-700' : 'bg-[#12100f] border-[#282321] text-[#d6d3d1]'
      }`}>
        <span className="text-[10px] uppercase font-semibold text-[#78716c]">Legend:</span>
        {LEGEND_ROLES.map(role => {
          const item = ROLE_PALETTE[role];
          return (
            <div key={role} className="flex items-center gap-1.5">
              <span className={`w-2.5 h-2.5 rounded-full border ${item.swatchClass}`} />
              <span>{item.label}</span>
            </div>
          );
        })}
        <div className="flex items-center gap-1.5">
          <span className="w-4 h-0.5 bg-[#ef4444]" />
          <span>Attack Edge (hover edge for label)</span>
        </div>
      </div>

      {/* Node Detail Inspector Drawer */}
      {selectedNode && (
        <div className={`absolute top-14 right-0 bottom-0 w-80 ${isLight ? 'bg-white border-l border-slate-200 text-slate-800' : 'bg-[#161413] border-l border-[#2b2523] text-[#e7e5e4]'} shadow-2xl p-5 overflow-y-auto z-20 space-y-4`}>
          <div className="flex items-center justify-between pb-3 border-b border-[#282321]">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-[#24130d] border border-[#ea580c]/40 flex items-center justify-center text-[#f95721]">
                {getNodeIcon(selectedNode.type)}
              </div>
              <div>
                <h4 className="text-xs font-bold text-[#fafaf9] font-mono break-all">{selectedNode.label}</h4>
                <div className="text-[10px] font-mono text-[#78716c] uppercase">
                  {ROLE_PALETTE[roleById.get(selectedNode.id) || 'internal_host'].label} ({selectedNode.type})
                </div>
              </div>
            </div>
            <button
              onClick={() => setSelectedNodeId(null)}
              className="text-[#a8a29e] hover:text-[#fafaf9] p-1 cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className={`p-3 rounded-xl border text-xs font-mono ${
            selectedNode.is_compromised
              ? 'bg-[#29130d] border-[#ea580c]/60 text-[#fca5a5]'
              : 'bg-[#100f0e] border-[#2b2523] text-[#d6d3d1]'
          }`}>
            <div className="font-semibold flex items-center gap-1.5">
              {selectedNode.is_compromised && <ShieldAlert className="w-3.5 h-3.5 text-[#f95721]" />}
              <span>{selectedNode.is_compromised ? 'HIGHLIGHTED / FLAGGED ENTITY' : 'OBSERVED ENTITY'}</span>
            </div>
            <div className="text-[11px] text-[#a8a29e] mt-1">
              Part of reconstructive attack chain: {selectedNode.is_attack_path ? 'YES' : 'NO'}
            </div>
          </div>

          {selectedNode.details && (
            <div className="space-y-1.5 text-xs">
              <div className="text-[11px] font-mono text-[#78716c] uppercase">Entity Metadata</div>
              <div className="bg-[#0d0c0c] border border-[#2b2523] rounded-xl p-3 space-y-1.5 font-mono text-[11px]">
                {Object.entries(selectedNode.details).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-2 text-[#a8a29e]">
                    <span className="text-[#78716c] shrink-0">{k}:</span>
                    <span className="text-[#fafaf9] font-medium text-right break-all">{Array.isArray(v) ? v.join(', ') : String(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

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
