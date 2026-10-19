import React, { useState } from 'react';
import { ExternalLink, Globe2, Map, Crosshair, Sparkles } from 'lucide-react';
import { CyberThreatGlobe } from './CyberThreatGlobe';
import { useApp } from '../store';

interface ThreatLocation {
  id: string;
  city: string;
  country: string;
  count: number;
  max: number;
  x: number; // percentage on 2D map
  y: number; // percentage on 2D map
  severity: 'critical' | 'high' | 'medium';
}

const THREAT_LOCATIONS: ThreatLocation[] = [
  { id: 'syd', city: 'Sydney', country: 'Australia', count: 72, max: 100, x: 86, y: 76, severity: 'critical' },
  { id: 'nyc', city: 'New York', country: 'USA', count: 58, max: 100, x: 28, y: 34, severity: 'high' },
  { id: 'sp', city: 'São Paulo', country: 'Brazil', count: 21, max: 100, x: 36, y: 72, severity: 'medium' },
  { id: 'sg', city: 'Singapore', country: 'Singapore', count: 12, max: 100, x: 76, y: 56, severity: 'medium' },
  { id: 'la', city: 'Los Angeles', country: 'USA', count: 4, max: 100, x: 18, y: 38, severity: 'medium' },
  { id: 'mia', city: 'Miami', country: 'USA', count: 0.75, max: 100, x: 26, y: 44, severity: 'medium' },
];

interface ThreatMapProps {
  onOpenReport?: () => void;
}

export const ThreatMap: React.FC<ThreatMapProps> = ({ onOpenReport }) => {
  const { theme } = useApp();
  const isLight = theme === 'light';
  const [selectedRange, setSelectedRange] = useState('Last Week');
  const [activeLoc, setActiveLoc] = useState<ThreatLocation>(THREAT_LOCATIONS[0]);
  const [viewMode, setViewMode] = useState<'2d' | '3d'>('3d');
  const [globeMode, setGlobeMode] = useState<'default' | 'advanced'>('default');

  return (
    <div className="rounded-2xl bg-[#161413]/90 border border-[#2b2523] p-4 sm:p-5 space-y-4 sm:space-y-5 backdrop-blur-xl relative overflow-hidden flex flex-col justify-between shadow-2xl w-full">
      {/* Top Header Bar */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2.5">
          <div className="w-2.5 h-2.5 rounded-full bg-[#f95721] shadow-[0_0_10px_#f95721] animate-pulse shrink-0" />
          <h3 className="text-sm font-semibold text-[#fafaf9] tracking-tight">Threat map</h3>
          <span className="text-[10px] font-mono text-[#a8a29e] bg-[#221e1c] px-2 py-0.5 rounded border border-[#2e2926] hidden sm:inline-block">
            Global Spatial Attack Mesh
          </span>
        </div>

        <div className="flex items-center gap-2 sm:gap-2.5 flex-wrap">
          {/* 3D vs 2D View Switcher */}
          <div className="inline-flex items-center p-0.5 rounded-lg bg-[#1a1817] border border-[#2c2724] text-xs font-mono">
            <button
              type="button"
              onClick={() => setViewMode('3d')}
              className={`px-2.5 py-1 rounded-md transition-all flex items-center gap-1.5 text-xs font-medium cursor-pointer ${
                viewMode === '3d'
                  ? 'bg-gradient-to-r from-[#ea580c] to-[#f95721] text-white shadow-[0_0_12px_rgba(249,87,33,0.4)]'
                  : 'text-[#a8a29e] hover:text-[#d6d3d1]'
              }`}
              title="Interactive 3D Three.js Geodesic Globe"
            >
              <Globe2 className="w-3.5 h-3.5" />
              <span>3D Globe</span>
            </button>
            <button
              type="button"
              onClick={() => setViewMode('2d')}
              className={`px-2.5 py-1 rounded-md transition-all flex items-center gap-1.5 text-xs font-medium cursor-pointer ${
                viewMode === '2d'
                  ? 'bg-[#292422] text-[#fafaf9] shadow-sm'
                  : 'text-[#a8a29e] hover:text-[#d6d3d1]'
              }`}
              title="2D Map Projection"
            >
              <Map className="w-3.5 h-3.5 text-[#f95721]" />
              <span>2D Map</span>
            </button>
          </div>

          {/* Time Range Selector */}
          <div className="relative">
            <select
              value={selectedRange}
              onChange={(e) => setSelectedRange(e.target.value)}
              className="appearance-none bg-[#191716] border border-[#2c2724] rounded-lg px-3 py-1 text-xs text-[#d6d3d1] font-mono focus:outline-none focus:border-[#f95721]/50 cursor-pointer pr-7"
            >
              <option>Last 24 Hours</option>
              <option>Last Week</option>
              <option>Last 30 Days</option>
            </select>
            <span className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-[#78716c] text-[10px]">
              ▼
            </span>
          </div>
        </div>
      </div>

      {/* Main Canvas Area: 3D Geodesic Sphere vs 2D Flat Projection */}
      {viewMode === '3d' ? (
        <div className="relative w-full space-y-2">
          {/* Target Vector & Interactive Telemetry Pill */}
          <div className="flex items-center justify-between flex-wrap gap-2 text-xs px-1">
            <div className="flex items-center gap-2 font-mono text-[11px] text-[#d6d3d1] flex-wrap">
              <Crosshair className="w-3.5 h-3.5 text-[#f95721] shrink-0" />
              <span className="text-[#a8a29e]">Target Vector:</span>
              <strong className="text-[#fafaf9]">{activeLoc.city}, {activeLoc.country}</strong>
              <span className={`text-[10px] px-2 py-0.5 rounded font-semibold ${
                activeLoc.severity === 'critical'
                  ? 'bg-red-950/80 text-red-400 border border-red-800/40'
                  : activeLoc.severity === 'high'
                  ? 'bg-amber-950/80 text-amber-400 border border-amber-800/40'
                  : 'bg-orange-950/80 text-orange-400 border border-orange-800/40'
              }`}>
                {activeLoc.count} Incidents
              </span>
            </div>

            <div className="hidden sm:flex items-center gap-1.5 text-[10px] font-mono text-[#a8a29e]">
              <Sparkles className="w-3 h-3 text-[#f95721]" />
              <span>Click gateway below to focus · Drag to orbit</span>
            </div>
          </div>

          {/* Borderless 3D Canvas Viewport: Freely floating, responsive & elegant */}
          <div className="relative w-full h-[340px] sm:h-[400px] md:h-[430px] flex items-center justify-center overflow-hidden rounded-xl">
            {/* Ambient Cyber Radial Glow */}
            <div 
              className="pointer-events-none absolute inset-0 opacity-40"
              style={{
                background: 'radial-gradient(circle at center, rgba(249, 87, 33, 0.14) 0%, rgba(249, 87, 33, 0.02) 50%, transparent 72%)'
              }}
            />

            {/* 3D Cyber Threat Globe with dynamic camera fitting */}
            <CyberThreatGlobe
              height="100%"
              className="w-full h-full"
              threatPointsCount={64}
              interactive={true}
              mode={globeMode}
              onModeChange={setGlobeMode}
              showControls={false}
              activeLocationId={activeLoc.id}
              onLocationSelect={(locId) => {
                const found = THREAT_LOCATIONS.find(l => l.id === locId);
                if (found) setActiveLoc(found);
              }}
            />

            {/* Floating Segmented Control (Default / Advanced) matching Reference Picture 1 */}
            <div className="absolute bottom-2 left-1/2 -translate-x-1/2 z-20">
              <div className="inline-flex items-center p-1 rounded-xl bg-[#191716]/90 border border-[#2c2724] shadow-xl backdrop-blur-md text-xs font-mono">
                <button
                  type="button"
                  onClick={() => setGlobeMode('default')}
                  className={`px-3.5 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                    globeMode === 'default'
                      ? 'bg-[#292422] text-[#fafaf9] shadow-sm'
                      : 'text-[#a8a29e] hover:text-[#d6d3d1]'
                  }`}
                >
                  Default
                </button>
                <button
                  type="button"
                  onClick={() => setGlobeMode('advanced')}
                  className={`px-3.5 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                    globeMode === 'advanced'
                      ? 'bg-gradient-to-r from-[#ea580c] to-[#f95721] text-white shadow-[0_0_12px_rgba(249,87,33,0.4)]'
                      : 'text-[#a8a29e] hover:text-[#d6d3d1]'
                  }`}
                >
                  Advanced
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* 2D Flat Map Projection */
        <div className={`relative w-full aspect-[2/1] sm:aspect-[2.2/1] ${isLight ? 'bg-slate-100 border-slate-200' : 'bg-[#0c0b0a] border-[#2b2523]'} rounded-xl border overflow-hidden flex items-center justify-center transition-colors`}>
          <svg 
            viewBox="0 0 1000 500" 
            className={`w-full h-full opacity-35 object-cover pointer-events-none ${isLight ? 'fill-slate-400' : 'fill-[#443d39]'}`}
            xmlns="http://www.w3.org/2000/svg"
          >
            {/* North America */}
            <path d="M120,60 Q180,50 250,90 Q300,140 280,180 Q250,220 220,250 Q160,220 130,170 Q100,120 120,60 Z" />
            {/* South America */}
            <path d="M280,260 Q340,280 350,340 Q330,420 290,460 Q270,420 260,350 Q260,290 280,260 Z" />
            {/* Europe */}
            <path d="M460,80 Q520,70 540,110 Q520,150 480,160 Q450,140 440,100 Z" />
            {/* Africa */}
            <path d="M460,180 Q530,190 550,260 Q530,340 480,360 Q440,300 440,230 Z" />
            {/* Asia */}
            <path d="M560,70 Q700,60 820,130 Q840,220 740,260 Q650,230 580,180 Z" />
            {/* Australia */}
            <path d="M780,330 Q860,330 870,380 Q840,430 780,420 Q750,380 780,330 Z" />
          </svg>

          {/* Pulsing Concentric Ripple Rings for each location */}
          {THREAT_LOCATIONS.map((loc) => {
            const isSelected = activeLoc.id === loc.id;
            return (
              <div
                key={loc.id}
                onClick={() => setActiveLoc(loc)}
                style={{ left: `${loc.x}%`, top: `${loc.y}%` }}
                className="absolute -translate-x-1/2 -translate-y-1/2 cursor-pointer group z-10"
              >
                <div 
                  className={`absolute -inset-3 rounded-full animate-ping pointer-events-none opacity-40 ${
                    loc.count > 40 ? 'bg-[#f95721]' : 'bg-[#ea580c]'
                  }`}
                  style={{ animationDuration: loc.count > 40 ? '1.8s' : '2.6s' }}
                />
                
                <div 
                  className={`w-7 h-7 rounded-full border flex items-center justify-center transition-transform duration-200 group-hover:scale-125 ${
                    isSelected 
                      ? 'border-white bg-[#f95721]/50 shadow-[0_0_12px_#f95721]' 
                      : 'border-[#f95721]/60 bg-[#f95721]/20'
                  }`}
                >
                  <div className="w-2.5 h-2.5 rounded-full bg-[#f95721] shadow-[0_0_10px_#f95721]" />
                </div>

                <div className="pointer-events-none absolute -top-8 left-1/2 -translate-x-1/2 px-2 py-0.5 rounded bg-[#161413] border border-[#3b3430] text-[10px] font-mono text-[#fafaf9] whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity shadow-lg">
                  {loc.city}: {loc.count} incidents
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Telemetry Volume Bars */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-[11px] font-mono text-[#a8a29e] px-1">
          <span>Active Monitored Gateways</span>
          <span className="hidden sm:inline">Relative Threat Density</span>
        </div>

        {THREAT_LOCATIONS.map((loc) => {
          const isSelected = activeLoc.id === loc.id;
          const widthPct = Math.max(4, Math.min(100, (loc.count / 72) * 100));

          return (
            <div
              key={loc.id}
              onClick={() => setActiveLoc(loc)}
              className={`group flex items-center justify-between gap-3 py-1.5 px-3 rounded-xl cursor-pointer transition-all border ${
                isSelected 
                  ? 'bg-[#28221f] border-[#f95721]/60 shadow-[0_0_12px_rgba(249,87,33,0.15)]' 
                  : 'bg-[#181615] border-transparent hover:bg-[#1f1b19] hover:border-[#2f2926]'
              }`}
            >
              {/* Number and City */}
              <div className="flex items-center gap-2.5 min-w-[120px] sm:w-44 shrink-0">
                <span className={`text-xs font-mono font-bold w-6 sm:w-7 ${
                  isSelected ? 'text-[#f95721]' : 'text-[#d6d3d1]'
                }`}>
                  {loc.count}
                </span>
                <span className={`text-xs truncate ${
                  isSelected ? 'text-[#fafaf9] font-medium' : 'text-[#a8a29e] group-hover:text-[#fafaf9]'
                }`}>
                  {loc.city}, {loc.country}
                </span>
              </div>

              {/* Horizontal Volume Bar */}
              <div className="flex-1 min-w-[60px] h-2 bg-[#25201d] rounded-full overflow-hidden flex items-center">
                <div
                  style={{ width: `${widthPct}%` }}
                  className={`h-full rounded-full transition-all duration-500 ${
                    loc.count > 50
                      ? 'bg-gradient-to-r from-[#ea580c] to-[#f95721] shadow-[0_0_10px_rgba(249,87,33,0.7)]'
                      : isSelected
                      ? 'bg-gradient-to-r from-[#d94e10] to-[#ea580c]'
                      : 'bg-[#ea580c]/80'
                  }`}
                />
              </div>

              {/* Severity Badge */}
              <span className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded border shrink-0 ${
                loc.severity === 'critical'
                  ? 'text-red-400 bg-red-950/40 border-red-900/40'
                  : loc.severity === 'high'
                  ? 'text-amber-400 bg-amber-950/40 border-amber-900/40'
                  : 'text-stone-400 bg-stone-900/40 border-stone-800/40'
              }`}>
                {loc.severity}
              </span>
            </div>
          );
        })}
      </div>

      {/* Bottom Action Footer */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pt-2 border-t border-[#2b2523]">
        <div className="text-[11px] font-mono text-[#78716c] flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
          <span>Real-time telemetry streaming active</span>
        </div>

        <button
          onClick={onOpenReport}
          className="w-full sm:w-auto px-4 py-2 rounded-xl bg-[#191716] hover:bg-[#23201d] border border-[#2e2926] text-xs font-semibold text-[#fafaf9] flex items-center justify-center gap-2 transition-all hover:border-[#f95721]/50 shadow-sm cursor-pointer"
        >
          <span>Full Forensic Report</span>
          <ExternalLink className="w-3.5 h-3.5 text-[#f95721]" />
        </button>
      </div>
    </div>
  );
};
