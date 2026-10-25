import React, { useState } from 'react';

import { useApp } from '../store';

import { GraphView } from '../components/GraphView';

import { CyberThreatGlobe } from '../components/CyberThreatGlobe';

import { GitBranch, ShieldAlert, Server, Globe, UserCheck, Layers, Globe2, Network, Sparkles } from 'lucide-react';



export const AttackGraph: React.FC = () => {

  const { activeCase, activeCaseGraph } = useApp();

  const [viewMode, setViewMode] = useState<'2d' | '3d'>('2d');

  const [globeMode, setGlobeMode] = useState<'default' | 'advanced'>('advanced');



  const compromisedHosts = activeCaseGraph.nodes.filter(n => n.type === 'host' && (n.is_compromised || n.is_attack_path));

  const compromisedUsers = activeCaseGraph.nodes.filter(n => n.type === 'user' && (n.is_compromised || n.is_attack_path));

  const threatIps = activeCaseGraph.nodes.filter(n => n.type === 'ip' && (n.role === 'external_ip' || n.role === 'adversary_infrastructure'));



  return (

    <div className="space-y-6">

      

      {/* Header */}

      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[#282321]">

        <div>

          <div className="text-[11px] font-mono text-[#a8a29e] mb-1 flex items-center gap-1.5">

            <span>&gt;</span>

            <span className="text-[#d6d3d1]">Entity Topology</span>

          </div>

          <h1 className="text-xl font-bold tracking-tight text-[#fafaf9] flex items-center gap-2.5">

            <GitBranch className="w-5 h-5 text-[#f95721]" />

            <span>Attack Path & Entity Relationship Graph</span>

          </h1>

          <p className="text-xs text-[#a8a29e] mt-0.5">

            Case: <strong className="text-[#fafaf9]">{activeCase?.name}</strong> · Interactive topology depicting lateral movement, privilege escalation, and external C2

          </p>

        </div>



        {/* 2D vs 3D View Toggle & Metrics */}

        <div className="flex items-center gap-3 flex-wrap">

          <div className="inline-flex items-center p-1 bg-[#191716] border border-[#2c2724] rounded-lg text-xs font-mono">

            <button

              onClick={() => setViewMode('2d')}

              className={`px-3 py-1.5 rounded-md transition-all flex items-center gap-1.5 font-medium ${

                viewMode === '2d'

                  ? 'bg-[#292422] text-[#fafaf9] shadow-sm'

                  : 'text-[#a8a29e] hover:text-[#d6d3d1]'

              }`}

            >

              <Network className="w-3.5 h-3.5 text-[#f95721]" />

              <span>2D Topology</span>

            </button>

            <button

              onClick={() => setViewMode('3d')}

              className={`px-3 py-1.5 rounded-md transition-all flex items-center gap-1.5 font-medium ${

                viewMode === '3d'

                  ? 'bg-[#f95721] text-white shadow-[0_0_12px_rgba(249,87,33,0.4)]'

                  : 'text-[#a8a29e] hover:text-[#d6d3d1]'

              }`}

            >

              <Globe2 className="w-3.5 h-3.5" />

              <span>3D Cyber Sphere</span>

            </button>

          </div>



          <div className="flex items-center gap-3 text-xs font-mono bg-[#161413] border border-[#2b2523] px-3 py-1.5 rounded-lg">

            <span className="text-[#a8a29e]">

              Entities: <strong className="text-[#fafaf9]">{activeCaseGraph.nodes.length}</strong>

            </span>

            <span className="text-[#57534e]">·</span>

            <span className="text-[#f95721]">

              Compromised: <strong className="text-[#ff7847]">{compromisedHosts.length + compromisedUsers.length}</strong>

            </span>

          </div>

        </div>

      </div>



      {/* Main Viewport: 2D Directed Graph OR 3D Three.js Geodesic Globe */}

      {viewMode === '3d' ? (

        <div className="rounded-2xl bg-[#161413]/90 border border-[#2b2523] p-4 sm:p-6 md:p-8 backdrop-blur-xl flex flex-col items-center justify-center space-y-5 sm:space-y-6 shadow-2xl relative overflow-hidden min-h-[420px] sm:min-h-[520px] w-full">

          <div className="text-center space-y-1.5 max-w-lg z-10 px-2">

            <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[#2a140d] border border-[#ea580c]/30 text-[#f95721] text-[11px] font-mono font-medium">

              <Sparkles className="w-3 h-3" />

              <span>Three.js Spatial Graph</span>

            </div>

            <h3 className="text-base sm:text-lg font-bold text-[#fafaf9]">Global Forensic Sphere Projection</h3>

            <p className="text-xs text-[#a8a29e]">

              Rotating 3D cyber-sphere displaying compromised vertices ({compromisedHosts.map(h => h.label).join(', ')}) connected by real-time attack trajectories.

            </p>

          </div>



          <CyberThreatGlobe

            height={320}

            threatPointsCount={58}

            interactive={true}

            mode={globeMode}

            onModeChange={setGlobeMode}

            showControls={true}

            caption="Drag to orbit · Scroll to inspect threat vector angles"

            className="w-full max-w-2xl"

          />

        </div>

      ) : (

        /* Main Interactive 2D Graph Viewport */

        <GraphView graphData={activeCaseGraph} />

      )}



      {/* Compromised Infrastructure & Threat Indicators Grid */}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

        

        {/* Compromised Hosts */}

        <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-5 space-y-3 shadow-xl">

          <div className="flex items-center justify-between border-b border-[#2b2523] pb-2.5">

            <div className="flex items-center gap-2 text-xs font-semibold text-[#fafaf9]">

              <Server className="w-4 h-4 text-[#f95721]" />

              <span>Compromised Hosts</span>

            </div>

            <span className="text-[11px] font-mono text-[#f95721] font-semibold bg-[#2a140d] px-2 py-0.5 rounded border border-[#ea580c]/30">

              {compromisedHosts.length}

            </span>

          </div>



          <div className="space-y-1.5 text-xs">

            {compromisedHosts.length === 0 ? (

              <div className="text-[#78716c] py-2">No compromised hosts identified</div>

            ) : (

              compromisedHosts.map(h => (

                <div key={h.id} className="p-2.5 bg-[#100f0e] border border-[#282321] rounded-xl flex justify-between items-center font-mono">

                  <span className="text-[#fafaf9] font-medium">{h.label}</span>

                  <span className="text-[10px] text-[#f95721]">{h.event_count} events</span>

                </div>

              ))

            )}

          </div>

        </div>



        {/* Compromised User Accounts */}

        <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-5 space-y-3 shadow-xl">

          <div className="flex items-center justify-between border-b border-[#2b2523] pb-2.5">

            <div className="flex items-center gap-2 text-xs font-semibold text-[#fafaf9]">

              <UserCheck className="w-4 h-4 text-[#f59e0b]" />

              <span>Targeted Accounts</span>

            </div>

            <span className="text-[11px] font-mono text-[#f59e0b] font-semibold bg-[#2a200d] px-2 py-0.5 rounded border border-[#d97706]/30">

              {compromisedUsers.length}

            </span>

          </div>



          <div className="space-y-1.5 text-xs">

            {compromisedUsers.length === 0 ? (

              <div className="text-[#78716c] py-2">No compromised user accounts identified</div>

            ) : (

              compromisedUsers.map(u => (

                <div key={u.id} className="p-2.5 bg-[#100f0e] border border-[#282321] rounded-xl flex justify-between items-center font-mono">

                  <span className="text-[#fafaf9] font-medium">{u.label}</span>

                  <span className="text-[10px] text-[#f59e0b]">{u.event_count} events</span>

                </div>

              ))

            )}

          </div>

        </div>



        {/* Threat IPs & C2 */}

        <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-5 space-y-3 shadow-xl">

          <div className="flex items-center justify-between border-b border-[#2b2523] pb-2.5">

            <div className="flex items-center gap-2 text-xs font-semibold text-[#fafaf9]">

              <Globe className="w-4 h-4 text-[#f95721]" />

              <span>Adversary C2 & Ingress IPs</span>

            </div>

            <span className="text-[11px] font-mono text-[#f95721] font-semibold bg-[#2a140d] px-2 py-0.5 rounded border border-[#ea580c]/30">

              {threatIps.length}

            </span>

          </div>



          <div className="space-y-1.5 text-xs">

            {threatIps.length === 0 ? (

              <div className="text-[#78716c] py-2">No external adversary IPs mapped</div>

            ) : (

              threatIps.map(ip => (

                <div key={ip.id} className="p-2.5 bg-[#100f0e] border border-[#282321] rounded-xl flex justify-between items-center font-mono">

                  <span className="text-[#fafaf9] font-medium">{ip.label}</span>

                  <span className="text-[10px] text-[#f95721]">{ip.event_count} events</span>

                </div>

              ))

            )}

          </div>

        </div>



      </div>



    </div>

  );

};

