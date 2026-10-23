import React from 'react';
import { useApp } from '../store';
import { Forensic3DCore } from '../components/Forensic3DCore';

export const About: React.FC = () => {
  const { theme } = useApp();
  const isLight = theme === 'light';

  const corePillars = [
    {
      id: '01',
      title: 'Cryptographic Chain of Custody & Attribution',
      desc: 'Automated cryptographic SHA-256 validation, tamper-proof digital custody ledgers, and threat actor attribution.',
      image: '/assets/about_art_1.png',
      tag: 'SHA-256 · NON-REPUDIATION',
      highlights: ['SHA-256 Verification', 'Immutable Custody Ledger', 'Adversary Attribution']
    },
    {
      id: '02',
      title: 'Autonomous Lateral Movement & Progression',
      desc: 'Uncovers multi-stage attacker progression shedding persistence anchors, privilege escalation, and internal hops.',
      image: '/assets/about_art_2.png',
      tag: 'AUTONOMOUS LATERAL MOVEMENT',
      highlights: ['Lateral Movement Graph', 'Privilege Escalation', 'Host Hop Telemetry']
    },
    {
      id: '03',
      title: 'Perimeter Containment & MITRE Telemetry',
      desc: 'Continuous perimeter barrier telemetry mapping adversary tactics against MITRE ATT&CK matrix sensors and tripwires.',
      image: '/assets/about_art_3.png',
      tag: 'MITRE ATT&CK · SENSOR WIRE',
      highlights: ['MITRE ATT&CK Matrix', 'Perimeter Telemetry', 'Sigma Rule Engine']
    },
    {
      id: '04',
      title: 'Host Anchoring & Volatile Memory Forensics',
      desc: 'Detects deeply anchored in-memory payloads, process hollowing, LSASS credential theft, and persistent OS hooks.',
      image: '/assets/about_art_4.png',
      tag: 'VOLATILE PAYLOAD ANCHORS',
      highlights: ['Process Injection', 'LSASS Defense', 'Volatile Memory Dumps']
    },
    {
      id: '05',
      title: 'Boundary Breach & Exfiltration Reconstruction',
      desc: 'Spatial 3D reconstruction of network boundary breaches, command-and-control beaconing, and unauthorized exfiltration.',
      image: '/assets/about_art_5.png',
      tag: 'BREACH & EXFILTRATION TOPOLOGY',
      highlights: ['3D Crime Scene', 'C2 Beacon Tracking', 'Blast Radius Isolation']
    }
  ];

  // Exact 2-set duplicate for a seamless 50% circular loop
  const loopPillars = [...corePillars, ...corePillars];

  return (
    <div className="space-y-8 max-w-6xl mx-auto py-4 px-4 sm:px-6">
      {/* Hero Header */}
      <div>
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="space-y-2.5 max-w-2xl">
            <div className="flex items-center gap-3 flex-wrap">
              <h1
                className={`text-3xl sm:text-4xl lg:text-5xl font-extrabold tracking-tight ${
                  isLight ? 'text-slate-900' : 'text-white'
                }`}
              >
                አሻራ
              </h1>
              <span className="text-xs sm:text-sm font-mono uppercase tracking-wider text-[#f95721] font-bold px-2.5 py-1 rounded-md bg-[#f95721]/10 border border-[#f95721]/30 shadow-sm">
                Digital Crime Scene Reconstruction Engine
              </span>
            </div>

            <p
              className={`text-sm sm:text-base leading-relaxed ${
                isLight ? 'text-slate-600' : 'text-[#a8a29e]'
              }`}
            >
              High-assurance cyber forensic platform reconstructing multi-stage intrusions from raw evidence into interactive 3D attack topologies and audit reports.
            </p>
          </div>

          <div className="shrink-0 flex items-center justify-center p-2 rounded-2xl bg-black/20 border border-white/5 backdrop-blur-sm">
            <Forensic3DCore size={88} interactive={true} />
          </div>
        </div>
      </div>

      {/* Core Forensic Capabilities: Proportional Medium-Sized Cards in Continuous Sliding Track */}
      <div className="space-y-4 pt-2">
        <div className="flex flex-wrap items-end justify-between gap-3 border-b border-[#2b2523] pb-2.5">
          <div>
            <h2
              className={`text-base sm:text-lg lg:text-xl font-bold tracking-tight ${
                isLight ? 'text-slate-900' : 'text-[#fafaf9]'
              }`}
            >
              Core Forensic Capabilities
            </h2>
            <p className={`text-xs mt-0.5 ${isLight ? 'text-slate-500' : 'text-[#a8a29e]'}`}>
              Comprehensive investigation pipeline engineered for forensic validation and attribution
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono text-[#f95721] bg-[#f95721]/10 border border-[#f95721]/20 px-2.5 py-1 rounded-full">
            <span className="w-2 h-2 rounded-full bg-[#f95721] animate-pulse" />
            <span>CONTINUOUS SCAN · HOVER TO PAUSE</span>
          </div>
        </div>

        {/* Circular Sliding Track Viewport */}
        <div className="relative w-full overflow-hidden py-3">
          {/* Edge fading gradients for smooth entering and exiting */}
          <div
            className={`pointer-events-none absolute left-0 top-0 bottom-0 w-12 sm:w-16 z-10 ${
              isLight
                ? 'bg-gradient-to-r from-slate-50 to-transparent'
                : 'bg-gradient-to-r from-[#0e0d0d] to-transparent'
            }`}
          />
          <div
            className={`pointer-events-none absolute right-0 top-0 bottom-0 w-12 sm:w-16 z-10 ${
              isLight
                ? 'bg-gradient-to-l from-slate-50 to-transparent'
                : 'bg-gradient-to-l from-[#0e0d0d] to-transparent'
            }`}
          />

          {/* Continuous Infinite Sliding Container: Proportional balanced dimensions */}
          <div className="animate-slide-circle-rtl flex flex-nowrap gap-5 sm:gap-6 w-max shrink-0 select-none">
            {loopPillars.map((pillar, idx) => (
              <div
                key={idx}
                className={`relative w-[290px] sm:w-[330px] md:w-[370px] lg:w-[400px] h-[195px] sm:h-[215px] md:h-[225px] lg:h-[235px] shrink-0 rounded-2xl border overflow-hidden select-none group transition-all duration-300 cursor-pointer shadow-xl flex flex-col justify-between ${
                  isLight
                    ? 'border-slate-300 bg-[#0d0c0c] hover:border-[#ea580c] hover:shadow-2xl'
                    : 'border-[#2e2825] bg-[#141211] hover:border-[#f95721] hover:shadow-[0_0_28px_rgba(249,87,33,0.35)]'
                }`}
              >
                {/* Background Image filling card with subtle zoom on hover */}
                <img
                  src={pillar.image}
                  alt={pillar.title}
                  referrerPolicy="no-referrer"
                  className="absolute inset-0 w-full h-full object-cover object-center transition-transform duration-700 ease-out group-hover:scale-108"
                />

                {/* Dark Gradient Overlay for maximum contrast & crisp text legibility */}
                <div
                  className="absolute inset-0 bg-gradient-to-t from-black/95 via-black/80 to-black/40 transition-opacity duration-300 group-hover:from-black/95 group-hover:via-black/85"
                />

                {/* Top Bar with Spec Tag and Capability ID */}
                <div className="relative z-10 p-3.5 sm:p-4 flex items-center justify-between w-full">
                  <span className="text-[10px] sm:text-[11px] font-mono uppercase tracking-wider px-2.5 py-1 rounded-md bg-black/85 backdrop-blur-md border border-white/20 text-[#ff936b] font-bold shadow-md">
                    {pillar.tag}
                  </span>

                  <span className="text-[10px] sm:text-[11px] font-mono tracking-widest px-2 py-0.5 rounded bg-black/70 backdrop-blur-md border border-white/10 text-stone-300 flex items-center gap-1.5 font-semibold">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#f95721] animate-pulse" />
                    CAP-{pillar.id}
                  </span>
                </div>

                {/* Bottom Content Layered Directly OVER the Image */}
                <div className="relative z-10 p-3.5 sm:p-4 space-y-1.5 bg-gradient-to-t from-black/90 via-black/60 to-transparent">
                  <h3 className="text-sm sm:text-base font-extrabold text-white tracking-tight leading-snug drop-shadow-md group-hover:text-[#ff936b] transition-colors line-clamp-1">
                    {pillar.title}
                  </h3>
                  <p className="text-[11px] sm:text-xs text-stone-200 font-medium leading-relaxed line-clamp-2 drop-shadow font-sans">
                    {pillar.desc}
                  </p>

                  {/* Feature Highlights Pills */}
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {pillar.highlights.map((item, hIdx) => (
                      <span
                        key={hIdx}
                        className="text-[9px] sm:text-[10px] font-mono px-2 py-0.5 rounded bg-black/60 backdrop-blur-md border border-white/15 text-stone-200 group-hover:border-[#f95721]/50 transition-colors font-medium"
                      >
                        {item}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
