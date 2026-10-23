import React from 'react';
import { useApp } from '../store';
import { Forensic3DCore } from '../components/Forensic3DCore';

export const About: React.FC = () => {
  const { theme } = useApp();
  const isLight = theme === 'light';

  const corePillars = [
    {
      id: '01',
      title: 'Cryptographic Chain of Custody & Adversary Attribution',
      desc: 'Automated cryptographic SHA-256 validation, tamper-proof digital custody ledgers, and threat actor attribution without compromise.',
      image: '/assets/about_art_1.png',
      tag: 'SHA-256 · NON-REPUDIATION',
      highlights: ['SHA-256 Verification', 'Immutable Custody Ledger', 'Adversary Attribution']
    },
    {
      id: '02',
      title: 'Autonomous Lateral Movement & Attack Progression',
      desc: 'Uncovers multi-stage attacker progression shedding persistence anchors, privilege escalation hops, and autonomous execution across internal networks.',
      image: '/assets/about_art_2.png',
      tag: 'AUTONOMOUS LATERAL MOVEMENT',
      highlights: ['Lateral Movement Graph', 'Privilege Escalation', 'Host Hop Telemetry']
    },
    {
      id: '03',
      title: 'Perimeter Containment & MITRE Telemetry',
      desc: 'Continuous perimeter barrier telemetry mapping adversary tactics against MITRE ATT&CK matrix sensors, firewall alerts, and Syslog tripwires.',
      image: '/assets/about_art_3.png',
      tag: 'MITRE ATT&CK · SENSOR WIRE',
      highlights: ['MITRE ATT&CK Matrix', 'Perimeter Telemetry', 'Sigma Rule Engine']
    },
    {
      id: '04',
      title: 'Host Anchoring & Volatile Memory Forensics',
      desc: 'Detects deeply anchored in-memory payloads, process hollowing, LSASS credential theft, and stealthy persistence mechanisms pinned to OS subsystems.',
      image: '/assets/about_art_4.png',
      tag: 'VOLATILE PAYLOAD ANCHORS',
      highlights: ['Process Injection', 'LSASS Defense', 'Volatile Memory Dumps']
    },
    {
      id: '05',
      title: 'Boundary Breach & Exfiltration Reconstruction',
      desc: 'Spatial 3D reconstruction of network boundary breaches, command-and-control beacon channels, and unauthorized data exfiltration pathways.',
      image: '/assets/about_art_5.png',
      tag: 'BREACH & EXFILTRATION TOPOLOGY',
      highlights: ['3D Crime Scene', 'C2 Beacon Tracking', 'Blast Radius Isolation']
    }
  ];

  // Exact 2-set duplicate for a seamless 50% circular loop
  const loopPillars = [...corePillars, ...corePillars];

  return (
    <div className="space-y-10 max-w-7xl mx-auto py-4 px-2 sm:px-4">
      {/* Hero Header */}
      <div>
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="space-y-3 max-w-3xl">
            <div className="flex items-center gap-3 flex-wrap">
              <h1
                className={`text-4xl sm:text-5xl lg:text-6xl font-black tracking-tight ${
                  isLight ? 'text-slate-900' : 'text-white'
                }`}
              >
                አሻራ
              </h1>
              <span className="text-xs sm:text-sm font-mono uppercase tracking-wider text-[#f95721] font-bold px-3 py-1.5 rounded-lg bg-[#f95721]/10 border border-[#f95721]/30 shadow-sm">
                Digital Crime Scene Reconstruction Engine
              </span>
            </div>

            <p
              className={`text-sm sm:text-base lg:text-lg leading-relaxed ${
                isLight ? 'text-slate-600' : 'text-[#a8a29e]'
              }`}
            >
              High-assurance cyber forensic platform reconstructing multi-stage intrusions from raw evidence into interactive 3D attack topologies and audit reports.
            </p>
          </div>

          <div className="shrink-0 flex items-center justify-center p-2 rounded-2xl bg-black/20 border border-white/5 backdrop-blur-sm">
            <Forensic3DCore size={105} interactive={true} />
          </div>
        </div>
      </div>

      {/* Core Forensic Capabilities: Continuous circular slider moving from Right to Left with Enlarged Boxes */}
      <div className="space-y-5 pt-4">
        <div className="flex flex-wrap items-end justify-between gap-3 border-b border-[#2b2523] pb-3">
          <div>
            <h2
              className={`text-lg sm:text-xl lg:text-2xl font-black tracking-tight ${
                isLight ? 'text-slate-900' : 'text-[#fafaf9]'
              }`}
            >
              Core Forensic Capabilities
            </h2>
            <p className={`text-xs sm:text-sm mt-0.5 ${isLight ? 'text-slate-500' : 'text-[#a8a29e]'}`}>
              Comprehensive investigation pipeline engineered for forensic validation and attribution
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono text-[#f95721] bg-[#f95721]/10 border border-[#f95721]/20 px-3 py-1 rounded-full">
            <span className="w-2 h-2 rounded-full bg-[#f95721] animate-pulse" />
            <span>CONTINUOUS SCAN · HOVER TO PAUSE</span>
          </div>
        </div>

        {/* Circular Sliding Track Viewport */}
        <div className="relative w-full overflow-hidden py-4">
          {/* Edge fading gradients for smooth entering and exiting */}
          <div
            className={`pointer-events-none absolute left-0 top-0 bottom-0 w-12 sm:w-20 z-10 ${
              isLight
                ? 'bg-gradient-to-r from-slate-50 to-transparent'
                : 'bg-gradient-to-r from-[#0e0d0d] to-transparent'
            }`}
          />
          <div
            className={`pointer-events-none absolute right-0 top-0 bottom-0 w-12 sm:w-20 z-10 ${
              isLight
                ? 'bg-gradient-to-l from-slate-50 to-transparent'
                : 'bg-gradient-to-l from-[#0e0d0d] to-transparent'
            }`}
          />

          {/* Continuous Infinite Sliding Container moving Right to Left with Substantially Increased Box Sizes */}
          <div className="animate-slide-circle-rtl flex flex-nowrap gap-6 sm:gap-7 w-max shrink-0 select-none">
            {loopPillars.map((pillar, idx) => (
              <div
                key={idx}
                className={`relative w-[360px] sm:w-[460px] md:w-[520px] lg:w-[560px] xl:w-[580px] h-[300px] sm:h-[330px] md:h-[350px] lg:h-[360px] shrink-0 rounded-2xl border overflow-hidden select-none group transition-all duration-300 cursor-pointer shadow-2xl flex flex-col justify-between ${
                  isLight
                    ? 'border-slate-300 bg-[#0d0c0c] hover:border-[#ea580c] hover:shadow-2xl'
                    : 'border-[#2e2825] bg-[#141211] hover:border-[#f95721] hover:shadow-[0_0_35px_rgba(249,87,33,0.4)]'
                }`}
              >
                {/* Background Image filling entire card with zoom on hover */}
                <img
                  src={pillar.image}
                  alt={pillar.title}
                  referrerPolicy="no-referrer"
                  className="absolute inset-0 w-full h-full object-cover object-center transition-transform duration-700 ease-out group-hover:scale-110"
                />

                {/* Dark Gradient Overlay for maximum contrast & crisp text legibility */}
                <div
                  className="absolute inset-0 bg-gradient-to-t from-black/95 via-black/85 to-black/50 transition-opacity duration-300 group-hover:from-black/95 group-hover:via-black/90"
                />

                {/* Top Bar with Spec Tag and Capability ID */}
                <div className="relative z-10 p-5 sm:p-6 flex items-center justify-between w-full">
                  <span className="text-[11px] sm:text-xs font-mono uppercase tracking-wider px-3 py-1.5 rounded-lg bg-black/85 backdrop-blur-md border border-white/20 text-[#ff936b] font-bold shadow-lg">
                    {pillar.tag}
                  </span>

                  <span className="text-[11px] sm:text-xs font-mono tracking-widest px-2.5 py-1 rounded-md bg-black/70 backdrop-blur-md border border-white/10 text-stone-300 flex items-center gap-1.5 font-semibold">
                    <span className="w-2 h-2 rounded-full bg-[#f95721] animate-pulse" />
                    CAP-{pillar.id}
                  </span>
                </div>

                {/* Bottom Content Layered Directly OVER the Image */}
                <div className="relative z-10 p-5 sm:p-6 space-y-3 bg-gradient-to-t from-black/85 via-black/50 to-transparent">
                  <h3 className="text-lg sm:text-xl lg:text-2xl font-black text-white tracking-tight leading-snug drop-shadow-[0_2px_4px_rgba(0,0,0,0.9)] group-hover:text-[#ff936b] transition-colors">
                    {pillar.title}
                  </h3>
                  <p className="text-xs sm:text-sm text-stone-200 font-medium leading-relaxed line-clamp-3 drop-shadow-[0_1px_3px_rgba(0,0,0,0.9)] font-sans">
                    {pillar.desc}
                  </p>

                  {/* Feature Highlights Pills */}
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {pillar.highlights.map((item, hIdx) => (
                      <span
                        key={hIdx}
                        className="text-[10px] sm:text-[11px] font-mono px-2.5 py-0.5 rounded-md bg-black/60 backdrop-blur-md border border-white/20 text-stone-200 group-hover:border-[#f95721]/50 transition-colors font-medium"
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
