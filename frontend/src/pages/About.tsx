import React from 'react';
import { useApp } from '../store';
import { Forensic3DCore } from '../components/Forensic3DCore';

export const About: React.FC = () => {
  const { theme } = useApp();
  const isLight = theme === 'light';

  const corePillars = [
    {
      title: 'Cryptographic Chain of Custody',
      desc: 'SHA-256 integrity validation upon ingestion with immutable custody ledgers.',
      image: '/assets/cyber_lock.jpg',
      tag: 'SHA-256'
    },
    {
      title: 'Multi-Format Ingestion',
      desc: 'Automated parsers for Linux Syslog, Windows EVTX, web logs, and PCAP summaries.',
      image: '/assets/cyber_circuits.jpg',
      tag: 'PCAP / EVTX'
    },
    {
      title: 'Attack Path Reconstruction',
      desc: 'Correlates multi-stage lateral movement, privilege escalation, and C2 beacons.',
      image: '/assets/cyber_servers.jpg',
      tag: 'LATERAL MOVEMENT'
    },
    {
      title: 'MITRE ATT&CK Correlation',
      desc: 'Continuous threat rule evaluation mapped directly to MITRE ATT&CK tactics.',
      image: '/assets/cyber_matrix.jpg',
      tag: 'MITRE MATRIX'
    },
    {
      title: 'Timeline Analysis',
      desc: 'Unified chronological event timeline with granular severity and attribution filters.',
      image: '/assets/cyber_global.jpg',
      tag: 'TELEMETRY'
    },
    {
      title: 'Forensic Reporting',
      desc: 'One-click executive and technical reports with cryptographic custody verification.',
      image: '/assets/cyber_code.jpg',
      tag: 'AUDIT REPORT'
    }
  ];

  // Exact 2-set duplicate for a seamless 50% circular loop
  const loopPillars = [...corePillars, ...corePillars];

  return (
    <div className="space-y-8 max-w-5xl mx-auto py-2">
      {/* Hero Header without enclosing card box */}
      <div>
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <h1
              className={`text-2xl sm:text-3xl lg:text-4xl font-extrabold tracking-tight ${
                isLight ? 'text-slate-900' : 'text-white'
              }`}
            >
              Digital Crime Scene Reconstruction Engine
            </h1>

            <p
              className={`text-sm sm:text-base leading-relaxed ${
                isLight ? 'text-slate-600' : 'text-[#a8a29e]'
              }`}
            >
              High-assurance cyber forensic platform reconstructing multi-stage intrusions from raw evidence into interactive 3D attack topologies and audit reports.
            </p>
          </div>

          <div className="shrink-0 flex items-center justify-center">
            <Forensic3DCore size={92} interactive={true} />
          </div>
        </div>
      </div>

      {/* Core Forensic Capabilities: Continuous circular slider moving from Right to Left */}
      <div className="space-y-3 pt-2">
        <div>
          <h2
            className={`text-sm sm:text-base font-bold tracking-tight ${
              isLight ? 'text-slate-900' : 'text-[#fafaf9]'
            }`}
          >
            Core Forensic Capabilities
          </h2>
        </div>

        {/* Circular Sliding Track Viewport */}
        <div className="relative w-full overflow-hidden py-3">
          {/* Edge fading gradients for smooth entering and exiting */}
          <div
            className={`pointer-events-none absolute left-0 top-0 bottom-0 w-16 z-10 ${
              isLight
                ? 'bg-gradient-to-r from-slate-50 to-transparent'
                : 'bg-gradient-to-r from-[#0e0d0d] to-transparent'
            }`}
          />
          <div
            className={`pointer-events-none absolute right-0 top-0 bottom-0 w-16 z-10 ${
              isLight
                ? 'bg-gradient-to-l from-slate-50 to-transparent'
                : 'bg-gradient-to-l from-[#0e0d0d] to-transparent'
            }`}
          />

          {/* Continuous Infinite Sliding Container moving Right to Left */}
          <div className="animate-slide-circle-rtl flex flex-nowrap gap-4 w-max shrink-0 select-none">
            {loopPillars.map((pillar, idx) => (
              <div
                key={idx}
                className={`relative w-[280px] sm:w-[320px] h-[130px] sm:h-[140px] shrink-0 rounded-2xl border overflow-hidden select-none group transition-all duration-300 cursor-pointer shadow-lg ${
                  isLight
                    ? 'border-slate-300 bg-white hover:border-[#ea580c] hover:shadow-xl'
                    : 'border-[#2e2825] bg-[#141211] hover:border-[#f95721] hover:shadow-[0_0_24px_rgba(249,87,33,0.3)]'
                }`}
              >
                {/* Background Image filling entire card */}
                <img
                  src={pillar.image}
                  alt={pillar.title}
                  referrerPolicy="no-referrer"
                  className="absolute inset-0 w-full h-full object-cover object-center transition-transform duration-700 ease-out group-hover:scale-108"
                />

                {/* Dark Gradient Overlay for maximum contrast & crisp text legibility */}
                <div
                  className="absolute inset-0 bg-gradient-to-t from-black/95 via-black/65 to-black/30 transition-opacity duration-300 group-hover:from-black/95 group-hover:via-black/70"
                />

                {/* Category Badge top-left */}
                <div className="absolute top-3 left-3 z-10">
                  <span className="text-[9.5px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-black/60 backdrop-blur-sm border border-white/20 text-[#ff936b] font-semibold">
                    {pillar.tag}
                  </span>
                </div>

                {/* Text Layered Directly OVER the Image */}
                <div className="relative z-10 h-full p-3.5 sm:p-4 flex flex-col justify-end text-left">
                  <h3 className="text-xs sm:text-sm font-extrabold text-white tracking-tight leading-snug drop-shadow-sm group-hover:text-[#ff936b] transition-colors">
                    {pillar.title}
                  </h3>
                  <p className="text-[10.5px] sm:text-[11px] text-[#e7e5e4]/90 leading-snug line-clamp-2 mt-1 drop-shadow-sm font-sans">
                    {pillar.desc}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
