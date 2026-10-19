import React from 'react';
import { useApp } from '../store';
import {
  Clock,
  GitBranch,
  ShieldAlert,
  FileText,
  Lock,
  Cpu,
  Layers,
  Scale
} from 'lucide-react';
import { Forensic3DCore } from '../components/Forensic3DCore';

export const About: React.FC = () => {
  const { theme } = useApp();
  const isLight = theme === 'light';

  const corePillars = [
    {
      icon: Lock,
      title: 'Cryptographic Chain of Custody',
      desc: 'SHA-256 integrity validation upon ingestion with immutable custody ledgers.'
    },
    {
      icon: Cpu,
      title: 'Multi-Format Ingestion',
      desc: 'Automated parsers for Linux Syslog, Windows EVTX, web logs, and PCAP summaries.'
    },
    {
      icon: GitBranch,
      title: 'Attack Path Reconstruction',
      desc: 'Correlates multi-stage lateral movement, privilege escalation, and C2 beacons.'
    },
    {
      icon: ShieldAlert,
      title: 'MITRE ATT&CK Correlation',
      desc: 'Continuous threat rule evaluation mapped directly to MITRE ATT&CK tactics.'
    },
    {
      icon: Clock,
      title: 'Timeline Analysis',
      desc: 'Unified chronological event timeline with granular severity and attribution filters.'
    },
    {
      icon: FileText,
      title: 'Forensic Reporting',
      desc: 'One-click executive and technical reports with cryptographic custody verification.'
    }
  ];

  const standards = [
    { name: 'NIST SP 800-86', detail: 'Forensic Techniques in Incident Response' },
    { name: 'MITRE ATT&CK v14', detail: 'Enterprise Threat Taxonomy' },
    { name: 'SHA-256 HMAC', detail: 'Cryptographic Integrity' },
    { name: 'ISO/IEC 27037', detail: 'Evidence Identification & Preservation' }
  ];

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Hero Banner */}
      <div className={`p-6 sm:p-8 rounded-3xl border ${
        isLight
          ? 'bg-white/90 border-[#e4e4e7] shadow-xl'
          : 'bg-[#161413]/90 border-[#2b2523] shadow-2xl'
      } backdrop-blur-xl relative overflow-hidden`}>
        {/* Ambient Glow */}
        <div
          className="pointer-events-none absolute -right-20 -top-20 w-80 h-80 rounded-full opacity-20"
          style={{
            background: 'radial-gradient(circle, #f95721 0%, transparent 70%)'
          }}
        />

        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 relative z-10">
          <div className="space-y-3 max-w-2xl">
            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight">
              Digital Crime Scene Reconstruction Engine
            </h1>

            <p className={`text-xs sm:text-sm leading-relaxed ${isLight ? 'text-[#52525b]' : 'text-[#a8a29e]'}`}>
              High-assurance cyber forensic platform reconstructing multi-stage intrusions from raw evidence into interactive 3D attack topologies and audit reports.
            </p>
          </div>

          <div className="shrink-0 flex items-center justify-center">
            <Forensic3DCore size={84} interactive={true} />
          </div>
        </div>
      </div>

      {/* Core Architectural Capabilities */}
      <div className="space-y-4">
        <div>
          <h2 className="text-base font-bold tracking-tight flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#f95721]" />
            <span>Core Forensic Capabilities</span>
          </h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {corePillars.map((pillar, idx) => {
            const Icon = pillar.icon;
            return (
              <div
                key={idx}
                className={`p-5 rounded-2xl border transition-all space-y-2.5 ${
                  isLight
                    ? 'bg-white/80 border-[#e4e4e7] hover:border-[#ea580c]/50 shadow-sm'
                    : 'bg-[#161413]/90 border-[#2b2523] hover:border-[#f95721]/50 shadow-lg'
                }`}
              >
                <div className="w-8 h-8 rounded-lg bg-[#24130d] border border-[#ea580c]/40 flex items-center justify-center text-[#f95721]">
                  <Icon className="w-4 h-4" />
                </div>
                <h3 className="text-xs font-bold text-[#fafaf9]">{pillar.title}</h3>
                <p className={`text-[11px] leading-relaxed ${isLight ? 'text-[#52525b]' : 'text-[#a8a29e]'}`}>
                  {pillar.desc}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Compliance & Standards */}
      <div className={`p-6 rounded-2xl border ${
        isLight
          ? 'bg-white/80 border-[#e4e4e7]'
          : 'bg-[#161413]/90 border-[#2b2523]'
      } space-y-4`}>
        <div className="flex items-center gap-2">
          <Scale className="w-4 h-4 text-[#f95721]" />
          <h2 className="text-sm font-bold tracking-tight">Compliance & Forensic Standards</h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {standards.map((std, i) => (
            <div
              key={i}
              className={`p-3 rounded-xl border flex items-start gap-3 ${
                isLight ? 'bg-[#f4f4f5]/60 border-[#e4e4e7]' : 'bg-[#100f0e] border-[#26211f]'
              }`}
            >
              <div className="w-2 h-2 rounded-full bg-[#f95721] mt-1 shrink-0" />
              <div>
                <div className="font-mono text-xs font-bold text-[#fafaf9]">{std.name}</div>
                <div className={`text-[11px] mt-0.5 ${isLight ? 'text-[#71717a]' : 'text-[#78716c]'}`}>
                  {std.detail}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
