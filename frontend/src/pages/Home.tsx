import React from 'react';
import { useApp } from '../store';
import {
  ChevronRight,
  FolderLock,
  ArrowRight
} from 'lucide-react';
import { ThreatHeroGlobe } from '../components/ThreatHeroGlobe';

export const Home: React.FC = () => {
  const {
    currentUser,
    setCurrentPage,
    cases,
    evidenceList,
    events,
    detections,
    setAuthNotice
  } = useApp();

  return (
    <div className="space-y-12 pb-16">
      {/* ========================================================================= */}
      {/* HERO HEADLINE & 1-LINE DESCRIPTION (With Kinetic Floating Text Motion)    */}
      {/* ========================================================================= */}
      <div className="pt-4 sm:pt-6 pb-2 text-center max-w-4xl mx-auto px-4 space-y-3 animate-kinetic-container">
        <h1 className="text-xl sm:text-2xl md:text-3xl lg:text-[32px] font-extrabold tracking-tight text-[#fafaf9] leading-snug">
          <span className="inline-block animate-kinetic-word" style={{ animationDelay: '0s' }}>
            Reconstruct
          </span>{' '}
          <span className="inline-block animate-kinetic-word" style={{ animationDelay: '0.15s' }}>
            Digital
          </span>{' '}
          <span className="inline-block animate-kinetic-word" style={{ animationDelay: '0.3s' }}>
            Crime
          </span>{' '}
          <span className="inline-block animate-kinetic-word" style={{ animationDelay: '0.45s' }}>
            Scenes
          </span>{' '}
          <span className="text-[#a8a29e] font-semibold inline-block animate-kinetic-word" style={{ animationDelay: '0.6s' }}>
            with
          </span>{' '}
          <span
            className="text-[#f95721] inline-block animate-kinetic-word animate-cyber-glow"
            style={{ animationDelay: '0.75s' }}
          >
            Cryptographic Precision
          </span>
        </h1>

        {/* 1-Sentence Description of what the website does below the headline */}
        <p className="text-sm sm:text-base text-[#a8a29e] font-sans max-w-2xl mx-auto leading-relaxed animate-subtle-pulse">
          An intelligent digital forensics platform that ingests multi-source evidentiary logs, correlates forensic artifacts, and reconstructs complete cyber incident timelines.
        </p>
      </div>

      {/* ========================================================================= */}
      {/* 3D THREAT MESH SPHERE (Interactive Geodesic 3D Design under Headline)      */}
      {/* ========================================================================= */}
      <ThreatHeroGlobe />

      {/* ========================================================================= */}
      {/* ACTIVE CASES DIRECTORY PREVIEW (Limited to two investigations)            */}
      {/* ========================================================================= */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-xl font-bold tracking-tight text-[#fafaf9]">
            Current Investigations
          </h2>
          <button
            type="button"
            onClick={() => {
              if (!currentUser) {
                setAuthNotice('Please sign in to inspect all active case investigations.');
                setCurrentPage('login');
              } else {
                setCurrentPage('cases');
              }
            }}
            className="text-xs font-semibold text-[#f95721] hover:text-[#fb923c] flex items-center gap-1 transition-colors cursor-pointer"
          >
            <span>View All Cases</span>
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {cases.slice(0, 2).map((c) => {
            const caseEvidence = evidenceList.filter((e) => e.case_id === c.id);
            const caseEvents = events.filter((e) => e.case_id === c.id);
            const caseDetections = detections.filter((d) => d.case_id === c.id);

            return (
              <div
                key={c.id}
                className="p-5 rounded-2xl bg-[#141211] border border-[#2e2825] hover:border-[#f95721]/60 transition-all space-y-4 shadow-lg"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[#27130b] text-[#ff8d60] border border-[#ea580c]/40 font-bold">
                        {c.status}
                      </span>
                      <span className="text-[11px] font-mono text-[#a8a29e]">{c.id}</span>
                    </div>
                    <h3 className="text-base font-bold text-[#fafaf9]">{c.name}</h3>
                  </div>
                  <FolderLock className="w-5 h-5 text-[#f95721] shrink-0" />
                </div>

                <p className="text-xs text-[#a8a29e] line-clamp-2 leading-relaxed">
                  {c.description}
                </p>

                <div className="grid grid-cols-3 gap-2 pt-2 border-t border-[#26201e] text-[11px] font-mono text-[#a8a29e]">
                  <div>
                    <span className="text-[#78716c] block text-[10px]">Evidence</span>
                    <strong className="text-[#fafaf9]">{caseEvidence.length} files</strong>
                  </div>
                  <div>
                    <span className="text-[#78716c] block text-[10px]">Events</span>
                    <strong className="text-[#fafaf9]">{caseEvents.length}</strong>
                  </div>
                  <div>
                    <span className="text-[#78716c] block text-[10px]">Threats</span>
                    <strong className="text-red-400">{caseDetections.length} alerts</strong>
                  </div>
                </div>

                <div className="pt-1 flex items-center justify-between">
                  <span className="text-[10px] font-mono text-[#78716c]">
                    Lead: {c.lead_investigator || 'DFIR Team'}
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      if (!currentUser) {
                        setAuthNotice(`Please sign in to inspect case "${c.name}".`);
                        setCurrentPage('login');
                      } else {
                        setCurrentPage('cases');
                      }
                    }}
                    className="px-3 py-1.5 rounded-lg bg-[#22130c] hover:bg-[#30160d] text-[#ff8d60] border border-[#ea580c]/40 text-xs font-semibold flex items-center gap-1 transition-colors cursor-pointer"
                  >
                    <span>Open Case</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
};
