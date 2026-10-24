import React, { useState, useEffect } from 'react';
import { useApp } from '../store';
import {
  FileText,
  Calendar,
  AlertTriangle
} from 'lucide-react';
import { ThreatHeroGlobe } from '../components/ThreatHeroGlobe';

interface MotionImageSequenceProps {
  images: string[];
  alt: string;
  className?: string;
}

const MotionImageSequence: React.FC<MotionImageSequenceProps> = ({ images, alt, className = '' }) => {
  const [currentIndex, setCurrentIndex] = useState(0);

  useEffect(() => {
    if (images.length <= 1) return;
    const timer = setInterval(() => {
      setCurrentIndex((prev) => (prev + 1) % images.length);
    }, 3500);
    return () => clearInterval(timer);
  }, [images.length]);

  return (
    <div className={`relative w-full max-w-[340px] sm:max-w-[360px] h-[460px] sm:h-[500px] lg:h-[520px] rounded-2xl overflow-hidden shrink-0 shadow-lg ${className}`}>
      {images.map((src, index) => {
        const isActive = index === currentIndex;
        return (
          <img
            key={src}
            src={src}
            alt={`${alt} ${index + 1}`}
            className={`absolute inset-0 w-full h-full object-cover rounded-2xl transition-all duration-1000 ease-in-out ${isActive
              ? 'opacity-100 scale-100 z-10'
              : 'opacity-0 scale-105 z-0 pointer-events-none'
              }`}
            loading="lazy"
          />
        );
      })}
    </div>
  );
};

export const Home: React.FC = () => {
  const {
    currentUser,
    setCurrentPage,
    cases,
    evidenceList,
    events,
    detections,
    setAuthNotice,
    theme
  } = useApp();

  const isLight = theme === 'light';

  // Retrieve Cobalt Shadow and DarkLock cases with fallbacks
  const cobaltCase = cases.find((c) => c.id === 'case-cobalt-shadow') || cases[0];
  const darklockCase = cases.find((c) => c.id === 'case-darklock') || cases[1] || cases[0];

  const cobaltEvidence = evidenceList.filter((e) => e.case_id === cobaltCase?.id);
  const cobaltEvents = events.filter((e) => e.case_id === cobaltCase?.id);
  const cobaltDetections = detections.filter((d) => d.case_id === cobaltCase?.id);

  const darklockEvidence = evidenceList.filter((e) => e.case_id === darklockCase?.id);
  const darklockEvents = events.filter((e) => e.case_id === darklockCase?.id);
  const darklockDetections = detections.filter((d) => d.case_id === darklockCase?.id);

  // Sequences of images that rotate with smooth seamless crossfade motion
  // Row 1 Image Box: starts with the subway hacker artwork
  const row1Images = [
    '/assets/mr_robot_subway.png',
    '/assets/fsociety_times_square.jpg',
    '/assets/mr_robot_crt.png'
  ];

  // Row 2 Image Box: displays the fsociety mask logo 1st on page load, followed by Anonymous artworks
  const row2Images = [
    '/assets/fsociety_mask_logo.png',
    '/assets/hacker_mask_1.png',
    '/assets/anonymous_parchment.png'
  ];

  return (
    <div className="space-y-12 pb-16">
      {/* ========================================================================= */}
      {/* HERO HEADLINE & 1-LINE DESCRIPTION (With Kinetic Floating Text Motion)    */}
      {/* ========================================================================= */}
      <div className="pt-4 sm:pt-6 pb-2 text-center max-w-4xl mx-auto px-4 space-y-3 animate-kinetic-container">
        <h1 className={`text-xl sm:text-2xl md:text-3xl lg:text-[32px] font-extrabold tracking-tight leading-snug ${isLight ? 'text-slate-900' : 'text-[#fafaf9]'
          }`}>
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
          <span className={`${isLight ? 'text-slate-500' : 'text-[#a8a29e]'} font-semibold inline-block animate-kinetic-word`} style={{ animationDelay: '0.6s' }}>
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
        <p className={`text-sm sm:text-base font-sans max-w-2xl mx-auto leading-relaxed animate-subtle-pulse ${isLight ? 'text-slate-600' : 'text-[#a8a29e]'
          }`}>
          An intelligent digital forensics platform that ingests multi-source evidentiary logs, correlates forensic artifacts, and reconstructs complete cyber incident timelines.
        </p>
      </div>

      {/* ========================================================================= */}
      {/* 3D THREAT MESH SPHERE (Interactive Geodesic 3D Design under Headline)      */}
      {/* ========================================================================= */}
      <ThreatHeroGlobe />

      {/* ========================================================================= */}
      {/* CURRENT INVESTIGATIONS (Visual 2x2 Staggered Case & Cyber Imagery Grid)     */}
      {/* ========================================================================= */}
      <section className="space-y-6 max-w-7xl mx-auto">
        {/* Section Header: Clean title without logo and without View All Cases */}
        <div className="flex items-center">
          <h2 className={`text-xl sm:text-2xl font-bold tracking-tight ${isLight ? 'text-slate-900' : 'text-[#fafaf9]'
            }`}>
            Current Investigations
          </h2>
        </div>

        {/* 2x2 Staggered Rows with visible height difference (Images taller, Case cards smaller, generous gap):
            Row 1: Cobalt Shadow Case (Left - smaller) + Hacker Command Center Image (Right - tall 520px, decreased width)
            Row 2: DarkLock Ransomware Image (Left - tall 520px, decreased width) + DarkLock Case (Right - smaller)
        */}
        <div className="space-y-10 sm:space-y-12">

          {/* ===================================================================== */}
          {/* ROW 1: Cobalt Shadow Case (Smaller) + Command Center Artwork (Taller)  */}
          {/* ===================================================================== */}
          <div className="flex flex-col lg:flex-row items-center justify-center gap-8 sm:gap-10 lg:gap-14">
            {/* Box 1: Operation Cobalt Shadow */}
            <div
              onClick={() => {
                if (!currentUser) {
                  setAuthNotice('Please sign in to inspect all active case investigations.');
                  setCurrentPage('login');
                } else {
                  setCurrentPage('cases');
                }
              }}
              className={`w-full max-w-lg lg:max-w-[480px] p-5 sm:p-6 rounded-2xl border transition-all duration-300 shadow-lg relative group cursor-pointer ${isLight
                ? 'bg-white border-slate-200 hover:border-[#ea580c]/50 hover:shadow-xl'
                : 'bg-[#141211] border-[#2e2825] hover:border-[#f95721]/50 hover:shadow-[0_0_25px_rgba(249,87,33,0.12)]'
                }`}
            >
              <div className="space-y-2.5">
                {/* Header row: badge + ID */}
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className="text-[10px] font-mono uppercase px-2.5 py-0.5 rounded-md bg-[#27130b] text-[#ff8d60] border border-[#ea580c]/40 font-bold tracking-wider">
                    {(cobaltCase?.status || 'IN PROGRESS').toUpperCase()}
                  </span>
                  <span className={`text-xs font-mono ${isLight ? 'text-slate-500' : 'text-[#a8a29e]'}`}>
                    {cobaltCase?.id || 'case-cobalt-shadow'}
                  </span>
                </div>

                {/* Case Title */}
                <h3 className={`text-base font-bold tracking-tight leading-snug ${isLight ? 'text-slate-900 group-hover:text-[#ea580c]' : 'text-[#fafaf9] group-hover:text-[#ff8d60]'
                  } transition-colors`}>
                  {cobaltCase?.name || 'Operation Cobalt Shadow: DMZ Web Exploit to Domain Controller Compromise'}
                </h3>

                {/* Case Description: Exactly as specified in 4th image */}
                <p className={`text-xs leading-relaxed ${isLight ? 'text-slate-600' : 'text-[#a8a29e]'}`}>
                  Complex multi-stage advanced threat investigation. Initial perimeter breach via web shell on Linux DMZ server web01, local privilege escalation to root via sudo caching, harvesting of domain backup operator credentials, lateral movement into core...
                </p>
              </div>

              <div className="space-y-3.5 pt-4">
                {/* 3-Column Metrics with icons */}
                <div className={`grid grid-cols-3 gap-2 pt-3 border-t ${isLight ? 'border-slate-200' : 'border-[#26201e]'
                  }`}>
                  <div>
                    <span className={`block text-[10px] uppercase tracking-wider font-medium mb-0.5 ${isLight ? 'text-slate-500' : 'text-[#78716c]'
                      }`}>
                      Evidence
                    </span>
                    <div className="flex items-center gap-1.5">
                      <FileText className={`w-3.5 h-3.5 ${isLight ? 'text-slate-600' : 'text-[#fafaf9]'}`} />
                      <strong className={`text-xs font-semibold ${isLight ? 'text-slate-900' : 'text-[#fafaf9]'}`}>
                        {cobaltEvidence.length || 4} files
                      </strong>
                    </div>
                  </div>

                  <div>
                    <span className={`block text-[10px] uppercase tracking-wider font-medium mb-0.5 ${isLight ? 'text-slate-500' : 'text-[#78716c]'
                      }`}>
                      Events
                    </span>
                    <div className="flex items-center gap-1.5">
                      <Calendar className={`w-3.5 h-3.5 ${isLight ? 'text-slate-600' : 'text-[#fafaf9]'}`} />
                      <strong className={`text-xs font-semibold ${isLight ? 'text-slate-900' : 'text-[#fafaf9]'}`}>
                        {cobaltEvents.length || 10}
                      </strong>
                    </div>
                  </div>

                  <div>
                    <span className={`block text-[10px] uppercase tracking-wider font-medium mb-0.5 ${isLight ? 'text-slate-500' : 'text-[#78716c]'
                      }`}>
                      Threats
                    </span>
                    <div className="flex items-center gap-1.5 text-red-500">
                      <AlertTriangle className="w-3.5 h-3.5 text-red-500" />
                      <strong className="text-xs font-semibold text-red-500">
                        {cobaltDetections.length || 4} alerts
                      </strong>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* First Image Box: Smooth seamless motion transition */}
            <MotionImageSequence
              images={row1Images}
              alt="Digital forensics operative"
            />
          </div>

          {/* ===================================================================== */}
          {/* ROW 2: Motion Image Sequence + DarkLock Case                         */}
          {/* ===================================================================== */}
          <div className="flex flex-col lg:flex-row items-center justify-center gap-8 sm:gap-10 lg:gap-14">
            {/* Second Image Box: Smooth seamless motion transition with user's uploaded images */}
            <MotionImageSequence
              images={row2Images}
              alt="fsociety adversary and mask investigation"
              className="order-2 lg:order-1"
            />

            {/* Box 2: DarkLock Ransomware Outbreak Case Card */}
            <div
              onClick={() => {
                if (!currentUser) {
                  setAuthNotice('Please sign in to inspect all active case investigations.');
                  setCurrentPage('login');
                } else {
                  setCurrentPage('cases');
                }
              }}
              className={`order-1 lg:order-2 w-full max-w-lg lg:max-w-[480px] p-5 sm:p-6 rounded-2xl border transition-all duration-300 shadow-lg relative group cursor-pointer ${isLight
                ? 'bg-white border-slate-200 hover:border-[#ea580c]/50 hover:shadow-xl'
                : 'bg-[#141211] border-[#2e2825] hover:border-[#f95721]/50 hover:shadow-[0_0_25px_rgba(249,87,33,0.12)]'
                }`}
            >
              <div className="space-y-2.5">
                {/* Header row: badge + ID */}
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className="text-[10px] font-mono uppercase px-2.5 py-0.5 rounded-md bg-[#27130b] text-[#ff8d60] border border-[#ea580c]/40 font-bold tracking-wider">
                    {(darklockCase?.status || 'OPEN').toUpperCase()}
                  </span>
                  <span className={`text-xs font-mono ${isLight ? 'text-slate-500' : 'text-[#a8a29e]'}`}>
                    {darklockCase?.id || 'case-darklock'}
                  </span>
                </div>

                {/* Case Title */}
                <h3 className={`text-base font-bold tracking-tight leading-snug ${isLight ? 'text-slate-900 group-hover:text-[#ea580c]' : 'text-[#fafaf9] group-hover:text-[#ff8d60]'
                  } transition-colors`}>
                  {darklockCase?.name || 'DarkLock Ransomware Outbreak: Finance Workstation to NAS'}
                </h3>

                {/* Case Description: Exactly as specified in 5th image */}
                <p className={`text-xs leading-relaxed ${isLight ? 'text-slate-600' : 'text-[#a8a29e]'}`}>
                  Rapid-onset cryptographic ransomware infection originating from malicious invoice attachment on workstation WS-FIN-04. Volume shadow copies purged via vssadmin and administrative SMB encryption observed targeting network storage FS01.
                </p>
              </div>

              <div className="space-y-3.5 pt-4">
                {/* 3-Column Metrics with icons */}
                <div className={`grid grid-cols-3 gap-2 pt-3 border-t ${isLight ? 'border-slate-200' : 'border-[#26201e]'
                  }`}>
                  <div>
                    <span className={`block text-[10px] uppercase tracking-wider font-medium mb-0.5 ${isLight ? 'text-slate-500' : 'text-[#78716c]'
                      }`}>
                      Evidence
                    </span>
                    <div className="flex items-center gap-1.5">
                      <FileText className={`w-3.5 h-3.5 ${isLight ? 'text-slate-600' : 'text-[#fafaf9]'}`} />
                      <strong className={`text-xs font-semibold ${isLight ? 'text-slate-900' : 'text-[#fafaf9]'}`}>
                        {darklockEvidence.length || 2} files
                      </strong>
                    </div>
                  </div>

                  <div>
                    <span className={`block text-[10px] uppercase tracking-wider font-medium mb-0.5 ${isLight ? 'text-slate-500' : 'text-[#78716c]'
                      }`}>
                      Events
                    </span>
                    <div className="flex items-center gap-1.5">
                      <Calendar className={`w-3.5 h-3.5 ${isLight ? 'text-slate-600' : 'text-[#fafaf9]'}`} />
                      <strong className={`text-xs font-semibold ${isLight ? 'text-slate-900' : 'text-[#fafaf9]'}`}>
                        {darklockEvents.length || 4}
                      </strong>
                    </div>
                  </div>

                  <div>
                    <span className={`block text-[10px] uppercase tracking-wider font-medium mb-0.5 ${isLight ? 'text-slate-500' : 'text-[#78716c]'
                      }`}>
                      Threats
                    </span>
                    <div className="flex items-center gap-1.5 text-red-500">
                      <AlertTriangle className="w-3.5 h-3.5 text-red-500" />
                      <strong className="text-xs font-semibold text-red-500">
                        {darklockDetections.length || 2} alerts
                      </strong>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

