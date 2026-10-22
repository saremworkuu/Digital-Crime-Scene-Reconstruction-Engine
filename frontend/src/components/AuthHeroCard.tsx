import React, { useState } from 'react';
import { Shield, Sparkles, Terminal } from 'lucide-react';

interface AuthHeroCardProps {
  imageSrc: string;
  imageAlt: string;
  className?: string;
}

export const AuthHeroCard: React.FC<AuthHeroCardProps> = ({
  imageSrc,
  imageAlt,
  className = ''
}) => {
  const [currentSrc, setCurrentSrc] = useState(imageSrc);
  const [imgError, setImgError] = useState(false);

  return (
    <div
      className={`relative w-full h-[400px] sm:h-[460px] lg:h-[500px] rounded-2xl overflow-hidden bg-[#0d0c0c] border border-[#2b2523] flex items-center justify-center shadow-2xl group ${className}`}
    >
      {!imgError ? (
        <img
          src={currentSrc}
          alt={imageAlt}
          onError={() => {
            if (currentSrc !== '/assets/contact_art.png') {
              setCurrentSrc('/assets/contact_art.png');
            } else {
              setImgError(true);
            }
          }}
          referrerPolicy="no-referrer"
          className="w-full h-full object-cover object-center transition-transform duration-700 group-hover:scale-105"
        />
      ) : (
        <div className="w-full h-full p-8 flex flex-col justify-between relative bg-gradient-to-br from-[#1c120c] via-[#100f0e] to-[#0a0908]">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_30%,rgba(249,87,33,0.15),transparent_60%)] pointer-events-none" />
          <div className="flex items-center justify-between z-10">
            <div className="w-10 h-10 rounded-xl bg-[#29140c] border border-[#f95721]/40 flex items-center justify-center text-[#f95721] shadow-lg">
              <Shield className="w-5 h-5" />
            </div>
            <span className="font-mono text-[10px] uppercase tracking-widest text-[#f95721] bg-[#29140c]/80 border border-[#f95721]/30 px-2.5 py-1 rounded-full">
              DCSRE CORE
            </span>
          </div>

          <div className="space-y-3 z-10">
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#221f1d] border border-[#382f2c] text-[11px] font-mono text-[#ff936b]">
              <Sparkles className="w-3.5 h-3.5 text-[#f95721]" />
              <span>Digital Crime Scene Reconstruction</span>
            </div>
            <h3 className="text-xl sm:text-2xl font-black text-white tracking-tight leading-snug">
              High-Assurance Cyber Forensic & Incident Telemetry
            </h3>
            <p className="text-xs text-[#a8a29e] leading-relaxed">
              Cryptographic chain of custody, automated timeline reconstruction, and interactive 3D threat mapping for enterprise forensic defense.
            </p>
          </div>

          <div className="pt-4 border-t border-[#25201e] flex items-center justify-between text-[11px] font-mono text-[#78716c] z-10">
            <span className="flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-[#f95721]" />
              SECURE DISPATCH GATEWAY
            </span>
            <span className="text-emerald-400">ONLINE</span>
          </div>
        </div>
      )}
    </div>
  );
};
