import React from 'react';
import { ExternalLink } from 'lucide-react';

interface MitreBadgeProps {
  techniqueId: string;
  tactic?: string;
  showLink?: boolean;
}

export const MitreBadge: React.FC<MitreBadgeProps> = ({ techniqueId, tactic, showLink = true }) => {
  // Convert T1505.003 to T1505/003 for attack.mitre.org URL
  const urlSuffix = techniqueId.replace('.', '/');
  const mitreUrl = `https://attack.mitre.org/techniques/${urlSuffix}/`;

  return (
    <div className="inline-flex items-center gap-1.5 text-xs font-mono text-[#fb923c] hover:text-[#ff936b] transition-colors">
      <span className="font-semibold text-[#a8a29e]">ATT&CK</span>
      <span className="text-[#f95721] font-semibold">{techniqueId}</span>
      {tactic && (
        <>
          <span className="text-[#57534e] font-sans" aria-hidden="true">·</span>
          <span className="text-[#a8a29e] font-sans text-[11px] truncate max-w-[140px]">{tactic}</span>
        </>
      )}
      {showLink && (
        <a
          href={mitreUrl}
          target="_blank"
          rel="noopener noreferrer"
          title={`View ${techniqueId} on MITRE ATT&CK Framework`}
          className="text-[#78716c] hover:text-[#f95721] inline-flex items-center"
          onClick={e => e.stopPropagation()}
        >
          <ExternalLink className="w-3 h-3 ml-0.5" />
        </a>
      )}
    </div>
  );
};
