import React from 'react';

interface StatusBadgeProps {
  status: string;
  variant?: 'status' | 'severity' | 'role' | 'boolean';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, variant = 'status' }) => {
  const norm = String(status || '').toLowerCase().trim();

  let style = 'bg-stone-800 text-stone-300 border-stone-700';

  if (variant === 'severity') {
    switch (norm) {
      case 'critical':
        style = 'bg-red-950/80 text-red-300 border-red-700/60 shadow-[0_0_10px_rgba(239,68,68,0.2)]';
        break;
      case 'high':
        style = 'bg-orange-950/80 text-orange-300 border-orange-700/60';
        break;
      case 'medium':
        style = 'bg-amber-950/80 text-amber-300 border-amber-700/60';
        break;
      case 'low':
        style = 'bg-blue-950/80 text-blue-300 border-blue-700/60';
        break;
      default:
        style = 'bg-stone-900 text-stone-400 border-stone-800';
    }
  } else if (variant === 'role') {
    switch (norm) {
      case 'admin':
        style = 'bg-red-950/80 text-red-300 border-red-600/70 shadow-[0_0_8px_rgba(239,68,68,0.25)] font-bold';
        break;
      case 'investigator':
        style = 'bg-orange-950/80 text-orange-300 border-[#ea580c]/60 font-semibold';
        break;
      case 'auditor':
        style = 'bg-purple-950/80 text-purple-300 border-purple-600/60 font-semibold';
        break;
      default:
        style = 'bg-stone-800 text-stone-300 border-stone-700';
    }
  } else {
    // Default Status colors
    switch (norm) {
      case 'active':
      case 'open':
      case 'completed':
      case 'online':
      case 'true':
      case 'match':
        style = 'bg-emerald-950/70 text-emerald-300 border-emerald-600/60';
        break;
      case 'under_review':
      case 'in_review':
      case 'processing':
      case 'replied':
      case 'pending':
        style = 'bg-amber-950/70 text-amber-300 border-amber-600/60';
        break;
      case 'disabled':
      case 'failed':
      case 'offline':
      case 'degraded':
      case 'false':
      case 'mismatch':
        style = 'bg-red-950/70 text-red-300 border-red-700/60';
        break;
      case 'new':
        style = 'bg-[#ea580c]/20 text-[#f95721] border-[#f95721]/50 font-bold animate-pulse';
        break;
      case 'closed':
      case 'archived':
      case 'spam':
        style = 'bg-stone-900 text-stone-400 border-stone-800';
        break;
      default:
        style = 'bg-stone-800/80 text-stone-300 border-stone-700';
    }
  }

  const formatText = (text: string) => {
    return text.replace(/_/g, ' ').toUpperCase();
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono tracking-wider border uppercase transition-all select-none ${style}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current opacity-80" />
      <span>{formatText(status)}</span>
    </span>
  );
};
