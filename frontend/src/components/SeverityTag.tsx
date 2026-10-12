import React from 'react';
import { EventSeverity } from '../types';

interface SeverityTagProps {
  severity: EventSeverity;
  showDot?: boolean;
}

export const SeverityTag: React.FC<SeverityTagProps> = ({ severity, showDot = true }) => {
  const styles: Record<EventSeverity, { label: string; textClass: string; dotClass: string }> = {
    critical: {
      label: 'Critical',
      textClass: 'text-[#f95721] font-semibold',
      dotClass: 'bg-[#f95721] shadow-[0_0_8px_#f95721]'
    },
    high: {
      label: 'High',
      textClass: 'text-[#fb923c] font-medium',
      dotClass: 'bg-[#ea580c]'
    },
    medium: {
      label: 'Medium',
      textClass: 'text-[#f59e0b] font-medium',
      dotClass: 'bg-[#f59e0b]'
    },
    low: {
      label: 'Low',
      textClass: 'text-[#a8a29e] font-normal',
      dotClass: 'bg-[#78716c]'
    }
  };

  const current = styles[severity] || styles.low;

  return (
    <span className={`inline-flex items-center gap-1.5 text-xs ${current.textClass} tracking-wide`}>
      {showDot && <span className={`w-1.5 h-1.5 rounded-full ${current.dotClass} shrink-0`} aria-hidden="true" />}
      <span className="uppercase text-[11px] font-mono">{current.label}</span>
    </span>
  );
};
