import { SeverityLevel } from '../types';

export function getSeverityBadgeClass(severity: SeverityLevel | string): string {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'bg-red-500/10 text-red-400 border-red-500/30';
    case 'high':
      return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    case 'medium':
      return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
    case 'low':
    default:
      return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
  }
}

export function getSeverityDotClass(severity: SeverityLevel | string): string {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'bg-red-500';
    case 'high':
      return 'bg-amber-500';
    case 'medium':
      return 'bg-yellow-500';
    case 'low':
    default:
      return 'bg-slate-400';
  }
}
