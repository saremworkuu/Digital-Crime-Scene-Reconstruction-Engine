import React from 'react';
import { DetectionAlert } from '../types';
import { ShieldAlert, CheckCircle, Clock } from 'lucide-react';
import { MitreBadge } from './MitreBadge';
import { SeverityTag } from './SeverityTag';

interface DetectionCardProps {
  detection: DetectionAlert;
  onToggleFalsePositive: (id: string, currentVal: boolean) => void;
}

export const DetectionCard: React.FC<DetectionCardProps> = ({ 
  detection, 
  onToggleFalsePositive 
}) => {
  return (
    <div className={`p-4 rounded-lg border space-y-3 transition-colors ${
      detection.falsePositive 
        ? 'bg-slate-900/30 border-slate-800/60 opacity-60' 
        : 'bg-slate-900/60 border-slate-800'
    }`}>
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2">
          <SeverityTag severity={detection.severity} />
          <MitreBadge techniqueId={detection.mitreTechnique} tactic={detection.mitreTactic} />
        </div>
        <button
          onClick={() => onToggleFalsePositive(detection.id, detection.falsePositive)}
          className={`text-[10px] font-semibold px-2 py-1 rounded transition-colors ${
            detection.falsePositive
              ? 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              : 'bg-slate-800/80 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
          }`}
        >
          {detection.falsePositive ? 'Marked as False Positive' : 'Mark False Positive'}
        </button>
      </div>

      <div>
        <h4 className="text-xs font-semibold text-slate-100">{detection.ruleName}</h4>
        <p className="text-xs text-slate-400 mt-1">{detection.description}</p>
      </div>

      <div className="flex items-center justify-between text-[11px] text-slate-500 pt-2 border-t border-slate-800/60">
        <span>Matched Events: {detection.matchedEventIds?.length || 0}</span>
        <span className="font-mono">{detection.timestamp ? detection.timestamp.substring(0, 19).replace('T', ' ') : '-'}</span>
      </div>
    </div>
  );
};
