import React from 'react';
import { Case } from '../types';
import { FolderKanban, ShieldAlert, ArrowRight } from 'lucide-react';

interface CaseCardProps {
  caseItem: Case;
  isSelected?: boolean;
  onSelect: (caseItem: Case) => void;
}

export const CaseCard: React.FC<CaseCardProps> = ({ caseItem, isSelected, onSelect }) => {
  const events = caseItem.eventCount ?? caseItem.event_count ?? 0;
  const critical = caseItem.criticalDetections ?? caseItem.critical_detections ?? caseItem.critical_detection_count ?? 0;
  const files = caseItem.evidenceCount ?? caseItem.evidence_count ?? 0;

  return (
    <div 
      onClick={() => onSelect(caseItem)}
      className={`p-4 rounded-2xl border transition-all cursor-pointer space-y-3 backdrop-blur-xl ${
        isSelected 
          ? 'bg-[#24130d]/80 border-[#ea580c] shadow-[0_0_20px_rgba(249,87,33,0.15)] ring-1 ring-[#f95721]/30' 
          : 'bg-[#161413]/90 border-[#2b2523] hover:border-[#3a322e]'
      }`}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-[#24130d] border border-[#ea580c]/40 flex items-center justify-center text-[#f95721]">
            <FolderKanban className="w-4 h-4" />
          </div>
          <div>
            <h4 className="text-xs font-semibold text-[#fafaf9]">{caseItem.name}</h4>
            <span className="text-[10px] text-[#a8a29e]">Lead: {caseItem.leadInvestigator || caseItem.lead_investigator || 'Lead Examiner'}</span>
          </div>
        </div>
        <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-medium ${
          caseItem.status === 'In Progress' ? 'bg-[#2a140d] text-[#f95721] border border-[#ea580c]/30' :
          caseItem.status === 'Open' ? 'bg-[#102a18] text-[#86efac] border border-[#22c55e]/30' :
          'bg-[#1f1b19] text-[#a8a29e] border border-[#38312d]'
        }`}>
          {caseItem.status}
        </span>
      </div>

      <p className="text-xs text-[#a8a29e] line-clamp-2">
        {caseItem.description}
      </p>

      <div className="flex items-center justify-between text-[11px] font-mono text-[#a8a29e] pt-2 border-t border-[#282321]">
        <div className="flex items-center gap-3">
          <span>{files} files</span>
          <span>{events.toLocaleString()} events</span>
          {critical > 0 && (
            <span className="text-[#fca5a5] flex items-center gap-1">
              <ShieldAlert className="w-3 h-3 text-[#f95721]" />
              <span>{critical} critical</span>
            </span>
          )}
        </div>
        <ArrowRight className="w-3.5 h-3.5 text-[#78716c]" />
      </div>
    </div>
  );
};
