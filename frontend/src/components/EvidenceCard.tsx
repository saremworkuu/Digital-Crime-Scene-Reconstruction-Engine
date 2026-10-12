import React from 'react';
import { EvidenceFile } from '../types';
import { FileCode, CheckCircle2, Clock } from 'lucide-react';

interface EvidenceCardProps {
  evidence: EvidenceFile;
  onSelect?: (evidence: EvidenceFile) => void;
}

export const EvidenceCard: React.FC<EvidenceCardProps> = ({ evidence, onSelect }) => {
  const events = evidence.eventCount ?? evidence.event_count ?? 0;
  const size = evidence.sizeBytes ?? evidence.size_bytes ?? 0;
  const hash = evidence.sha256Hash || evidence.sha256_hash || '-';

  return (
    <div 
      onClick={() => onSelect?.(evidence)}
      className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-4 space-y-3 hover:border-[#3a322e] transition-colors cursor-pointer backdrop-blur-xl shadow-xl"
    >
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-[#24130d] border border-[#ea580c]/40 flex items-center justify-center text-[#f95721]">
            <FileCode className="w-4 h-4" />
          </div>
          <div>
            <h4 className="text-xs font-semibold text-[#fafaf9]">{evidence.filename}</h4>
            <span className="text-[10px] text-[#a8a29e]">Type: {evidence.type || evidence.file_type}</span>
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          {evidence.status === 'Parsed' ? (
            <span className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded font-mono bg-[#102a18] text-[#86efac] border border-[#22c55e]/30">
              <CheckCircle2 className="w-3 h-3" />
              <span>Parsed</span>
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded font-mono bg-[#2a140d] text-[#f95721] border border-[#ea580c]/30">
              <Clock className="w-3 h-3" />
              <span>{evidence.status}</span>
            </span>
          )}
        </div>
      </div>

      <div className="text-[11px] font-mono text-[#a8a29e] space-y-1">
        <div className="truncate">
          <span className="text-[#78716c]">SHA-256: </span>
          <span className="text-[#f95721]">{hash}</span>
        </div>
        <div className="flex justify-between text-[#78716c]">
          <span>Events: {events.toLocaleString()}</span>
          <span>Size: {(size / 1024).toFixed(1)} KB</span>
        </div>
      </div>
    </div>
  );
};
