import React from 'react';
import { useApp } from '../store';
import { ThreatMap } from '../components/ThreatMap';
import { formatCaseNameWithId } from '../utils/caseDisplay';
import { isEvidenceContainer } from '../utils/evidenceContainer';

export const Dashboard: React.FC = () => {
  const { activeCase, activeCaseDetections, activeCaseEvents, activeCaseEvidence, setCurrentPage } = useApp();
  const artifactEvidenceCount = activeCaseEvidence.filter(item => !isEvidenceContainer(item)).length;
  const metrics = [
    { label: 'Findings', value: activeCaseDetections.filter(item => !item.false_positive).length },
    { label: 'Normalized events', value: activeCaseEvents.length },
    { label: 'Evidence files', value: artifactEvidenceCount },
  ];

  return (
    <div className="space-y-6">
      <div className="text-sm text-[#a8a29e]">Selected case: <strong className="text-[#fafaf9]">{activeCase ? formatCaseNameWithId(activeCase.name, activeCase.id) : 'No case selected'}</strong></div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 sm:gap-5">
        {metrics.map(metric => (
          <div key={metric.label} className="rounded-2xl bg-[#161413]/90 border border-[#2b2523] p-5 shadow-xl">
            <div className="text-xs text-[#a8a29e]">{metric.label}</div>
            <div className="mt-2 text-3xl font-bold font-mono text-[#fafaf9]">{metric.value}</div>
          </div>
        ))}
      </div>
      <ThreatMap onOpenReport={() => setCurrentPage('reports')} />
    </div>
  );
};
