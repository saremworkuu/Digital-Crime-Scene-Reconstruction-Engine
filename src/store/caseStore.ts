import { Case, EvidenceFile, ForensicEvent, DetectionAlert, AttackChain } from '../types';

export interface CaseState {
  currentCaseId: string;
  cases: Case[];
  evidenceFiles: EvidenceFile[];
  events: ForensicEvent[];
  detections: DetectionAlert[];
  attackChains: AttackChain[];
}

export const initialCaseState: Partial<CaseState> = {
  currentCaseId: 'case-cobalt-shadow',
  cases: [],
  evidenceFiles: [],
  events: [],
  detections: [],
  attackChains: []
};
