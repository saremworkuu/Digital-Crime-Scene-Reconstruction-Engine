import { Case, EvidenceFile, NormalizedEvent, DetectionResult, AttackGraphData } from '../types';

export interface ScenarioBundle {
  caseData: Case;
  evidenceFiles: EvidenceFile[];
  events: NormalizedEvent[];
  detections: DetectionResult[];
  graphData: AttackGraphData;
}

/**
 * Initial scenarios list.
 * Mock data cleared - ready for real investigation files.
 */
export const INITIAL_SCENARIOS: ScenarioBundle[] = [];
