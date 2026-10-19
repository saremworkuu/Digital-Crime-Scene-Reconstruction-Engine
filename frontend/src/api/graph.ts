import { apiClient } from './client';
import { AttackGraphData } from '../types';

export const graphApi = {
  getCaseGraph: async (caseId: string, attackPathOnly = false) => {
    return apiClient.get<AttackGraphData>(`/cases/${caseId}/graph?attack_path_only=${attackPathOnly}`);
  }
};
