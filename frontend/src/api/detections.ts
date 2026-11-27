import { apiClient } from './client';
import { DetectionResult, DetectionRule } from '../types';

export const detectionsApi = {
  listByCase: async (caseId: string) => {
    return apiClient.get<DetectionResult[]>(`/cases/${caseId}/detections`);
  },
  run: async (caseId: string) => {
    return apiClient.post<DetectionResult[]>(`/cases/${caseId}/run`);
  },
  toggleFalsePositive: async (detectionId: string, falsePositive: boolean, reason?: string) => {
    return apiClient.post(`/detections/${detectionId}/false-positive`, {
      false_positive: falsePositive,
      reason
    });
  },
  listRules: async () => {
    return apiClient.get<DetectionRule[]>('/detections/rules');
  },
  reloadRules: async () => {
    return apiClient.post('/detections/rules/reload');
  }
};
