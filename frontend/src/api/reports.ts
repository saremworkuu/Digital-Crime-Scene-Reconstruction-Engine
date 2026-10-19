import { apiClient } from './client';
import { ForensicReport } from '../types';

export const reportsApi = {
  generate: async (caseId: string) => {
    return apiClient.post<ForensicReport>(`/cases/${caseId}/reports/generate`);
  },
  exportPdf: async (caseId: string) => {
    return apiClient.get<Blob>(`/cases/${caseId}/reports/pdf`);
  },
  exportHtml: async (caseId: string) => {
    return apiClient.get<string>(`/cases/${caseId}/reports/html`);
  }
};
