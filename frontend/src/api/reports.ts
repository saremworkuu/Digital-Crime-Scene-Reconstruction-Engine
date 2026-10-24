import { apiClient } from './client';
import { ForensicReport } from '../types';

export const reportsApi = {
  generate: async (caseId: string) => {
    return apiClient.post<ForensicReport>(`/reports/${caseId}/reports/generate`);
  },
  exportPdf: async (caseId: string) => {
    return apiClient.getBlob(`/reports/${caseId}/reports/pdf`);
  },
  exportHtml: async (caseId: string) => {
    return apiClient.get<string>(`/reports/${caseId}/reports/html`);
  }
};
