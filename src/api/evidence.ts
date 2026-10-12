import { apiClient } from './client';
import { EvidenceFile, ParserType } from '../types';

export const evidenceApi = {
  listByCase: async (caseId: string) => {
    return apiClient.get<EvidenceFile[]>(`/cases/${caseId}/evidence`);
  },
  upload: async (caseId: string, formData: FormData) => {
    // Standard fetch for multipart file upload
    const token = apiClient.getToken();
    const headers = new Headers();
    if (token) headers.set('Authorization', `Bearer ${token}`);
    
    const res = await fetch(`/api/v1/cases/${caseId}/evidence/upload`, {
      method: 'POST',
      headers,
      body: formData
    });
    return res.json();
  },
  reparse: async (evidenceId: string, parserType: ParserType) => {
    return apiClient.post<EvidenceFile>(`/evidence/${evidenceId}/reparse`, { parser_type: parserType });
  },
  delete: async (evidenceId: string) => {
    return apiClient.delete(`/evidence/${evidenceId}`);
  }
};
