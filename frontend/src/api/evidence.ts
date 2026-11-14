import { apiClient } from './client';
import { EvidenceFile, ParserType } from '../types';

export const evidenceApi = {
  listByCase: async (caseId: string) => {
    return apiClient.get<EvidenceFile[]>(`/evidence/cases/${caseId}/evidence`);
  },
  upload: async (caseId: string, formData: FormData) => {
    if (!apiClient.getToken()) {
      throw new Error('Your secure session has expired. Sign in again before uploading evidence.');
    }

    const response = await apiClient.postFormData<any>(`/evidence/cases/${caseId}/evidence/upload`, formData);
    if (response.error || !response.data) {
      throw new Error(response.error || 'The backend did not confirm the evidence upload.');
    }
    return response.data;
  },

  reparse: async (evidenceId: string, parserType: ParserType) => {
    return apiClient.post<EvidenceFile>(`/evidence/${evidenceId}/reparse`, { parser_type: parserType });
  },
  delete: async (evidenceId: string) => {
    return apiClient.delete(`/evidence/${evidenceId}`);
  }
};
