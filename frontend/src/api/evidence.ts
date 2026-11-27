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
      const rawDetail = response.error;
      const detailText =
        typeof rawDetail === 'string'
          ? rawDetail
          : rawDetail !== undefined && rawDetail !== null
            ? JSON.stringify(rawDetail)
            : 'The backend did not confirm the evidence upload.';
      const statusPrefix = typeof response.status === 'number' && response.status > 0 ? `HTTP ${response.status}: ` : '';
      const err = new Error(`${statusPrefix}${detailText}`) as Error & {
        status?: number;
        detail?: unknown;
      };
      err.status = response.status;
      err.detail = rawDetail;
      throw err;
    }
    return response.data;
  },

  getZipStatus: async (caseId: string, evidenceId: string) => {
    return apiClient.get<any>(`/evidence/cases/${caseId}/evidence/${evidenceId}/status`);
  },

  reparse: async (evidenceId: string, parserType: ParserType) => {
    return apiClient.post<EvidenceFile>(`/evidence/${evidenceId}/reparse`, { parser_type: parserType });
  },
  delete: async (evidenceId: string) => {
    return apiClient.delete(`/evidence/${evidenceId}`);
  }
};
