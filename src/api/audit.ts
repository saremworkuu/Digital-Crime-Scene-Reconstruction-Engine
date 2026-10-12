import { apiClient } from './client';
import { AuditLogEntry } from '../types';

export const auditApi = {
  list: async (params?: { caseId?: string; limit?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.caseId) searchParams.append('case_id', params.caseId);
    if (params?.limit) searchParams.append('limit', String(params.limit));
    return apiClient.get<AuditLogEntry[]>(`/audit?${searchParams.toString()}`);
  },
  exportCsv: async (caseId?: string) => {
    const query = caseId ? `?case_id=${caseId}` : '';
    return apiClient.get<string>(`/audit/export${query}`);
  }
};
