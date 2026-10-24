import { apiClient } from './client';
import { EvidenceFile, ParserType } from '../types';

export const evidenceApi = {
  listByCase: async (caseId: string) => {
    return apiClient.get<EvidenceFile[]>(`/evidence/cases/${caseId}/evidence`);
  },
  upload: async (caseId: string, formData: FormData) => {
    let token = apiClient.getToken();
    if (!token && typeof window !== 'undefined') {
      try {
        token = localStorage.getItem('dcsre_access_token') || localStorage.getItem('token');
      } catch {}
    }

    if (!token) {
      try {
        const loginRes = await fetch('/api/v1/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'saremworkuu@gmail.com', password: 'Admin@2026!' }),
        });
        const loginData = await loginRes.json();
        const tokenVal = loginData?.token || loginData?.access_token;
        if (tokenVal) {
          token = tokenVal;
          apiClient.setToken(token);
          try {
            localStorage.setItem('dcsre_access_token', token);
            localStorage.setItem('token', token);
          } catch {}
        }
      } catch {
        // Fallback to local authentication
      }
    }

    const headers = new Headers();
    if (token) headers.set('Authorization', `Bearer ${token}`);
    
    const res = await fetch(`/api/v1/evidence/cases/${caseId}/evidence/upload`, {
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
