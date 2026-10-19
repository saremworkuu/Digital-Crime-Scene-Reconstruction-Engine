import { apiClient } from './client';
import { Case, CaseStatus } from '../types';

export const casesApi = {
  list: async (status?: CaseStatus) => {
    const query = status ? `?status=${status}` : '';
    return apiClient.get<Case[]>(`/cases${query}`);
  },
  getById: async (id: string) => {
    return apiClient.get<Case>(`/cases/${id}`);
  },
  create: async (data: { name: string; description: string; tags?: string[] }) => {
    return apiClient.post<Case>('/cases', data);
  },
  update: async (id: string, data: Partial<Case>) => {
    return apiClient.put<Case>(`/cases/${id}`, data);
  },
  delete: async (id: string) => {
    return apiClient.delete(`/cases/${id}`);
  },
  assignUsers: async (id: string, userIds: string[]) => {
    return apiClient.post(`/cases/${id}/assign`, { user_ids: userIds });
  }
};
