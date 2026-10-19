import { apiClient } from './client';
import { NormalizedEvent } from '../types';

export const eventsApi = {
  listByCase: async (caseId: string, params?: { host?: string; user?: string; severity?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.host) searchParams.append('host', params.host);
    if (params?.user) searchParams.append('user', params.user);
    if (params?.severity) searchParams.append('severity', params.severity);
    return apiClient.get<NormalizedEvent[]>(`/cases/${caseId}/events?${searchParams.toString()}`);
  },
  getById: async (eventId: string) => {
    return apiClient.get<NormalizedEvent>(`/events/${eventId}`);
  }
};
