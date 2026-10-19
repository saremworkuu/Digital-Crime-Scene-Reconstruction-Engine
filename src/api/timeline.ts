import { apiClient } from './client';
import { NormalizedEvent } from '../types';

export const timelineApi = {
  getCaseTimeline: async (caseId: string, params?: { startTime?: string; endTime?: string; limit?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.startTime) searchParams.append('start_time', params.startTime);
    if (params?.endTime) searchParams.append('end_time', params.endTime);
    if (params?.limit) searchParams.append('limit', String(params.limit));
    return apiClient.get<NormalizedEvent[]>(`/cases/${caseId}/timeline?${searchParams.toString()}`);
  }
};
