/**
 * System Service (Admin-Only)
 * Direct integration with FastAPI endpoints (/api/v1/admin/system).
 */

import { AdminDashboardSummary, AdminQueueJob, AdminSettings, AdminSystemHealth } from '../../admin/types';
import { apiClient } from '../../api';
import {
  fetchWithAdminCache,
  invalidateAdminCache,
  peekAdminCache,
  unwrapApi
} from './storageHelper';

export const systemService = {
  getCachedDashboardSummary(): AdminDashboardSummary | undefined {
    return peekAdminCache<AdminDashboardSummary>('/admin/system/summary');
  },

  async getDashboardSummary(force = false): Promise<AdminDashboardSummary> {
    return fetchWithAdminCache(
      '/admin/system/summary',
      async () => {
        const res = await apiClient.get<AdminDashboardSummary>('/admin/system/summary');
        return unwrapApi(res, 'Failed to load dashboard summary.');
      },
      { ttlMs: 20000, force }
    );
  },

  getCachedSystemHealth(): AdminSystemHealth | undefined {
    return peekAdminCache<AdminSystemHealth>('/admin/system/health');
  },

  async getSystemHealth(force = false): Promise<AdminSystemHealth> {
    return fetchWithAdminCache(
      '/admin/system/health',
      async () => {
        const res = await apiClient.get<AdminSystemHealth>('/admin/system/health');
        return unwrapApi(res, 'Failed to load system health.');
      },
      { ttlMs: 20000, force }
    );
  },

  async retryQueueJob(jobId: string): Promise<AdminQueueJob> {
    const res = await apiClient.post<AdminQueueJob>(`/admin/system/queue/${jobId}/retry`);
    const job = unwrapApi(res, 'Failed to retry queue job.');
    invalidateAdminCache('/admin/system', '/admin/evidence', '/admin/audit');
    return job;
  },

  getCachedSettings(): AdminSettings | undefined {
    return peekAdminCache<AdminSettings>('/admin/system/settings');
  },

  async getSettings(force = false): Promise<AdminSettings> {
    return fetchWithAdminCache(
      '/admin/system/settings',
      async () => {
        const res = await apiClient.get<AdminSettings>('/admin/system/settings');
        return unwrapApi(res, 'Failed to load system settings.');
      },
      { ttlMs: 60000, force }
    );
  },

  async updateSettings(patch: Partial<AdminSettings>): Promise<AdminSettings> {
    const res = await apiClient.patch<AdminSettings>('/admin/system/settings', patch);
    const updated = unwrapApi(res, 'Failed to update system settings.');
    invalidateAdminCache('/admin/system/settings', '/admin/audit');
    return updated;
  }
};
