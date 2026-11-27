/**
 * Evidence Service (Admin-Only)
 * Direct integration with FastAPI endpoints (/api/v1/admin/evidence).
 */

import { AdminEvidence } from '../../admin/types';
import { apiClient } from '../../api';
import {
  fetchWithAdminCache,
  invalidateAdminCache,
  peekAdminCache,
  unwrapApi,
  withQuery
} from './storageHelper';

export const evidenceService = {
  getCachedEvidence(filters?: {
    case_id?: string;
    type?: string;
    status?: string;
    search?: string;
  }): AdminEvidence[] | undefined {
    return peekAdminCache<AdminEvidence[]>(withQuery('/admin/evidence', filters));
  },

  async getEvidence(
    filters?: {
      case_id?: string;
      type?: string;
      status?: string;
      search?: string;
    },
    force = false
  ): Promise<AdminEvidence[]> {
    const url = withQuery('/admin/evidence', filters);
    return fetchWithAdminCache(
      url,
      async () => {
        const res = await apiClient.get<AdminEvidence[]>(url);
        if (res.error) throw new Error(res.error);
        return Array.isArray(res.data) ? res.data : [];
      },
      { force }
    );
  },

  async verifyIntegrity(id: string): Promise<{
    verified: boolean;
    computed_sha256: string;
    expected_sha256: string;
    match: boolean;
  }> {
    const res = await apiClient.post<{
      verified: boolean;
      computed_sha256: string;
      expected_sha256: string;
      match: boolean;
    }>(`/admin/evidence/${id}/verify`);
    const result = unwrapApi(res, 'Failed to verify evidence integrity.');
    invalidateAdminCache('/admin/evidence', '/admin/audit');
    return result;
  },

  async deleteEvidence(id: string): Promise<void> {
    const res = await apiClient.delete(`/admin/evidence/${id}`);
    if (res.error) throw new Error(res.error);
    invalidateAdminCache(
      '/admin/evidence',
      '/admin/cases',
      '/admin/system/summary',
      '/admin/system/health',
      '/admin/audit'
    );
  }
};
