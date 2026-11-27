/**
 * Cases Service (Admin-Only)
 * Direct integration with FastAPI endpoints (/api/v1/admin/cases).
 */

import { AdminCase, CaseStatus } from '../../admin/types';
import { apiClient } from '../../api';
import {
  fetchWithAdminCache,
  invalidateAdminCache,
  peekAdminCache,
  unwrapApi,
  withQuery
} from './storageHelper';

export const casesService = {
  getCachedCases(filters?: { status?: string; archived?: boolean; search?: string }): AdminCase[] | undefined {
    return peekAdminCache<AdminCase[]>(withQuery('/admin/cases', filters));
  },

  async getCases(
    filters?: { status?: string; archived?: boolean; search?: string },
    force = false
  ): Promise<AdminCase[]> {
    const url = withQuery('/admin/cases', filters);
    return fetchWithAdminCache(
      url,
      async () => {
        const res = await apiClient.get<AdminCase[]>(url);
        if (res.error) throw new Error(res.error);
        return Array.isArray(res.data) ? res.data : [];
      },
      { force }
    );
  },

  async getCaseById(id: string): Promise<AdminCase | undefined> {
    const res = await apiClient.get<AdminCase>(`/admin/cases/${id}`);
    return res.error ? undefined : res.data;
  },

  async updateStatus(id: string, status: CaseStatus): Promise<AdminCase> {
    const res = await apiClient.patch<AdminCase>(`/admin/cases/${id}/status`, { status });
    const updated = unwrapApi(res, 'Failed to update case status.');
    invalidateAdminCache('/admin/cases', '/admin/system/summary', '/admin/audit');
    return updated;
  },

  async assignInvestigators(id: string, investigators: string[]): Promise<AdminCase> {
    const res = await apiClient.patch<AdminCase>(`/admin/cases/${id}/assign`, { investigators });
    const updated = unwrapApi(res, 'Failed to assign investigators.');
    invalidateAdminCache('/admin/cases', '/admin/audit');
    return updated;
  },

  async toggleLegalHold(id: string, legalHold: boolean, reason?: string): Promise<AdminCase> {
    const res = await apiClient.patch<AdminCase>(`/admin/cases/${id}/legal-hold`, {
      legal_hold: legalHold,
      reason
    });
    const updated = unwrapApi(res, 'Failed to update legal hold.');
    invalidateAdminCache('/admin/cases', '/admin/audit');
    return updated;
  },

  async toggleArchive(id: string, isArchived: boolean): Promise<AdminCase> {
    const res = await apiClient.patch<AdminCase>(`/admin/cases/${id}/archive`, {
      is_archived: isArchived
    });
    const updated = unwrapApi(res, 'Failed to update archive status.');
    invalidateAdminCache('/admin/cases', '/admin/audit');
    return updated;
  }
};
