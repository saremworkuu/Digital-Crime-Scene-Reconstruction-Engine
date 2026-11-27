/**
 * Rules Service (Admin-Only)
 * Direct integration with FastAPI endpoints (/api/v1/admin/rules).
 */

import { AdminSigmaRule, RuleSeverity } from '../../admin/types';
import { apiClient } from '../../api';
import {
  fetchWithAdminCache,
  invalidateAdminCache,
  peekAdminCache,
  unwrapApi,
  withQuery
} from './storageHelper';

export const rulesService = {
  getCachedRules(filters?: { severity?: string; enabled?: boolean; search?: string }): AdminSigmaRule[] | undefined {
    return peekAdminCache<AdminSigmaRule[]>(withQuery('/admin/rules', filters));
  },

  async getRules(
    filters?: { severity?: string; enabled?: boolean; search?: string },
    force = false
  ): Promise<AdminSigmaRule[]> {
    const url = withQuery('/admin/rules', filters);
    return fetchWithAdminCache(
      url,
      async () => {
        const res = await apiClient.get<AdminSigmaRule[]>(url);
        if (res.error) throw new Error(res.error);
        return Array.isArray(res.data) ? res.data : [];
      },
      { force }
    );
  },

  async toggleRule(id: string, enabled: boolean): Promise<AdminSigmaRule> {
    const res = await apiClient.patch<AdminSigmaRule>(`/admin/rules/${id}/toggle`, { enabled });
    const updated = unwrapApi(res, 'Failed to toggle rule.');
    invalidateAdminCache('/admin/rules', '/admin/audit');
    return updated;
  },

  async createRule(data: {
    name: string;
    severity: RuleSeverity;
    mitre_id: string;
    description: string;
    query: string;
  }): Promise<AdminSigmaRule> {
    const res = await apiClient.post<AdminSigmaRule>('/admin/rules', data);
    const created = unwrapApi(res, 'Failed to create rule.');
    invalidateAdminCache('/admin/rules', '/admin/audit');
    return created;
  },

  async updateRule(id: string, patch: Partial<AdminSigmaRule>): Promise<AdminSigmaRule> {
    const res = await apiClient.patch<AdminSigmaRule>(`/admin/rules/${id}`, patch);
    const updated = unwrapApi(res, 'Failed to update rule.');
    invalidateAdminCache('/admin/rules', '/admin/audit');
    return updated;
  },

  async deleteRule(id: string): Promise<void> {
    const res = await apiClient.delete(`/admin/rules/${id}`);
    if (res.error) throw new Error(res.error);
    invalidateAdminCache('/admin/rules', '/admin/audit');
  },

  async testRule(id: string): Promise<{
    ruleId: string;
    matchCount: number;
    sampleMatches: Array<{ timestamp: string; host: string; log_snippet: string }>;
  }> {
    const res = await apiClient.post<{
      ruleId: string;
      matchCount: number;
      sampleMatches: Array<{ timestamp: string; host: string; log_snippet: string }>;
    }>(`/admin/rules/${id}/test`);
    const result = unwrapApi(res, 'Failed to test rule.');
    invalidateAdminCache('/admin/rules');
    return result;
  },

  exportRulesToJson(rules: AdminSigmaRule[]): string {
    return JSON.stringify(rules, null, 2);
  },

  async importRulesFromJson(jsonContent: string): Promise<number> {
    const parsed = JSON.parse(jsonContent);
    if (!Array.isArray(parsed)) throw new Error('Import file must contain a JSON array of rules.');
    const res = await apiClient.post<{ importedCount: number }>('/admin/rules/import', parsed);
    const count = unwrapApi(res, 'Failed to import rules.').importedCount ?? 0;
    invalidateAdminCache('/admin/rules', '/admin/audit');
    return count;
  }
};
