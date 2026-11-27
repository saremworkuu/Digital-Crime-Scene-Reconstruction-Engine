/**
 * Audit Log Service (Admin & Auditor)
 * Direct integration with FastAPI endpoints (/api/v1/admin/audit).
 */

import { AdminAuditEntry } from '../../admin/types';
import { apiClient } from '../../api';
import {
  fetchWithAdminCache,
  invalidateAdminCache,
  peekAdminCache,
  withQuery
} from './storageHelper';

type AuditPageResult = {
  entries: AdminAuditEntry[];
  total: number;
  page: number;
  totalPages: number;
};

export const auditService = {
  getCachedAuditLogs(filters?: {
    user?: string;
    action?: string;
    case_id?: string;
    date_from?: string;
    date_to?: string;
    search?: string;
    page?: number;
    limit?: number;
  }): AuditPageResult | undefined {
    return peekAdminCache<AuditPageResult>(withQuery('/admin/audit', filters));
  },

  async getAuditLogs(
    filters?: {
      user?: string;
      action?: string;
      case_id?: string;
      date_from?: string;
      date_to?: string;
      search?: string;
      page?: number;
      limit?: number;
    },
    force = false
  ): Promise<AuditPageResult> {
    const url = withQuery('/admin/audit', filters);
    return fetchWithAdminCache(
      url,
      async () => {
        const res = await apiClient.get<AuditPageResult>(url);
        if (res.error) throw new Error(res.error);
        return {
          entries: Array.isArray(res.data?.entries) ? res.data.entries : [],
          total: res.data?.total ?? 0,
          page: res.data?.page ?? (filters?.page || 1),
          totalPages: res.data?.totalPages ?? 1
        };
      },
      { ttlMs: 15000, force }
    );
  },

  async log(params: {
    action: string;
    target_type: string;
    target_id: string;
    case_id?: string;
    details?: Record<string, any>;
  }): Promise<void> {
    const res = await apiClient.post('/admin/audit', {
      action: params.action,
      target_type: params.target_type,
      target_id: params.target_id,
      case_id: params.case_id,
      details: params.details || {}
    });
    if (res.error) throw new Error(res.error);
    invalidateAdminCache('/admin/audit');
  },

  exportToCsv(entries: AdminAuditEntry[]): string {
    const headers = [
      'Audit_ID',
      'Timestamp_ISO',
      'User_ID',
      'User_Name',
      'Role',
      'Action',
      'Case_ID',
      'Target_Type',
      'Target_ID',
      'IP_Address',
      'Details'
    ];

    const rows = entries.map((e) => [
      `"${e.id}"`,
      `"${e.timestamp}"`,
      `"${e.user_id}"`,
      `"${e.user_name}"`,
      `"${e.role}"`,
      `"${e.action}"`,
      `"${e.case_id || 'N/A'}"`,
      `"${e.target_type}"`,
      `"${e.target_id}"`,
      `"${e.ip_address}"`,
      `"${JSON.stringify(e.details || {}).replace(/"/g, '""')}"`
    ]);

    return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
  }
};
