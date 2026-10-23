/**
 * Audit Service (Admin-Only, Read-Only Log with Append-Only Logging)
 * Implements immutable audit trail records for regulatory non-repudiation.
 *
 * NOTE: The `auditAdapter` abstracts persistence. To connect to an RFC-6962 transparency
 * log or PostgreSQL backend, update only this adapter.
 */

import { AdminAuditEntry } from '../../admin/types';
import { SEED_AUDIT_LOGS } from '../../mocks/admin/seedData';
import { delay, getStored, setStored } from './storageHelper';

// ============================================================================
// DATA ACCESS ADAPTER (Mock Implementation -> Swappable to Real Backend API)
// ============================================================================
const auditAdapter = {
  async getAll(): Promise<AdminAuditEntry[]> {
    await delay(300, 500);
    return getStored<AdminAuditEntry[]>('audit', SEED_AUDIT_LOGS);
  },

  async append(entry: AdminAuditEntry): Promise<void> {
    await delay(100, 250);
    const list = getStored<AdminAuditEntry[]>('audit', SEED_AUDIT_LOGS);
    list.unshift(entry);
    setStored('audit', list);
  }
};

// ============================================================================
// SERVICE INTERFACE
// ============================================================================
export interface AuditFilters {
  user?: string;
  action?: string;
  case_id?: string;
  date_from?: string;
  date_to?: string;
  search?: string;
  page?: number;
  limit?: number;
}

export const auditService = {
  async getAuditLogs(filters?: AuditFilters): Promise<{
    entries: AdminAuditEntry[];
    total: number;
    page: number;
    totalPages: number;
  }> {
    const all = await auditAdapter.getAll();

    const filtered = all.filter((item) => {
      if (filters?.user && filters.user !== 'all' && item.user_id !== filters.user && item.user_name !== filters.user) {
        return false;
      }
      if (filters?.action && filters.action !== 'all' && item.action !== filters.action) {
        return false;
      }
      if (filters?.case_id && filters.case_id !== 'all' && item.case_id !== filters.case_id) {
        return false;
      }
      if (filters?.date_from) {
        if (new Date(item.timestamp) < new Date(filters.date_from)) return false;
      }
      if (filters?.date_to) {
        if (new Date(item.timestamp) > new Date(filters.date_to)) return false;
      }
      if (filters?.search) {
        const q = filters.search.toLowerCase();
        const detailsStr = JSON.stringify(item.details || {}).toLowerCase();
        return (
          item.action.toLowerCase().includes(q) ||
          item.user_name.toLowerCase().includes(q) ||
          item.target_id.toLowerCase().includes(q) ||
          item.ip_address.toLowerCase().includes(q) ||
          detailsStr.includes(q)
        );
      }
      return true;
    });

    const page = filters?.page || 1;
    const limit = filters?.limit || 15;
    const startIndex = (page - 1) * limit;
    const paginated = filtered.slice(startIndex, startIndex + limit);

    return {
      entries: paginated,
      total: filtered.length,
      page,
      totalPages: Math.ceil(filtered.length / limit) || 1
    };
  },

  async log(params: {
    action: string;
    target_type: string;
    target_id: string;
    case_id?: string;
    details?: Record<string, any>;
    userOverride?: { id: string; name: string; role: string };
  }): Promise<void> {
    const newEntry: AdminAuditEntry = {
      id: `aud-${Date.now().toString().slice(-6)}-${Math.floor(Math.random() * 900 + 100)}`,
      timestamp: new Date().toISOString(),
      user_id: params.userOverride?.id || 'usr-admin',
      user_name: params.userOverride?.name || 'Sarem Worku',
      role: params.userOverride?.role || 'admin',
      action: params.action,
      case_id: params.case_id,
      target_type: params.target_type,
      target_id: params.target_id,
      details: params.details || {},
      ip_address: '192.168.1.104'
    };

    await auditAdapter.append(newEntry);
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
