/**
 * Users Service (Admin-Only)
 * Direct integration with FastAPI endpoints (/api/v1/admin/users).
 */

import { AdminUser, AdminRole, UserStatus } from '../../admin/types';
import { apiClient } from '../../api';
import {
  fetchWithAdminCache,
  invalidateAdminCache,
  peekAdminCache,
  unwrapApi,
  withQuery
} from './storageHelper';

export const usersService = {
  getCachedUsers(filters?: { role?: string; status?: string; search?: string }): AdminUser[] | undefined {
    return peekAdminCache<AdminUser[]>(withQuery('/admin/users', filters));
  },

  async getUsers(
    filters?: { role?: string; status?: string; search?: string },
    force = false
  ): Promise<AdminUser[]> {
    const url = withQuery('/admin/users', filters);
    return fetchWithAdminCache(
      url,
      async () => {
        const res = await apiClient.get<AdminUser[]>(url);
        if (res.error) throw new Error(res.error);
        return Array.isArray(res.data) ? res.data : [];
      },
      { force }
    );
  },

  async getUserById(id: string): Promise<AdminUser | undefined> {
    const res = await apiClient.get<AdminUser>(`/admin/users/${id}`);
    return res.error ? undefined : res.data;
  },

  async createUser(data: {
    name: string;
    email: string;
    role: AdminRole;
    department: string;
    status?: UserStatus;
  }): Promise<AdminUser> {
    const res = await apiClient.post<AdminUser>('/admin/users', {
      name: data.name,
      email: data.email,
      role: data.role,
      department: data.department,
      status: data.status || 'active'
    });
    const created = unwrapApi(res, 'Failed to create user.');
    invalidateAdminCache('/admin/users', '/admin/system/summary', '/admin/audit');
    return created;
  },

  async updateUser(id: string, patch: Partial<AdminUser>): Promise<AdminUser> {
    const res = await apiClient.patch<AdminUser>(`/admin/users/${id}`, patch);
    const updated = unwrapApi(res, 'Failed to update user.');
    invalidateAdminCache('/admin/users', '/admin/audit');
    return updated;
  },

  async deleteUser(id: string): Promise<void> {
    const res = await apiClient.delete(`/admin/users/${id}`);
    if (res.error) throw new Error(res.error);
    invalidateAdminCache('/admin/users', '/admin/system/summary', '/admin/audit');
  },

  async resetPassword(id: string): Promise<{ temporaryToken: string }> {
    const res = await apiClient.post<{ temporaryToken: string }>(`/admin/users/${id}/reset-password`);
    const result = unwrapApi(res, 'Failed to reset user password.');
    invalidateAdminCache('/admin/audit');
    return result;
  },

  async forceLogoutSession(userId: string, sessionId: string): Promise<void> {
    const res = await apiClient.post(`/admin/users/${userId}/sessions/${sessionId}/terminate`);
    if (res.error) throw new Error(res.error);
    invalidateAdminCache('/admin/users', '/admin/audit');
  }
};
