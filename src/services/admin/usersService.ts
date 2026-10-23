/**
 * Users Service (Admin-Only)
 * Handles account lifecycle, RBAC assignments, session terminations, and security settings.
 *
 * NOTE: The `usersAdapter` abstracts data access. To connect a live FastAPI endpoint
 * later, replace only the adapter methods below without modifying page callers.
 */

import { AdminUser, AdminRole, UserStatus } from '../../admin/types';
import { SEED_USERS } from '../../mocks/admin/seedData';
import { delay, getStored, setStored } from './storageHelper';
import { auditService } from './auditService';

// ============================================================================
// DATA ACCESS ADAPTER (Mock Implementation -> Swappable to Real Backend API)
// ============================================================================
const usersAdapter = {
  async getAll(): Promise<AdminUser[]> {
    await delay(300, 500);
    return getStored<AdminUser[]>('users', SEED_USERS);
  },

  async saveAll(users: AdminUser[]): Promise<void> {
    await delay(200, 400);
    setStored('users', users);
  }
};

// ============================================================================
// SERVICE INTERFACE
// ============================================================================
export const usersService = {
  async getUsers(filters?: { role?: string; status?: string; search?: string }): Promise<AdminUser[]> {
    const list = await usersAdapter.getAll();
    return list.filter((user) => {
      if (filters?.role && filters.role !== 'all' && user.role !== filters.role) {
        return false;
      }
      if (filters?.status && filters.status !== 'all' && user.status !== filters.status) {
        return false;
      }
      if (filters?.search) {
        const q = filters.search.toLowerCase();
        return (
          user.name.toLowerCase().includes(q) ||
          user.email.toLowerCase().includes(q) ||
          user.department.toLowerCase().includes(q)
        );
      }
      return true;
    });
  },

  async getUserById(id: string): Promise<AdminUser | null> {
    const list = await usersAdapter.getAll();
    return list.find((u) => u.id === id) || null;
  },

  async createUser(data: {
    name: string;
    email: string;
    role: AdminRole;
    department: string;
    status?: UserStatus;
  }): Promise<AdminUser> {
    const list = await usersAdapter.getAll();
    const newUser: AdminUser = {
      id: `usr-${Date.now().toString().slice(-6)}`,
      name: data.name,
      email: data.email,
      role: data.role,
      department: data.department,
      status: data.status || 'active',
      last_login: 'Never',
      created_at: new Date().toISOString(),
      two_factor_enabled: false,
      failed_login_attempts: 0,
      sessions: []
    };

    list.unshift(newUser);
    await usersAdapter.saveAll(list);

    await auditService.log({
      action: 'USER_CREATE',
      target_type: 'USER',
      target_id: newUser.id,
      details: { email: newUser.email, role: newUser.role, department: newUser.department }
    });

    return newUser;
  },

  async updateUser(id: string, patch: Partial<AdminUser>): Promise<AdminUser> {
    const list = await usersAdapter.getAll();
    const index = list.findIndex((u) => u.id === id);
    if (index === -1) throw new Error(`User with ID ${id} not found.`);

    const updated = { ...list[index], ...patch };
    list[index] = updated;
    await usersAdapter.saveAll(list);

    await auditService.log({
      action: 'USER_UPDATE',
      target_type: 'USER',
      target_id: id,
      details: patch
    });

    return updated;
  },

  async deleteUser(id: string): Promise<void> {
    const list = await usersAdapter.getAll();
    const target = list.find((u) => u.id === id);
    const filtered = list.filter((u) => u.id !== id);
    await usersAdapter.saveAll(filtered);

    await auditService.log({
      action: 'USER_DELETE',
      target_type: 'USER',
      target_id: id,
      details: { deleted_name: target?.name, deleted_email: target?.email }
    });
  },

  async resetPassword(id: string): Promise<{ temporaryToken: string }> {
    await delay(350, 500);
    const token = `TMP-PWD-${Math.random().toString(36).substring(2, 9).toUpperCase()}`;

    await auditService.log({
      action: 'USER_PASSWORD_RESET',
      target_type: 'USER',
      target_id: id,
      details: { reset_initiated_by: 'admin', token_generated: true }
    });

    return { temporaryToken: token };
  },

  async forceLogoutSession(userId: string, sessionId: string): Promise<void> {
    const list = await usersAdapter.getAll();
    const user = list.find((u) => u.id === userId);
    if (user) {
      user.sessions = user.sessions.filter((s) => s.id !== sessionId);
      await usersAdapter.saveAll(list);

      await auditService.log({
        action: 'SESSION_TERMINATED',
        target_type: 'USER',
        target_id: userId,
        details: { terminated_session_id: sessionId }
      });
    }
  }
};
