import React, { useState, useEffect } from 'react';
import {
  UserPlus,
  Key,
  Shield,
  Trash2,
  Lock,
  UserCheck,
  UserX,
  Smartphone,
  LogOut,
  Laptop,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { DataTable, Column } from '../components/DataTable';
import { FilterBar } from '../components/FilterBar';
import { StatusBadge } from '../components/StatusBadge';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { usersService, systemService } from '../../services/admin';
import { AdminUser, AdminRole, UserStatus, AdminSettings } from '../types';
import { toast } from '../../components/Toast';
import { useApp } from '../../store';

export const UsersPage: React.FC = () => {
  const { theme } = useApp();
  const isLight = theme === 'light';

  const [users, setUsers] = useState<AdminUser[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Filters
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

  // Selected User for Details / Sessions / Edit Modal
  const [selectedUser, setSelectedUser] = useState<AdminUser | null>(null);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [createModalOpen, setCreateModalOpen] = useState(false);

  // Form Fields
  const [formName, setFormName] = useState('');
  const [formEmail, setFormEmail] = useState('');
  const [formRole, setFormRole] = useState<AdminRole>('investigator');
  const [formDepartment, setFormDepartment] = useState('');
  const [formStatus, setFormStatus] = useState<UserStatus>('active');

  // Security Settings
  const [settings, setSettings] = useState<AdminSettings | null>(null);
  const [savingSettings, setSavingSettings] = useState(false);

  // Dialog State
  const [confirmDialog, setConfirmDialog] = useState<{
    isOpen: boolean;
    title: string;
    message: string;
    action: () => Promise<void>;
  }>({
    isOpen: false,
    title: '',
    message: '',
    action: async () => {}
  });

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [userList, sysSettings] = await Promise.all([
        usersService.getUsers({ search, role: roleFilter, status: statusFilter }),
        systemService.getSettings()
      ]);
      setUsers(userList);
      setSettings(sysSettings);
      if (selectedUser) {
        const refreshed = userList.find((u) => u.id === selectedUser.id);
        if (refreshed) setSelectedUser(refreshed);
      }
    } catch (err: any) {
      toast.error('Failed to load users: ' + (err.message || 'Error'));
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [search, roleFilter, statusFilter]);

  const handleOpenCreate = () => {
    setFormName('');
    setFormEmail('');
    setFormRole('investigator');
    setFormDepartment('Digital Forensic Incident Response (DFIR)');
    setFormStatus('active');
    setCreateModalOpen(true);
  };

  const handleOpenEdit = (user: AdminUser) => {
    setSelectedUser(user);
    setFormName(user.name);
    setFormEmail(user.email);
    setFormRole(user.role);
    setFormDepartment(user.department);
    setFormStatus(user.status);
    setEditModalOpen(true);
  };

  const handleSaveCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await usersService.createUser({
        name: formName,
        email: formEmail,
        role: formRole,
        department: formDepartment,
        status: formStatus
      });
      toast.success(`Account for ${formName} successfully created.`);
      setCreateModalOpen(false);
      loadData();
    } catch (err: any) {
      toast.error(err.message || 'Failed to create user');
    }
  };

  const handleSaveEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedUser) return;
    try {
      await usersService.updateUser(selectedUser.id, {
        name: formName,
        email: formEmail,
        role: formRole,
        department: formDepartment,
        status: formStatus
      });
      toast.success(`Updated ${formName} account.`);
      setEditModalOpen(false);
      loadData();
    } catch (err: any) {
      toast.error(err.message || 'Failed to update user');
    }
  };

  const handleResetPassword = async (user: AdminUser) => {
    try {
      const res = await usersService.resetPassword(user.id);
      toast.success(`Temporary token issued for ${user.email}: ${res.temporaryToken}`);
    } catch (err: any) {
      toast.error('Password reset failed: ' + err.message);
    }
  };

  const handleToggleStatus = async (user: AdminUser) => {
    const nextStatus: UserStatus = user.status === 'active' ? 'disabled' : 'active';
    try {
      await usersService.updateUser(user.id, { status: nextStatus });
      toast.success(`User ${user.name} is now ${nextStatus}.`);
      loadData();
    } catch (err: any) {
      toast.error('Status update failed: ' + err.message);
    }
  };

  const handleDeleteUser = (user: AdminUser) => {
    setConfirmDialog({
      isOpen: true,
      title: `Delete Account: ${user.name}`,
      message: `Are you sure you want to permanently delete ${user.name} (${user.email})? This action cannot be reversed.`,
      action: async () => {
        try {
          await usersService.deleteUser(user.id);
          toast.success(`Account ${user.name} deleted.`);
          if (selectedUser?.id === user.id) setSelectedUser(null);
          loadData();
        } catch (err: any) {
          toast.error('Delete failed: ' + err.message);
        }
      }
    });
  };

  const handleForceLogout = (user: AdminUser, sessionId: string) => {
    setConfirmDialog({
      isOpen: true,
      title: 'Force Session Termination',
      message: `Terminate active login session for ${user.name}? The examiner will be required to re-authenticate immediately.`,
      action: async () => {
        try {
          await usersService.forceLogoutSession(user.id, sessionId);
          toast.success('Session terminated successfully.');
          loadData();
        } catch (err: any) {
          toast.error('Session termination failed: ' + err.message);
        }
      }
    });
  };

  const handleUpdateSecuritySettings = async (patch: Partial<AdminSettings>) => {
    setSavingSettings(true);
    try {
      const updated = await systemService.updateSettings(patch);
      setSettings(updated);
      toast.success('Security policy updated.');
    } catch (err: any) {
      toast.error('Failed to update security settings');
    } finally {
      setSavingSettings(false);
    }
  };

  const columns: Column<AdminUser>[] = [
    {
      key: 'name',
      header: 'Examiner & Identity',
      render: (u) => (
        <div className="space-y-0.5">
          <div className={`font-bold font-sans flex items-center gap-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
            <span>{u.name}</span>
            {u.two_factor_enabled && (
              <span
                title="2FA Active"
                className={`p-0.5 rounded border ${
                  isLight
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : 'bg-emerald-950/80 text-emerald-400 border-emerald-600/40'
                }`}
              >
                <Smartphone className="w-3 h-3" />
              </span>
            )}
          </div>
          <div className={`text-[11px] font-mono ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>{u.email}</div>
        </div>
      )
    },
    {
      key: 'role',
      header: 'Role',
      render: (u) => <StatusBadge status={u.role} variant="role" />
    },
    {
      key: 'department',
      header: 'Department',
      render: (u) => (
        <span className={`text-xs font-sans line-clamp-1 ${isLight ? 'text-slate-600' : 'text-stone-300'}`}>
          {u.department}
        </span>
      )
    },
    {
      key: 'status',
      header: 'Status',
      render: (u) => <StatusBadge status={u.status} />
    },
    {
      key: 'last_login',
      header: 'Last Login',
      render: (u) => (
        <span className={`text-xs font-mono ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
          {u.last_login === 'Never' ? 'Never' : new Date(u.last_login).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}
        </span>
      )
    },
    {
      key: 'actions',
      header: 'Actions',
      className: 'text-right',
      render: (u) => (
        <div className="flex items-center justify-end gap-1.5">
          <button
            type="button"
            onClick={() => setSelectedUser(u)}
            className={`p-1.5 rounded-lg border transition-colors cursor-pointer ${
              isLight
                ? 'bg-slate-100 hover:bg-slate-200 text-slate-700 hover:text-slate-900 border-slate-200'
                : 'bg-stone-900 hover:bg-stone-800 text-stone-300 hover:text-white border-stone-700'
            }`}
            title="Inspect Sessions & Profile"
          >
            <Laptop className="w-3.5 h-3.5" />
          </button>

          <button
            type="button"
            onClick={() => handleResetPassword(u)}
            className={`p-1.5 rounded-lg border transition-colors cursor-pointer ${
              isLight
                ? 'bg-amber-50 hover:bg-amber-100 text-amber-700 border-amber-200'
                : 'bg-stone-900 hover:bg-amber-950/50 text-amber-400 border-stone-700 hover:border-amber-600/50'
            }`}
            title="Issue Temporary Reset Token"
          >
            <Key className="w-3.5 h-3.5" />
          </button>

          <button
            type="button"
            onClick={() => handleToggleStatus(u)}
            className={`p-1.5 rounded-lg border transition-colors cursor-pointer ${
              u.status === 'active'
                ? isLight
                  ? 'bg-slate-100 hover:bg-slate-200 text-slate-600 border-slate-200'
                  : 'bg-stone-900 hover:bg-stone-800 text-stone-400 border-stone-700'
                : isLight
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                : 'bg-emerald-950/50 text-emerald-400 border-emerald-600/40'
            }`}
            title={u.status === 'active' ? 'Disable Account' : 'Enable Account'}
          >
            {u.status === 'active' ? <UserX className="w-3.5 h-3.5" /> : <UserCheck className="w-3.5 h-3.5" />}
          </button>

          <button
            type="button"
            onClick={() => handleOpenEdit(u)}
            className={`p-1.5 rounded-lg border transition-colors cursor-pointer text-xs font-mono ${
              isLight
                ? 'bg-slate-100 hover:bg-slate-200 text-slate-700 hover:text-[#f95721] border-slate-200'
                : 'bg-stone-900 hover:bg-stone-800 text-stone-300 hover:text-[#f95721] border-stone-700 hover:border-[#f95721]/50'
            }`}
            title="Edit User"
          >
            Edit
          </button>

          <button
            type="button"
            onClick={() => handleDeleteUser(u)}
            className={`p-1.5 rounded-lg border transition-colors cursor-pointer ${
              isLight
                ? 'bg-rose-50 hover:bg-rose-100 text-rose-700 border-rose-200'
                : 'bg-stone-900 hover:bg-red-950/50 text-stone-500 hover:text-red-400 border-stone-700 hover:border-red-600/50'
            }`}
            title="Delete User"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      )
    }
  ];

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div
        className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b ${
          isLight ? 'border-slate-200' : 'border-[#282321]'
        }`}
      >
        <div>
          <h1
            className={`text-xl sm:text-2xl font-black tracking-tight font-sans ${
              isLight ? 'text-slate-900' : 'text-white'
            }`}
          >
            User Directory & Access Control
          </h1>
          <p className={`text-xs sm:text-sm font-sans mt-0.5 ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
            Role assignments (Admin, Investigator, Auditor), active session termination, and credential rules
          </p>
        </div>

        <button
          type="button"
          onClick={handleOpenCreate}
          className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs sm:text-sm font-bold text-white bg-[#f95721] hover:bg-[#ea580c] transition-all shadow-[0_0_15px_rgba(249,87,33,0.3)] cursor-pointer w-fit"
        >
          <UserPlus className="w-4 h-4" />
          <span>Create User</span>
        </button>
      </div>

      {/* Security Policies Configuration Box */}
      {settings && (
        <div
          className={`p-4 sm:p-5 rounded-2xl border space-y-3 ${
            isLight
              ? 'bg-white border-slate-200 shadow-sm'
              : 'bg-[#141211]/90 border-[#2b2523] shadow-md'
          }`}
        >
          <div
            className={`flex items-center justify-between flex-wrap gap-2 border-b pb-2 ${
              isLight ? 'border-slate-100' : 'border-[#241e1c]'
            }`}
          >
            <div
              className={`flex items-center gap-2 font-bold text-xs sm:text-sm font-sans ${
                isLight ? 'text-slate-900' : 'text-white'
              }`}
            >
              <Shield className="w-4 h-4 text-[#f95721]" />
              <span>Identity & Credential Security Policies</span>
            </div>
            <span className={`text-[10px] font-mono ${isLight ? 'text-slate-400' : 'text-stone-500'}`}>
              Live Enforcement
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-sans">
            {/* 2FA Toggle */}
            <div
              className={`flex items-center justify-between p-3 rounded-xl border ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-black/40 border-[#28221f]'
              }`}
            >
              <div className="space-y-0.5">
                <span className={`font-semibold block ${isLight ? 'text-slate-900' : 'text-white'}`}>
                  Enforce 2FA
                </span>
                <span className={`text-[11px] block ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
                  Require TOTP for all roles
                </span>
              </div>
              <input
                type="checkbox"
                checked={settings.two_factor_enforced}
                disabled={savingSettings}
                onChange={(e) => handleUpdateSecuritySettings({ two_factor_enforced: e.target.checked })}
                className="w-4 h-4 accent-[#f95721] cursor-pointer"
              />
            </div>

            {/* Min Password Length */}
            <div
              className={`flex items-center justify-between p-3 rounded-xl border ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-black/40 border-[#28221f]'
              }`}
            >
              <div className="space-y-0.5">
                <span className={`font-semibold block ${isLight ? 'text-slate-900' : 'text-white'}`}>
                  Password Rules
                </span>
                <span className={`text-[11px] block ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
                  Min length: {settings.min_password_length} chars
                </span>
              </div>
              <select
                value={settings.min_password_length}
                disabled={savingSettings}
                onChange={(e) => handleUpdateSecuritySettings({ min_password_length: Number(e.target.value) })}
                className={`px-2 py-1 rounded border font-mono text-xs cursor-pointer ${
                  isLight
                    ? 'bg-white border-slate-300 text-slate-800'
                    : 'bg-[#1a1715] border-stone-700 text-white'
                }`}
              >
                <option value={8}>8 chars</option>
                <option value={12}>12 chars</option>
                <option value={16}>16 chars</option>
              </select>
            </div>

            {/* Lockout Limit */}
            <div
              className={`flex items-center justify-between p-3 rounded-xl border ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-black/40 border-[#28221f]'
              }`}
            >
              <div className="space-y-0.5">
                <span className={`font-semibold block ${isLight ? 'text-slate-900' : 'text-white'}`}>
                  Failed Login Lockout
                </span>
                <span className={`text-[11px] block ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
                  Lockout after 5 failed attempts
                </span>
              </div>
              <span
                className={`px-2.5 py-0.5 rounded-md font-mono font-bold border ${
                  isLight
                    ? 'bg-rose-50 border-rose-200 text-rose-700'
                    : 'bg-red-950/70 border-red-800/60 text-red-400'
                }`}
              >
                5 Attempts
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Filter Bar */}
      <FilterBar
        searchQuery={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search by name, email, or department..."
        filters={[
          {
            key: 'role',
            label: 'Role',
            value: roleFilter,
            options: [
              { label: 'All Roles', value: 'all' },
              { label: 'Admin', value: 'admin' },
              { label: 'Investigator', value: 'investigator' },
              { label: 'Auditor', value: 'auditor' }
            ],
            onChange: setRoleFilter
          },
          {
            key: 'status',
            label: 'Status',
            value: statusFilter,
            options: [
              { label: 'All Statuses', value: 'all' },
              { label: 'Active', value: 'active' },
              { label: 'Disabled', value: 'disabled' }
            ],
            onChange: setStatusFilter
          }
        ]}
        onResetFilters={() => {
          setSearch('');
          setRoleFilter('all');
          setStatusFilter('all');
        }}
      />

      {/* Main Users Table */}
      <DataTable
        columns={columns}
        data={users}
        keyExtractor={(u) => u.id}
        isLoading={isLoading}
        emptyTitle="No users matched"
        emptyMessage="No accounts matched the active search or filter criteria."
      />

      {/* Drawer / Details for Selected User Active Sessions */}
      {selectedUser && (
        <div
          className={`p-5 rounded-2xl border space-y-4 ${
            isLight
              ? 'bg-white border-slate-200 shadow-sm text-slate-800'
              : 'bg-[#141211]/90 border-[#2b2523] shadow-xl text-stone-200'
          }`}
        >
          <div
            className={`flex items-center justify-between border-b pb-3 ${
              isLight ? 'border-slate-100' : 'border-[#26201e]'
            }`}
          >
            <div className="space-y-0.5">
              <h3
                className={`text-sm sm:text-base font-bold font-sans flex items-center gap-2 ${
                  isLight ? 'text-slate-900' : 'text-white'
                }`}
              >
                <Laptop className="w-4 h-4 text-[#f95721]" />
                <span>Active Login Sessions for {selectedUser.name}</span>
              </h3>
              <p className={`text-xs font-sans ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
                Review authenticated devices and force terminate suspicious tokens
              </p>
            </div>
            <button
              type="button"
              onClick={() => setSelectedUser(null)}
              className={`text-xs font-mono cursor-pointer ${
                isLight ? 'text-slate-500 hover:text-slate-900' : 'text-stone-400 hover:text-white'
              }`}
            >
              Close Panel
            </button>
          </div>

          {selectedUser.sessions.length === 0 ? (
            <p className={`text-xs font-mono py-3 ${isLight ? 'text-slate-400' : 'text-stone-500'}`}>
              No active live sessions detected for this user.
            </p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {selectedUser.sessions.map((sess) => (
                <div
                  key={sess.id}
                  className={`p-3.5 rounded-xl border flex items-center justify-between gap-3 text-xs ${
                    isLight
                      ? 'bg-slate-50 border-slate-200'
                      : 'bg-black/40 border-[#2b2523]'
                  }`}
                >
                  <div className="space-y-1 min-w-0">
                    <div className={`font-semibold font-sans truncate ${isLight ? 'text-slate-900' : 'text-white'}`}>
                      {sess.device}
                    </div>
                    <div className={`text-[11px] font-mono ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
                      IP: {sess.ip} · Last Active: {sess.last_active}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleForceLogout(selectedUser, sess.id)}
                    className={`px-2.5 py-1.5 rounded-lg text-xs font-mono border transition-colors flex items-center gap-1.5 cursor-pointer shrink-0 ${
                      isLight
                        ? 'text-red-700 hover:bg-red-50 bg-white border-red-200'
                        : 'text-red-400 hover:text-white bg-red-950/50 hover:bg-red-900/60 border-red-800/60'
                    }`}
                    title="Terminate Session"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    <span>Force Logout</span>
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Modal: Create User */}
      {createModalOpen && (
        <div
          className={`fixed inset-0 z-50 flex items-center justify-center p-4 backdrop-blur-sm animate-fadeIn ${
            isLight ? 'bg-slate-900/40' : 'bg-black/80'
          }`}
        >
          <div
            className={`w-full max-w-md rounded-2xl border p-6 shadow-2xl space-y-4 ${
              isLight ? 'bg-white border-slate-200 text-slate-800' : 'bg-[#141211] border-[#2e2724] text-white'
            }`}
          >
            <h3 className={`text-lg font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
              Create Forensic Examiner Account
            </h3>
            <form onSubmit={handleSaveCreate} className="space-y-3.5">
              <div>
                <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-600' : 'text-stone-400'}`}>
                  Full Name
                </label>
                <input
                  type="text"
                  required
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  placeholder="e.g. Alex Mercer"
                  className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm border focus:outline-none focus:border-[#f95721] ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900 placeholder:text-slate-400'
                      : 'bg-black/40 border-[#2e2724] text-white'
                  }`}
                />
              </div>

              <div>
                <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-600' : 'text-stone-400'}`}>
                  Official Email
                </label>
                <input
                  type="email"
                  required
                  value={formEmail}
                  onChange={(e) => setFormEmail(e.target.value)}
                  placeholder="e.g. a.mercer@dcsre.net"
                  className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm border focus:outline-none focus:border-[#f95721] ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900 placeholder:text-slate-400'
                      : 'bg-black/40 border-[#2e2724] text-white'
                  }`}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-600' : 'text-stone-400'}`}>
                    Role
                  </label>
                  <select
                    value={formRole}
                    onChange={(e) => setFormRole(e.target.value as AdminRole)}
                    className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm border focus:outline-none focus:border-[#f95721] cursor-pointer ${
                      isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-900'
                        : 'bg-black/40 border-[#2e2724] text-white'
                    }`}
                  >
                    <option value="investigator" className={isLight ? 'bg-white text-slate-900' : 'bg-[#141211]'}>Investigator</option>
                    <option value="auditor" className={isLight ? 'bg-white text-slate-900' : 'bg-[#141211]'}>Auditor</option>
                    <option value="admin" className={isLight ? 'bg-white text-slate-900' : 'bg-[#141211]'}>Administrator</option>
                  </select>
                </div>
                <div>
                  <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-600' : 'text-stone-400'}`}>
                    Status
                  </label>
                  <select
                    value={formStatus}
                    onChange={(e) => setFormStatus(e.target.value as UserStatus)}
                    className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm border focus:outline-none focus:border-[#f95721] cursor-pointer ${
                      isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-900'
                        : 'bg-black/40 border-[#2e2724] text-white'
                    }`}
                  >
                    <option value="active" className={isLight ? 'bg-white text-slate-900' : 'bg-[#141211]'}>Active</option>
                    <option value="disabled" className={isLight ? 'bg-white text-slate-900' : 'bg-[#141211]'}>Disabled</option>
                  </select>
                </div>
              </div>

              <div>
                <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-600' : 'text-stone-400'}`}>
                  Department
                </label>
                <input
                  type="text"
                  required
                  value={formDepartment}
                  onChange={(e) => setFormDepartment(e.target.value)}
                  className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm border focus:outline-none focus:border-[#f95721] ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900'
                      : 'bg-black/40 border-[#2e2724] text-white'
                  }`}
                />
              </div>

              <div className={`flex items-center justify-end gap-2.5 pt-3 border-t ${isLight ? 'border-slate-100' : 'border-[#26201e]'}`}>
                <button
                  type="button"
                  onClick={() => setCreateModalOpen(false)}
                  className={`px-4 py-2 rounded-xl text-xs font-semibold border cursor-pointer ${
                    isLight
                      ? 'text-slate-700 bg-slate-100 border-slate-300 hover:bg-slate-200'
                      : 'text-stone-300 bg-stone-900 border-stone-700 hover:bg-stone-800'
                  }`}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl text-xs font-bold text-white bg-[#f95721] hover:bg-[#ea580c] cursor-pointer shadow-md"
                >
                  Create User
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Edit User */}
      {editModalOpen && selectedUser && (
        <div
          className={`fixed inset-0 z-50 flex items-center justify-center p-4 backdrop-blur-sm animate-fadeIn ${
            isLight ? 'bg-slate-900/40' : 'bg-black/80'
          }`}
        >
          <div
            className={`w-full max-w-md rounded-2xl border p-6 shadow-2xl space-y-4 ${
              isLight ? 'bg-white border-slate-200 text-slate-800' : 'bg-[#141211] border-[#2e2724] text-white'
            }`}
          >
            <h3 className={`text-lg font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
              Edit Account: {selectedUser.name}
            </h3>
            <form onSubmit={handleSaveEdit} className="space-y-3.5">
              <div>
                <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-600' : 'text-stone-400'}`}>
                  Full Name
                </label>
                <input
                  type="text"
                  required
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm border focus:outline-none focus:border-[#f95721] ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900'
                      : 'bg-black/40 border-[#2e2724] text-white'
                  }`}
                />
              </div>

              <div>
                <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-600' : 'text-stone-400'}`}>
                  Email
                </label>
                <input
                  type="email"
                  required
                  value={formEmail}
                  onChange={(e) => setFormEmail(e.target.value)}
                  className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm border focus:outline-none focus:border-[#f95721] ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900'
                      : 'bg-black/40 border-[#2e2724] text-white'
                  }`}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-600' : 'text-stone-400'}`}>
                    Role
                  </label>
                  <select
                    value={formRole}
                    onChange={(e) => setFormRole(e.target.value as AdminRole)}
                    className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm border focus:outline-none focus:border-[#f95721] cursor-pointer ${
                      isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-900'
                        : 'bg-black/40 border-[#2e2724] text-white'
                    }`}
                  >
                    <option value="investigator" className={isLight ? 'bg-white text-slate-900' : 'bg-[#141211]'}>Investigator</option>
                    <option value="auditor" className={isLight ? 'bg-white text-slate-900' : 'bg-[#141211]'}>Auditor</option>
                    <option value="admin" className={isLight ? 'bg-white text-slate-900' : 'bg-[#141211]'}>Administrator</option>
                  </select>
                </div>
                <div>
                  <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-600' : 'text-stone-400'}`}>
                    Status
                  </label>
                  <select
                    value={formStatus}
                    onChange={(e) => setFormStatus(e.target.value as UserStatus)}
                    className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm border focus:outline-none focus:border-[#f95721] cursor-pointer ${
                      isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-900'
                        : 'bg-black/40 border-[#2e2724] text-white'
                    }`}
                  >
                    <option value="active" className={isLight ? 'bg-white text-slate-900' : 'bg-[#141211]'}>Active</option>
                    <option value="disabled" className={isLight ? 'bg-white text-slate-900' : 'bg-[#141211]'}>Disabled</option>
                    <option value="suspended" className={isLight ? 'bg-white text-slate-900' : 'bg-[#141211]'}>Suspended</option>
                  </select>
                </div>
              </div>

              <div>
                <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-600' : 'text-stone-400'}`}>
                  Department
                </label>
                <input
                  type="text"
                  required
                  value={formDepartment}
                  onChange={(e) => setFormDepartment(e.target.value)}
                  className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm border focus:outline-none focus:border-[#f95721] ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900'
                      : 'bg-black/40 border-[#2e2724] text-white'
                  }`}
                />
              </div>

              <div className={`flex items-center justify-end gap-2.5 pt-3 border-t ${isLight ? 'border-slate-100' : 'border-[#26201e]'}`}>
                <button
                  type="button"
                  onClick={() => setEditModalOpen(false)}
                  className={`px-4 py-2 rounded-xl text-xs font-semibold border cursor-pointer ${
                    isLight
                      ? 'text-slate-700 bg-slate-100 border-slate-300 hover:bg-slate-200'
                      : 'text-stone-300 bg-stone-900 border-stone-700 hover:bg-stone-800'
                  }`}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl text-xs font-bold text-white bg-[#f95721] hover:bg-[#ea580c] cursor-pointer shadow-md"
                >
                  Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Confirm Action Dialog */}
      <ConfirmDialog
        isOpen={confirmDialog.isOpen}
        title={confirmDialog.title}
        message={confirmDialog.message}
        onConfirm={async () => {
          await confirmDialog.action();
          setConfirmDialog((prev) => ({ ...prev, isOpen: false }));
        }}
        onCancel={() => setConfirmDialog((prev) => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
};
