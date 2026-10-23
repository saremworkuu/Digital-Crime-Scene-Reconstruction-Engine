/**
 * AdminApp Container
 * Connects AdminLayout, AdminGuard, and all 9 Admin pages.
 * Supports URL hash routing (e.g. #/admin/users) and state navigation.
 *
 * NOTE: Real security must be enforced server-side later via JWT verification
 * and RBAC middleware. Frontend guards only control user experience flow.
 */

import React, { useState, useEffect } from 'react';
import { useApp } from '../store';
import { AdminGuard } from './components/AdminGuard';
import { AdminLayout } from './components/AdminLayout';

// Admin Pages
import { DashboardPage } from './pages/DashboardPage';
import { UsersPage } from './pages/UsersPage';
import { AuditLogPage } from './pages/AuditLogPage';
import { CasesPage } from './pages/CasesPage';
import { EvidencePage } from './pages/EvidencePage';
import { RulesPage } from './pages/RulesPage';
import { MessagesPage } from './pages/MessagesPage';
import { SystemHealthPage } from './pages/SystemHealthPage';
import { SettingsPage } from './pages/SettingsPage';

export const AdminApp: React.FC = () => {
  const { currentUser, setCurrentPage } = useApp();

  // Helper to extract sub-tab from hash if available (e.g. #/admin/audit -> 'audit')
  const getSubTabFromHash = (): string => {
    if (typeof window !== 'undefined') {
      const hash = window.location.hash;
      const match = hash.match(/#\/admin\/([a-z_-]+)/i);
      if (match && match[1]) {
        return match[1];
      }
    }
    return (currentUser?.role as string) === 'auditor' ? 'audit' : 'dashboard';
  };

  const [activeSubTab, setActiveSubTab] = useState<string>(getSubTabFromHash);

  // Sync hash changes with sub-tab state
  useEffect(() => {
    const handleHashChange = () => {
      const tab = getSubTabFromHash();
      setActiveSubTab(tab);
    };

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, [currentUser]);

  const handleSelectTab = (tabId: string) => {
    setActiveSubTab(tabId);
    if (typeof window !== 'undefined') {
      window.location.hash = `#/admin/${tabId}`;
    }
  };

  const handleExitAdmin = () => {
    if (typeof window !== 'undefined') {
      window.location.hash = '';
    }
    if (currentUser?.role === 'admin') {
      setCurrentPage('home');
    } else {
      setCurrentPage('dashboard');
    }
  };

  const renderActivePage = () => {
    switch (activeSubTab) {
      case 'dashboard':
        return <DashboardPage onNavigateTab={handleSelectTab} />;
      case 'users':
        return <UsersPage />;
      case 'audit':
        return <AuditLogPage />;
      case 'cases':
        return <CasesPage />;
      case 'evidence':
        return <EvidencePage />;
      case 'rules':
        return <RulesPage />;
      case 'messages':
        return <MessagesPage />;
      case 'health':
        return <SystemHealthPage />;
      case 'settings':
        return <SettingsPage />;
      default:
        return (currentUser?.role as string) === 'auditor' ? (
          <AuditLogPage />
        ) : (
          <DashboardPage onNavigateTab={handleSelectTab} />
        );
    }
  };

  return (
    <AdminGuard activeAdminSubTab={activeSubTab}>
      <AdminLayout
        activeTab={activeSubTab}
        onSelectTab={handleSelectTab}
        onExitAdmin={handleExitAdmin}
      >
        {renderActivePage()}
      </AdminLayout>
    </AdminGuard>
  );
};

export default AdminApp;
