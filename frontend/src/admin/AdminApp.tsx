/**
 * AdminApp Container
 * Connects AdminLayout, AdminGuard, and all 9 Admin pages.
 * Keeps visited tabs mounted for instant switching and warms core admin caches cleanly.
 */

import React, { useState, useEffect, useRef } from 'react';
import { useApp } from '../store';
import { AdminGuard } from './components/AdminGuard';
import { AdminLayout } from './components/AdminLayout';
import {
  auditService,
  casesService,
  evidenceService,
  messagesService,
  rulesService,
  systemService,
  usersService
} from '../services/admin';
import { clearAllAdminMemoryCache, clearLegacyAdminStorage } from '../services/admin/storageHelper';

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
  const isAuditor = (currentUser?.role as string) === 'auditor';

  const getSubTabFromHash = (): string => {
    if (typeof window !== 'undefined') {
      const hash = window.location.hash;
      const match = hash.match(/#\/admin\/([a-z_-]+)/i);
      if (match && match[1]) {
        return match[1];
      }
    }
    return isAuditor ? 'audit' : 'dashboard';
  };

  const [activeSubTab, setActiveSubTab] = useState<string>(getSubTabFromHash);
  const [visitedTabs, setVisitedTabs] = useState<string[]>(() => [getSubTabFromHash()]);
  const warmedUserRef = useRef<string | null>(null);

  useEffect(() => {
    clearLegacyAdminStorage();
  }, []);

  useEffect(() => {
    if (!currentUser) {
      clearAllAdminMemoryCache();
      warmedUserRef.current = null;
      return;
    }

    if (isAuditor || warmedUserRef.current === currentUser.id) {
      return;
    }
    warmedUserRef.current = currentUser.id;

    let cancelled = false;
    const timer = window.setTimeout(async () => {
      try {
        await Promise.allSettled([casesService.getCases(), usersService.getUsers()]);
        if (cancelled) return;
        await Promise.allSettled([
          auditService.getAuditLogs({ page: 1, limit: 12 }),
          messagesService.getMessages({ page: 1, limit: 10 })
        ]);
        if (cancelled) return;
        await Promise.allSettled([
          evidenceService.getEvidence(),
          rulesService.getRules()
        ]);
        if (cancelled) return;
        await Promise.allSettled([
          systemService.getSystemHealth(),
          systemService.getSettings()
        ]);
      } catch {
        // Ignore background prefetch errors
      }
    }, 350);

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [currentUser, isAuditor]);

  // Keep visited tabs mounted for zero-latency back-and-forth switching
  useEffect(() => {
    setVisitedTabs((prev) => (prev.includes(activeSubTab) ? prev : [...prev, activeSubTab]));
  }, [activeSubTab]);

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

  const renderTabContent = (tabId: string) => {
    switch (tabId) {
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
        return isAuditor ? (
          <AuditLogPage />
        ) : (
          <DashboardPage onNavigateTab={handleSelectTab} />
        );
    }
  };

  const tabsToRender = isAuditor ? ['audit'] : visitedTabs;

  return (
    <AdminGuard activeAdminSubTab={activeSubTab}>
      <AdminLayout
        activeTab={activeSubTab}
        onSelectTab={handleSelectTab}
        onExitAdmin={handleExitAdmin}
      >
        {tabsToRender.map((tabId) => {
          const isCurrent = tabId === activeSubTab || (isAuditor && tabId === 'audit');
          return (
            <div key={tabId} className={isCurrent ? 'block' : 'hidden'}>
              {renderTabContent(tabId)}
            </div>
          );
        })}
      </AdminLayout>
    </AdminGuard>
  );
};

export default AdminApp;
