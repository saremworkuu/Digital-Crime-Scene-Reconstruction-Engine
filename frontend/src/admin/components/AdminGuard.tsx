/**
 * AdminGuard Component
 * Enforces role-based frontend access boundaries for /admin/* paths.
 *
 * NOTE: Real security must be enforced server-side later via JWT verification
 * and RBAC middleware. Frontend guards only control user experience flow.
 */

import React from 'react';
import { useApp } from '../../store';
import { NoAccess } from './NoAccess';

interface AdminGuardProps {
  children: React.ReactNode;
  activeAdminSubTab?: string;
}

export const AdminGuard: React.FC<AdminGuardProps> = ({ children, activeAdminSubTab }) => {
  const { currentUser } = useApp();

  // If no user is authenticated, block access
  if (!currentUser) {
    return <NoAccess requiredRole="admin" />;
  }

  // Admin has full access to all /admin/* sections
  if (currentUser.role === 'admin') {
    return <>{children}</>;
  }

  // Auditors may open ONLY the audit log (read-only)
  if ((currentUser.role as string) === 'auditor') {
    if (activeAdminSubTab === 'audit') {
      return <>{children}</>;
    }
    return <NoAccess requiredRole="admin (Auditor access restricted to Audit Log)" />;
  }

  // Anyone else (e.g. investigator) sees "No access" page
  return <NoAccess requiredRole="admin" />;
};
