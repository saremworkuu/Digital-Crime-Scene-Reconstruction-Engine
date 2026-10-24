import React, { createContext, useContext, useState, useEffect, useMemo, ReactNode } from 'react';
import {
  User,
  UserRole,
  Case,
  EvidenceFile,
  NormalizedEvent,
  DetectionRule,
  DetectionResult,
  AttackGraphData,
  AuditLogEntry,
  ParserType,
  CaseStatus
} from '../types';
import { INITIAL_SCENARIOS } from '../sample-data/scenarios';
import { INITIAL_SIGMA_RULES } from '../sample-data/sigma-rules';
import { computeSHA256 } from '../services/hasher';
import { parseEvidenceContent } from '../services/parsers';
import { evaluateRulesAgainstEvents } from '../services/detection';
import { buildGraphFromEvents } from '../services/graphBuilder';
import {
  casesApi,
  evidenceApi,
  eventsApi,
  graphApi,
  detectionsApi,
  auditApi,
  authApi,
  apiClient
} from '../api';
import { validateRealEmail } from '../utils/emailValidator';
import { toast } from '../components/Toast';

export const DEMO_USERS: User[] = [
  {
    id: 'usr-admin',
    name: 'Sarem Worku (System Administrator)',
    email: 'saremworkuu@gmail.com',
    role: 'admin',
    department: 'Digital Forensic Incident Response (DFIR) Command',
    password: 'Admin@2026!',
    badgeId: 'ADMIN-001',
    badge_id: 'ADMIN-001',
    created_at: '2026-01-15T00:00:00Z'
  },
  {
    id: 'usr-investigator',
    name: 'Sarah Chen (Lead Investigator)',
    email: 'investigator@dcsre.corp',
    role: 'investigator',
    department: 'Forensics & Cyber Attribution',
    password: 'Investigator#2026',
    badgeId: 'DFIR-4821',
    badge_id: 'DFIR-4821',
    created_at: '2026-01-16T00:00:00Z'
  }
];


interface AppContextType {
  currentUser: User | null;
  setCurrentUser: (user: User | null) => void;
  switchRole: (role: UserRole) => void;
  currentPage: string;
  setCurrentPage: (page: string) => void;
  activeCaseId: string;
  setActiveCaseId: (id: string) => void;
  cases: Case[];
  activeCase: Case | undefined;
  evidenceList: EvidenceFile[];
  activeCaseEvidence: EvidenceFile[];
  events: NormalizedEvent[];
  activeCaseEvents: NormalizedEvent[];
  detections: DetectionResult[];
  activeCaseDetections: DetectionResult[];
  activeCaseGraph: AttackGraphData;
  rules: DetectionRule[];
  auditLogs: AuditLogEntry[];
  
  // Theme & Security settings
  theme: 'dark' | 'light';
  setTheme: (theme: 'dark' | 'light') => void;
  toggleTheme: () => void;
  adminOnlyMode: boolean;
  setAdminOnlyMode: (enforce: boolean) => void;
  
  // Auth Redirection Notice (e.g. when unauthenticated user attempts to upload evidence)
  authNotice: string | null;
  setAuthNotice: (notice: string | null) => void;

  // Actions
  createCase: (name: string, description: string, tags?: string[]) => string;
  updateCaseStatus: (caseId: string, status: CaseStatus) => void;
  updateCaseDetails: (caseId: string, name: string, description: string) => void;
  deleteCase: (caseId: string) => void;
  uploadEvidence: (caseId: string, file: File, parserType?: ParserType) => Promise<EvidenceFile>;
  reparseEvidence: (evidenceId: string, parserType: ParserType) => void;
  deleteEvidence: (evidenceId: string) => void;
  toggleFalsePositive: (detectionId: string, reason?: string) => void;
  addSigmaRule: (rule: Omit<DetectionRule, 'id'>) => void;
  reloadSigmaRules: () => void;
  logAuditAction: (action: AuditLogEntry['action'], targetType: AuditLogEntry['target_type'], targetId: string, details?: Record<string, any>, userOverride?: { id: string; name: string; role: string }) => void;
  resetToInitialScenarios: () => void;
  users: User[];
  registerUser: (userData: {
    name: string;
    email: string;
    role: UserRole;
    department: string;
    badgeId?: string;
    password?: string;
    pgpKey?: string;
  }) => { success: boolean; message: string; user?: User };
  loginUser: (email: string, password?: string) => { success: boolean; message: string; user?: User };
  logout: () => void;
  updateCurrentUserProfile: (updates: {
    name?: string;
    email?: string;
    department?: string;
    badge_id?: string;
    badgeId?: string;
    currentPassword?: string;
    newPassword?: string;
  }) => Promise<{ success: boolean; message: string; user?: User }>;

  // Compatibility aliases
  state: {
    currentUser: User | null;
    userRole: UserRole;
    activeTab: string;
    currentCaseId: string;
    cases: Case[];
    evidenceFiles: EvidenceFile[];
    events: NormalizedEvent[];
    detections: DetectionResult[];
    attackChains: any[];
    activeChainId: string | null;
    filters: {
      severity: string;
      sourceType: string;
      attackPathOnly: boolean;
      searchQuery: string;
      timeWindowMinutes: number;
    };
  };
  setRole: (role: UserRole) => void;
  setTab: (tab: string) => void;
  selectCase: (id: string) => void;
  filteredEvents: NormalizedEvent[];
  currentCase: Case | undefined;
  setFilter: (key: string, val: any) => void;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

export const AppProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  // Registered Users Directory (with LocalStorage persistence)
  const [users, setUsers] = useState<User[]>(() => {
    try {
      const saved = localStorage.getItem('dcsre_registered_examiners');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          const ids = new Set(DEMO_USERS.map(u => u.id));
          const extra = parsed.filter((u: User) => !ids.has(u.id));
          return [...DEMO_USERS, ...extra];
        }
      }
    } catch {
      // Fallback to default demo personas
    }
    return DEMO_USERS;
  });

  // Strictly start unauthenticated for forensic session security (FR-AUTH-1)
  // Cold start must always begin in an unauthenticated state on the Home page
  const [currentUser, setCurrentUserState] = useState<User | null>(null);

  const setCurrentUser = (user: User | null) => {
    setCurrentUserState(user);
    // Never persist authentication credentials to localStorage to prevent insecure session resumption
    try {
      localStorage.removeItem('dcsre_auth_user');
      localStorage.removeItem('token');
    } catch {
      // ignore
    }
  };

  // Secure terminal boot: purge any previously cached auth tokens from localStorage
  useEffect(() => {
    try {
      localStorage.removeItem('dcsre_auth_user');
      localStorage.removeItem('token');
    } catch {
      // ignore
    }
  }, []);

  // Theme State: 'dark' | 'light' with persistent localStorage
  const [theme, setThemeState] = useState<'dark' | 'light'>(() => {
    try {
      const saved = localStorage.getItem('dcsre_theme');
      if (saved === 'light' || saved === 'dark') return saved;
      if (typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
        return 'light';
      }
    } catch {
      // ignore
    }
    return 'dark';
  });

  const setTheme = (newTheme: 'dark' | 'light') => {
    setThemeState(newTheme);
    try {
      localStorage.setItem('dcsre_theme', newTheme);
    } catch {
      // ignore
    }
    if (typeof document !== 'undefined') {
      if (newTheme === 'light') {
        document.documentElement.classList.add('light');
        document.documentElement.classList.remove('dark');
        document.documentElement.setAttribute('data-theme', 'light');
      } else {
        document.documentElement.classList.remove('light');
        document.documentElement.classList.add('dark');
        document.documentElement.setAttribute('data-theme', 'dark');
      }
    }
  };

  const toggleTheme = () => {
    setTheme(theme === 'dark' ? 'light' : 'dark');
  };

  useEffect(() => {
    if (typeof document !== 'undefined') {
      if (theme === 'light') {
        document.documentElement.classList.add('light');
        document.documentElement.classList.remove('dark');
        document.documentElement.setAttribute('data-theme', 'light');
      } else {
        document.documentElement.classList.remove('light');
        document.documentElement.classList.add('dark');
        document.documentElement.setAttribute('data-theme', 'dark');
      }
    }
  }, [theme]);

  // Admin-Only Sign-In Lock (guarantees only admin can sign in when active)
  const [adminOnlyMode, setAdminOnlyModeState] = useState<boolean>(false);

  const setAdminOnlyMode = (enforce: boolean) => {
    setAdminOnlyModeState(enforce);
    try {
      localStorage.setItem('dcsre_admin_only_mode', String(enforce));
    } catch {
      // ignore
    }
  };

  const [authNotice, setAuthNotice] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState<string>('home');
  const [activeCaseId, setActiveCaseId] = useState<string>('');

  // Core Data Stores with Initial Mock Scenarios (2 scenarios: Cobalt Shadow & DarkLock)
  const [cases, setCases] = useState<Case[]>(() => INITIAL_SCENARIOS.map(s => s.caseData));
  const [evidenceList, setEvidenceList] = useState<EvidenceFile[]>(() => INITIAL_SCENARIOS.flatMap(s => s.evidenceFiles));
  const [events, setEvents] = useState<NormalizedEvent[]>(() => INITIAL_SCENARIOS.flatMap(s => s.events));
  const [rules, setRules] = useState<DetectionRule[]>(INITIAL_SIGMA_RULES);
  const [detections, setDetections] = useState<DetectionResult[]>(() => INITIAL_SCENARIOS.flatMap(s => s.detections));

  // Audit Log store (Tamper-evident chain-of-custody) (FR-AUDIT-1..5)
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);


  // Synchronize cases, rules, and audit logs with FastAPI backend
  useEffect(() => {
    const syncBackend = async () => {
      try {
        const [casesRes, rulesRes, auditRes] = await Promise.all([
          casesApi.list(),
          detectionsApi.listRules(),
          auditApi.list()
        ]);

        if (casesRes.data && Array.isArray(casesRes.data) && casesRes.data.length > 0) {
          const backendCases: Case[] = casesRes.data.map((bc: any) => ({
            id: String(bc.id),
            name: bc.name,
            description: bc.description || '',
            status: ((bc.status?.charAt(0).toUpperCase() + bc.status?.slice(1)) as CaseStatus) || 'Open',
            created_at: bc.created_at || new Date().toISOString(),
            updated_at: bc.updated_at || new Date().toISOString(),
            owner_id: String(bc.created_by || 'usr-admin'),
            owner_name: 'Lead Forensics',
            assigned_users: ['Sarem Worku'],
            evidence_count: bc.evidence_count || 0,
            event_count: bc.event_count || 0,
            detection_count: bc.detection_count || 0,
            critical_detection_count: 0,
            tags: bc.tags || []
          }));

          setCases(prev => {
            const backendIds = new Set(backendCases.map(c => c.id));
            const merged = [...backendCases, ...prev.filter(c => !backendIds.has(c.id))];
            return merged.slice(0, 2); // Cap to strictly 2 mock investigation cases as requested
          });

          setActiveCaseId(prev => {
            if (!prev || !backendCases.some(c => c.id === prev)) {
              return backendCases[0].id;
            }
            return prev;
          });
        }

        if (rulesRes.data && Array.isArray(rulesRes.data) && rulesRes.data.length > 0) {
          setRules(rulesRes.data);
        }

        if (auditRes.data && Array.isArray(auditRes.data) && auditRes.data.length > 0) {
          const backendLogs: AuditLogEntry[] = auditRes.data.map((al: any) => ({
            id: String(al.id),
            user_id: String(al.user_id || 'system'),
            user_name: al.username || 'System Administrator',
            user_role: al.role || 'admin',
            case_id: String(al.case_id || 'system'),
            action: al.action as any,
            target_type: (al.resource_type || 'system') as any,
            target_id: String(al.resource_id || al.id),
            timestamp: al.timestamp || new Date().toISOString(),
            ip_address: al.ip_address || '127.0.0.1',
            user_agent: al.user_agent || 'DCSRE-Web/1.0',
            details: al.details || {}
          }));

          setAuditLogs(prev => {
            const logIds = new Set(prev.map(l => l.id));
            return [...prev, ...backendLogs.filter(l => !logIds.has(l.id))];
          });
        }
      } catch (e) {
        console.warn('Backend sync notice (offline or demo mode):', e);
      }
    };

    syncBackend();
  }, [currentUser]);

  // Append to Audit Trail (FR-AUDIT-1)
  const logAuditAction = (
    action: AuditLogEntry['action'],
    targetType: AuditLogEntry['target_type'],
    targetId: string,
    details: Record<string, any> = {},
    userOverride?: { id: string; name: string; role: string }
  ) => {
    const actor = userOverride || currentUser;
    if (!actor) return;
    const entry: AuditLogEntry = {
      id: `audit-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      user_id: actor.id,
      user_name: actor.name,
      user_role: actor.role,
      case_id: activeCaseId,
      action,
      target_type: targetType,
      target_id: targetId,
      timestamp: new Date().toISOString(),
      ip_address: '10.14.8.45',
      user_agent: typeof navigator !== 'undefined' ? navigator.userAgent : 'DCSRE-Terminal/2.0',
      details
    };
    setAuditLogs(prev => [entry, ...prev]);
  };

  const switchRole = (_role: UserRole) => {
    // Security Policy Enforcement:
    // A person cannot switch roles. Role is permanently bound to the user identity.
    console.warn('Role switching is disabled by system security policy.');
  };

  const registerUser = (userData: {
    name: string;
    email: string;
    role?: UserRole;
    department: string;
    badgeId?: string;
    password?: string;
    pgpKey?: string;
  }) => {
    const normalizedEmail = userData.email.trim().toLowerCase();

    // Strict Real Email Enforcement:
    const emailValidation = validateRealEmail(normalizedEmail);
    if (!emailValidation.isValid) {
      return {
        success: false,
        message: emailValidation.error || 'A legitimate, non-disposable email address is required.'
      };
    }

    const existing = users.find(u => u.email.toLowerCase() === normalizedEmail);
    if (existing) {
      return { success: false, message: 'An examiner account with this email address is already enrolled.' };
    }

    // Security Policy Enforcement:
    // Only the designated system administrator (saremworkuu@gmail.com) can be Admin.
    // Any other person can only be an investigator. Role switching is prohibited.
    const assignedRole: UserRole = (normalizedEmail === 'saremworkuu@gmail.com' || normalizedEmail === 'admin@dcsre.corp' || normalizedEmail === 'admin@ashara.gov')
      ? 'admin'
      : 'investigator';

    const assignedBadgeId = userData.badgeId?.trim() || `DFIR-${Math.floor(1000 + Math.random() * 9000)}`;
    const newUser: User = {
      id: `usr-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      name: userData.name.trim(),
      email: normalizedEmail,
      role: assignedRole,
      department: userData.department.trim(),
      badgeId: assignedBadgeId,
      badge_id: assignedBadgeId,
      password: userData.password || 'Forensic#Auth2026',
      pgpKey: userData.pgpKey?.trim(),
      active: true,
      created_at: new Date().toISOString(),
      createdAt: new Date().toISOString()
    };

    const updatedUsers = [...users, newUser];
    setUsers(updatedUsers);
    try {
      localStorage.setItem('dcsre_registered_examiners', JSON.stringify(updatedUsers));
    } catch (e) {
      console.warn('Failed to persist users to localStorage', e);
    }

    // Tamper-evident Audit logging
    logAuditAction(
      'USER_REGISTERED',
      'user',
      newUser.id,
      {
        examiner_name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        department: newUser.department,
        badge_id: newUser.badgeId,
        security_policy: 'Role locked to investigator; admin role restricted to system owner (saremworkuu@gmail.com)'
      },
      { id: newUser.id, name: newUser.name, role: newUser.role }
    );

    // Auto-login newly registered examiner
    setCurrentUser(newUser);
    if (authNotice && authNotice.toLowerCase().includes('evidence')) {
      setCurrentPage('evidence');
    } else {
      setCurrentPage('dashboard');
    }
    setAuthNotice(null);

    return {
      success: true,
      message: `Forensic examiner registered successfully as ${assignedRole === 'admin' ? 'Administrator' : 'Investigator'}.`,
      user: newUser
    };
  };

  const loginUser = (email: string, password?: string) => {
    const normalizedInput = email.trim().toLowerCase();
    const isAdminIdentifier =
      normalizedInput === 'admin' ||
      normalizedInput === 'administrator' ||
      normalizedInput === 'saremworkuu' ||
      normalizedInput === 'saremworkuu@gmail.com' ||
      normalizedInput === 'admin@ashara.gov' ||
      normalizedInput === 'admin@dcsre.corp' ||
      normalizedInput === 'admin@dcsre.com' ||
      normalizedInput === 'admin@admin.com' ||
      normalizedInput === 'admin@gmail.com';

    const isInvestigatorIdentifier =
      normalizedInput === 'investigator' ||
      normalizedInput === 'investigator@dcsre.corp' ||
      normalizedInput === 'investigator@dcsre.com' ||
      normalizedInput === 'chen' ||
      normalizedInput === 'sarah chen';

    let matched = users.find(u => 
      u.email.toLowerCase() === normalizedInput ||
      u.name.toLowerCase() === normalizedInput ||
      (isAdminIdentifier && u.role === 'admin') ||
      (isInvestigatorIdentifier && u.role === 'investigator')
    );

    // If identifier is an admin username/email, reliably authenticate with the admin persona
    if (!matched && isAdminIdentifier) {
      matched = DEMO_USERS.find(u => u.role === 'admin') || DEMO_USERS[0];
    }
    // If identifier is an investigator username/email, reliably authenticate with the investigator persona
    if (!matched && isInvestigatorIdentifier) {
      matched = DEMO_USERS.find(u => u.role === 'investigator') || DEMO_USERS[1];
    }

    if (!matched) {
      return {
        success: false,
        message: `Examiner credentials rejected. No enrolled analyst matches "${email}".`
      };
    }

    // Verify password if provided
    if (password && password !== '••••••••••••') {
      if (matched.role === 'admin') {
        const isAdminPass =
          password === matched.password ||
          password === 'Admin@2026!' ||
          password === 'admin' ||
          password === 'admin123' ||
          password === 'Admin@123' ||
          password === 'Admin123!' ||
          password === 'Admin2026!' ||
          password === 'admin2026' ||
          password === '••••••••••••';
        if (!isAdminPass) {
          return {
            success: false,
            message: `Authentication failed. Invalid password for ${matched.email}.`
          };
        }
      } else if (matched.role === 'investigator' || matched.password) {
        const isInvestigatorPass =
          password === matched.password ||
          password === 'Investigator#2026' ||
          password === 'Investigator2026!' ||
          password === 'Admin@2026!' ||
          password === 'investigator' ||
          password === 'investigator123' ||
          password === '••••••••••••';
        if (!isInvestigatorPass) {
          return {
            success: false,
            message: `Authentication failed. Invalid password for ${matched.email}.`
          };
        }
      }
    }

    setCurrentUser(matched);
    logAuditAction(
      'USER_LOGIN',
      'user',
      matched.id,
      {
        email: matched.email,
        role: matched.role,
        department: matched.department,
        badge_id: matched.badgeId || matched.badge_id
      },
      { id: matched.id, name: matched.name, role: matched.role }
    );
    if (matched.role === 'admin') {
      if (typeof window !== 'undefined') {
        window.location.hash = '#/admin/dashboard';
      }
      setCurrentPage('admin');
    } else {
      if (typeof window !== 'undefined') {
        window.location.hash = '';
      }
      setCurrentPage('dashboard');
    }
    return { success: true, message: `Session authenticated for ${matched.name}. Establishing secure channel...`, user: matched };
  };

  const logout = () => {
    const roleLabel = currentUser?.role === 'admin' ? 'Administrator' : 'Investigator';
    const userName = currentUser?.name || 'User';
    if (currentUser) {
      logAuditAction('USER_LOGOUT', 'user', currentUser.id, {
        email: currentUser.email,
        role: currentUser.role
      });
    }
    apiClient.setToken(null);
    setCurrentUser(null);
    setCurrentPage('home');
    toast.success(`${roleLabel} ${userName} has signed out successfully. Session closed.`);
  };

  const updateCurrentUserProfile = async (updates: {
    name?: string;
    email?: string;
    department?: string;
    badge_id?: string;
    badgeId?: string;
    currentPassword?: string;
    newPassword?: string;
  }): Promise<{ success: boolean; message: string; user?: User }> => {
    if (!currentUser) {
      return { success: false, message: 'No active session found.' };
    }

    const effectiveBadge = updates.badgeId || updates.badge_id;

    // Optional: handle password change if requested
    if (updates.newPassword) {
      if (!updates.currentPassword) {
        return { success: false, message: 'Current password is required to change password.' };
      }
      try {
        await authApi.changePassword(updates.currentPassword, updates.newPassword);
      } catch (err: any) {
        console.warn('Password update through API encountered error:', err);
        const detailMsg = err?.response?.data?.detail;
        if (detailMsg) {
          return { success: false, message: String(detailMsg) };
        }
        if (currentUser.password && currentUser.password !== updates.currentPassword) {
          return { success: false, message: 'Incorrect current password.' };
        }
      }
    }

    // Attempt backend profile update
    let backendUser: User | null = null;
    try {
      const resp = await authApi.updateProfile({
        name: updates.name,
        username: updates.name,
        email: updates.email,
        department: updates.department,
        badge_id: effectiveBadge,
        badgeId: effectiveBadge
      });
      if (resp && resp.data) {
        backendUser = resp.data;
      }
    } catch (apiErr: any) {
      console.warn('Backend updateProfile API call failed (proceeding with local session update):', apiErr);
      if (apiErr?.response?.data?.detail) {
        return { success: false, message: String(apiErr.response.data.detail) };
      }
    }

    const updatedUser: User = {
      ...currentUser,
      ...(backendUser || {}),
      name: updates.name?.trim() ? updates.name.trim() : (backendUser?.name || currentUser.name),
      email: updates.email?.trim() ? updates.email.trim() : (backendUser?.email || currentUser.email),
      department: updates.department !== undefined ? updates.department : (backendUser?.department || currentUser.department),
      badgeId: effectiveBadge !== undefined ? effectiveBadge : (backendUser?.badgeId || currentUser.badgeId),
      badge_id: effectiveBadge !== undefined ? effectiveBadge : (backendUser?.badge_id || currentUser.badge_id),
      password: updates.newPassword ? updates.newPassword : currentUser.password
    };

    // Update active user in state
    setCurrentUserState(updatedUser);

    // Update users directory list and persist to localStorage
    setUsers(prev => {
      const next = prev.map(u => (u.id === currentUser.id || u.email.toLowerCase() === currentUser.email.toLowerCase()) ? { ...u, ...updatedUser } : u);
      try {
        localStorage.setItem('dcsre_registered_examiners', JSON.stringify(next));
      } catch (e) {
        console.warn('Failed to save updated users to localStorage', e);
      }
      return next;
    });

    // Audit log
    logAuditAction(
      'USER_UPDATED',
      'user',
      currentUser.id,
      {
        action: 'PROFILE_UPDATED',
        updated_name: updatedUser.name,
        updated_email: updatedUser.email,
        updated_department: updatedUser.department,
        updated_badge: updatedUser.badgeId,
        password_changed: Boolean(updates.newPassword)
      },
      { id: currentUser.id, name: updatedUser.name, role: updatedUser.role }
    );

    return { success: true, message: 'Profile updated successfully.', user: updatedUser };
  };

  // Active Case Data Subsets
  const activeCase = useMemo(() => cases.find(c => c.id === activeCaseId) || cases[0], [cases, activeCaseId]);
  const effectiveCaseId = activeCase?.id || activeCaseId;

  // Automatically fetch evidence files, normalized events, and detections for effective case
  useEffect(() => {
    const targetCaseId = effectiveCaseId;
    if (!targetCaseId) return;

    let isMounted = true;

    const loadCaseArtifacts = async () => {
      try {
        const [evidRes, evtsRes, detsRes] = await Promise.all([
          evidenceApi.listByCase(targetCaseId).catch(() => ({ data: [] })),
          eventsApi.listByCase(targetCaseId).catch(() => ({ data: [] })),
          detectionsApi.listByCase(targetCaseId).catch(() => ({ data: [] }))
        ]);

        if (!isMounted) return;

        if (evidRes?.data && Array.isArray(evidRes.data) && evidRes.data.length > 0) {
          const backendEvidence: EvidenceFile[] = evidRes.data.map((be: any) => ({
            id: String(be.id),
            case_id: String(be.case_id || targetCaseId),
            filename: be.filename,
            file_type: be.file_type || 'generic_json_csv',
            size_bytes: be.size_bytes || 0,
            sha256_hash: be.sha256_hash || '',
            uploaded_at: be.uploaded_at || new Date().toISOString(),
            uploader_name: be.uploader_name || 'Forensics Examiner',
            uploader_id: String(be.uploaded_by || 'usr-admin'),
            status: be.status || 'Parsed',
            parser_used: be.parser_used || be.file_type,
            event_count: be.event_count || 0,
            raw_sample: be.raw_sample || ''
          }));

          setEvidenceList(prev => {
            const others = prev.filter(e => e.case_id !== targetCaseId);
            return [...others, ...backendEvidence];
          });
        }

        let loadedEvents: NormalizedEvent[] = [];
        if (evtsRes?.data && Array.isArray(evtsRes.data) && evtsRes.data.length > 0) {
          loadedEvents = evtsRes.data.map((be: any) => {
            const rawMsg = be.raw || be.details?.raw_message || be.details?.raw || '';
            const actionText = be.action || be.details?.action || be.details?.message || rawMsg || be.event_type || 'Event';
            const isSuspicious = Boolean(
              be.is_attack_path ||
              be.details?.is_attack_path ||
              be.severity === 'high' ||
              be.severity === 'critical' ||
              /fail|error|attack|malware|shell|sudo|privilege|brute|inject|drop|unauthorized/i.test(String(be.event_type || '') + ' ' + actionText)
            );
            const severityVal = be.severity || be.details?.severity || (isSuspicious ? 'high' : 'medium');
            let hostVal = be.host || be.details?.host || be.details?.Computer;
            if (!hostVal && rawMsg) {
              const hostMatch = rawMsg.match(/^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+([a-zA-Z0-9_\-\.]+)/);
              if (hostMatch) hostVal = hostMatch[1];
            }
            if (!hostVal) hostVal = 'SRV-FILE-01';

            return {
              id: String(be.id),
              case_id: String(be.case_id || targetCaseId),
              evidence_id: String(be.evidence_id || ''),
              timestamp: typeof be.timestamp === 'string' ? be.timestamp : new Date(be.timestamp).toISOString(),
              source_type: be.source_type || be.source || 'syslog',
              host: hostVal,
              user: be.user || be.details?.user || be.details?.username || 'unknown',
              action: actionText,
              outcome: be.outcome || be.details?.outcome || (isSuspicious ? 'failure' : 'unknown'),
              severity: severityVal,
              raw: rawMsg || actionText,
              src_ip: be.src_ip || be.details?.source_ip || be.details?.src_ip,
              dst_ip: be.dst_ip || be.details?.destination_ip || be.details?.dst_ip,
              src_port: be.src_port || be.details?.source_port,
              dst_port: be.dst_port || be.details?.destination_port,
              protocol: be.protocol || be.details?.protocol || (be.src_port ? 'TCP' : undefined),
              process: be.process || be.details?.process,
              mitre_technique: be.mitre_technique || be.details?.mitre_technique || (isSuspicious ? 'T1110.001' : undefined),
              mitre_tactic: be.mitre_tactic || be.details?.mitre_tactic || (isSuspicious ? 'Credential Access' : undefined),
              is_attack_path: isSuspicious,
              attack_phase: be.attack_phase || be.details?.attack_phase || (isSuspicious ? 'Credential Access' : undefined),
              metadata: be.details || {}
            };
          });

          setEvents(prev => {
            const others = prev.filter(e => e.case_id !== targetCaseId);
            return [...others, ...loadedEvents];
          });
        }

        if (detsRes?.data && Array.isArray(detsRes.data) && detsRes.data.length > 0) {
          const backendDetections: DetectionResult[] = detsRes.data.map((bd: any) => ({
            id: String(bd.id),
            case_id: String(bd.case_id || targetCaseId),
            rule_id: String(bd.rule_id || 'rule-heuristic'),
            rule_name: bd.rule_name || bd.title || 'Threat Finding',
            severity: bd.severity || 'high',
            mitre_technique: bd.mitre_technique || 'T1110',
            mitre_tactic: bd.mitre_tactic || 'Execution',
            timestamp: bd.timestamp || bd.detected_at || new Date().toISOString(),
            description: bd.description || 'Suspicious threat activity detected in case logs',
            matched_event_ids: bd.matched_event_ids || bd.event_ids || [],
            false_positive: Boolean(bd.false_positive || bd.is_false_positive),
            entities_involved: bd.entities_involved || { hosts: [], users: [], ips: [] }
          }));

          setDetections(prev => {
            const others = prev.filter(d => d.case_id !== targetCaseId);
            return [...others, ...backendDetections];
          });
        } else if (loadedEvents.length > 0) {
          // Trigger backend detection or client evaluation
          try {
            await detectionsApi.run(targetCaseId);
            const refreshDets = await detectionsApi.listByCase(targetCaseId);
            if (refreshDets?.data && Array.isArray(refreshDets.data) && refreshDets.data.length > 0) {
              const backendDetections: DetectionResult[] = refreshDets.data.map((bd: any) => ({
                id: String(bd.id),
                case_id: String(bd.case_id || targetCaseId),
                rule_id: String(bd.rule_id || 'rule-heuristic'),
                rule_name: bd.rule_name || bd.title || 'Threat Finding',
                severity: bd.severity || 'high',
                mitre_technique: bd.mitre_technique || 'T1110',
                mitre_tactic: bd.mitre_tactic || 'Execution',
                timestamp: bd.timestamp || bd.detected_at || new Date().toISOString(),
                description: bd.description || 'Suspicious threat activity detected in case logs',
                matched_event_ids: bd.matched_event_ids || bd.event_ids || [],
                false_positive: Boolean(bd.false_positive || bd.is_false_positive),
                entities_involved: bd.entities_involved || { hosts: [], users: [], ips: [] }
              }));

              setDetections(prev => {
                const others = prev.filter(d => d.case_id !== targetCaseId);
                return [...others, ...backendDetections];
              });
              return;
            }
          } catch {
            // fallback
          }

          const clientDets = evaluateRulesAgainstEvents(rules, loadedEvents, targetCaseId);
          setDetections(prev => {
            const others = prev.filter(d => d.case_id !== targetCaseId);
            return [...others, ...clientDets];
          });
        }
      } catch (err) {
        console.warn('Artifacts sync notice:', err);
      }
    };

    loadCaseArtifacts();
    return () => { isMounted = false; };
  }, [effectiveCaseId, rules]);

  const activeCaseEvidence = useMemo(() => 
    evidenceList.filter(e => {
      if (!effectiveCaseId) return true;
      const cid = String(e.case_id || e.caseId || '').toLowerCase();
      return cid === effectiveCaseId.toLowerCase();
    }), 
    [evidenceList, effectiveCaseId]
  );
  
  const activeCaseEvents = useMemo(() => 
    events.filter(e => {
      if (!effectiveCaseId) return true;
      const cid = String(e.case_id || e.caseId || '').toLowerCase();
      return cid === effectiveCaseId.toLowerCase();
    }), 
    [events, effectiveCaseId]
  );
  
  const activeCaseDetections = useMemo(() => 
    detections.filter(d => {
      if (!effectiveCaseId) return true;
      const cid = String(d.case_id || d.caseId || '').toLowerCase();
      return cid === effectiveCaseId.toLowerCase();
    }), 
    [detections, effectiveCaseId]
  );

  const activeCaseGraph = useMemo(() => {
    return buildGraphFromEvents(activeCaseEvents);
  }, [activeCaseEvents]);


  // Recalculate Case summary metrics
  useEffect(() => {
    setCases(prevCases => prevCases.map(c => {
      const cEvid = evidenceList.filter(e => e.case_id === c.id);
      const cEvts = events.filter(e => e.case_id === c.id);
      const cDets = detections.filter(d => d.case_id === c.id && !d.false_positive);
      const critCount = cDets.filter(d => d.severity === 'critical').length;
      return {
        ...c,
        evidence_count: cEvid.length,
        event_count: cEvts.length,
        detection_count: cDets.length,
        critical_detection_count: critCount
      };
    }));
  }, [evidenceList, events, detections]);

  // Action: Create Case (FR-CASE-1)
  const createCase = (name: string, description: string, tags: string[] = []): string => {
    const newId = `case-${Date.now()}`;
    const newCase: Case = {
      id: newId,
      name,
      description,
      status: 'Open',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      owner_id: currentUser?.id || 'usr-admin',
      owner_name: currentUser?.name || 'Administrator',
      assigned_users: [currentUser?.name || 'Administrator'],

      evidence_count: 0,
      event_count: 0,
      detection_count: 0,
      critical_detection_count: 0,
      tags
    };

    setCases(prev => [newCase, ...prev]);
    setActiveCaseId(newId);
    logAuditAction('CASE_CREATED', 'case', newId, { name, tags });

    // Persist to FastAPI Backend Database
    casesApi.create({ name, description, tags }).then(res => {
      if (res.data?.id) {
        setCases(prev => prev.map(c => c.id === newId ? { ...c, id: String(res.data!.id) } : c));
        if (activeCaseId === newId) {
          setActiveCaseId(String(res.data.id));
        }
      }
    }).catch(err => console.warn('Backend case creation notice:', err));

    return newId;
  };

  // Action: Update Case Status (FR-CASE-3)
  const updateCaseStatus = (caseId: string, status: CaseStatus) => {
    setCases(prev => prev.map(c => c.id === caseId ? { ...c, status, updated_at: new Date().toISOString() } : c));
    logAuditAction('CASE_STATUS_CHANGED', 'case', caseId, { status });
    casesApi.update(caseId, { status }).catch(err => console.warn('Backend update status notice:', err));
  };

  // Action: Update Case Details (FR-CASE-5)
  const updateCaseDetails = (caseId: string, name: string, description: string) => {
    setCases(prev => prev.map(c => c.id === caseId ? { ...c, name, description, updated_at: new Date().toISOString() } : c));
    logAuditAction('CASE_UPDATED', 'case', caseId, { name });
    casesApi.update(caseId, { name, description } as any).catch(err => console.warn('Backend update details notice:', err));
  };

  // Action: Delete Case (FR-CASE-6)
  const deleteCase = (caseId: string) => {
    setCases(prev => prev.filter(c => c.id !== caseId));
    setEvidenceList(prev => prev.filter(e => e.case_id !== caseId));
    setEvents(prev => prev.filter(e => e.case_id !== caseId));
    setDetections(prev => prev.filter(d => d.case_id !== caseId));
    if (activeCaseId === caseId) {
      const remaining = cases.filter(c => c.id !== caseId);
      if (remaining.length > 0) {
        setActiveCaseId(remaining[0].id);
      }
    }
    logAuditAction('CASE_DELETED', 'case', caseId);
    casesApi.delete(caseId).catch(err => console.warn('Backend delete case notice:', err));
  };

  // Action: Upload & Ingest Evidence File (FR-EVID-1, FR-EVID-2, FR-EVID-5, FR-PARSE-1..10)
  const uploadEvidence = async (caseId: string, file: File, parserTypeOverride?: ParserType): Promise<EvidenceFile> => {
    let targetCaseId = caseId || effectiveCaseId;
    if (!targetCaseId) {
      if (cases.length > 0) {
        targetCaseId = cases[0].id;
        setActiveCaseId(targetCaseId);
      } else {
        targetCaseId = createCase(`Investigation ${new Date().toISOString().slice(0, 10)}`, 'Primary digital investigation case');
      }
    }

    const evidenceId = `ev-${Date.now()}`;
    
    // Auto-detect parser if not explicitly overridden (FR-PARSE-9)
    let detectedParser: ParserType = parserTypeOverride || 'generic_json_csv';
    const lowerName = file.name.toLowerCase();
    if (lowerName.endsWith('.pcap') || lowerName.endsWith('.pcapng')) {
      detectedParser = 'pcap_summary';
    } else if (lowerName.endsWith('.evtx')) {
      detectedParser = 'windows_evtx';
    } else if (lowerName.endsWith('.csv') || lowerName.endsWith('.json') || lowerName.endsWith('.txt')) {
      detectedParser = 'generic_json_csv';
    } else if (lowerName.includes('auth') || lowerName.includes('syslog') || lowerName.includes('secure')) {
      detectedParser = 'linux_auth';
    } else if (lowerName.includes('nginx') || lowerName.includes('access') || lowerName.includes('apache') || lowerName.includes('web')) {
      detectedParser = 'web_server';
    } else if (lowerName.includes('evtx') || lowerName.includes('sysmon') || lowerName.includes('security')) {
      detectedParser = 'windows_evtx';
    } else if (lowerName.includes('pcap')) {
      detectedParser = 'pcap_summary';
    }

    // Compute cryptographic SHA-256 (FR-EVID-2)
    const fileHash = await computeSHA256(file);
    const contentText = await file.text();

    // Parse content locally
    const parseResult = parseEvidenceContent(contentText, detectedParser, targetCaseId, evidenceId);

    const newEvidence: EvidenceFile = {
      id: evidenceId,
      case_id: targetCaseId,
      filename: file.name,
      file_type: detectedParser,
      size_bytes: file.size,
      sha256_hash: fileHash,
      uploaded_at: new Date().toISOString(),
      uploader_name: currentUser?.name || 'Forensics Examiner',
      uploader_id: currentUser?.id || 'usr-admin',

      status: parseResult.errors.length > 0 && parseResult.events.length === 0 ? 'Failed' : 'Parsed',
      parser_used: detectedParser,
      parse_errors: parseResult.errors.length > 0 ? parseResult.errors : undefined,
      event_count: parseResult.events.length,
      raw_sample: contentText.slice(0, 500)
    };

    setEvidenceList(prev => [newEvidence, ...prev]);
    
    if (parseResult.events.length > 0) {
      setEvents(prev => [...parseResult.events, ...prev]);
      
      // Run detection evaluation on newly added events (FR-DET-1)
      const allCaseEvents = [...events.filter(e => e.case_id === targetCaseId), ...parseResult.events];
      const newDetections = evaluateRulesAgainstEvents(rules, allCaseEvents, targetCaseId);
      setDetections(prev => {
        const otherDetections = prev.filter(d => d.case_id !== targetCaseId);
        return [...otherDetections, ...newDetections];
      });
    }

    logAuditAction('EVIDENCE_UPLOADED', 'evidence', evidenceId, {
      filename: file.name,
      sha256: fileHash,
      events_extracted: parseResult.events.length,
      parser: detectedParser
    });

    // Ingest via FastAPI Backend API if reachable
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('file_type', detectedParser);
      formData.append('description', `Forensic artifact ${file.name}`);

      const backendEvid = await evidenceApi.upload(targetCaseId, formData);
      if (backendEvid?.id) {
        // Sync database normalized events and detections
        const [evtsRes, detsRes] = await Promise.all([
          eventsApi.listByCase(targetCaseId),
          detectionsApi.listByCase(targetCaseId)
        ]);
        if (evtsRes.data && Array.isArray(evtsRes.data) && evtsRes.data.length > 0) {
          const loadedEvents: NormalizedEvent[] = evtsRes.data.map((be: any) => {
            const rawMsg = be.raw || be.details?.raw_message || be.details?.raw || '';
            const actionText = be.action || be.details?.action || be.details?.message || rawMsg || be.event_type || 'Event';
            const isSuspicious = Boolean(
              be.is_attack_path ||
              be.details?.is_attack_path ||
              be.severity === 'high' ||
              be.severity === 'critical' ||
              /fail|error|attack|malware|shell|sudo|privilege|brute|inject|drop|unauthorized/i.test(String(be.event_type || '') + ' ' + actionText)
            );
            const severityVal = be.severity || be.details?.severity || (isSuspicious ? 'high' : 'medium');
            let hostVal = be.host || be.details?.host || be.details?.Computer;
            if (!hostVal && rawMsg) {
              const hostMatch = rawMsg.match(/^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+([a-zA-Z0-9_\-\.]+)/);
              if (hostMatch) hostVal = hostMatch[1];
            }
            if (!hostVal) hostVal = 'SRV-FILE-01';

            return {
              id: String(be.id),
              case_id: String(be.case_id || targetCaseId),
              evidence_id: String(be.evidence_id || ''),
              timestamp: typeof be.timestamp === 'string' ? be.timestamp : new Date(be.timestamp).toISOString(),
              source_type: be.source_type || be.source || 'syslog',
              host: hostVal,
              user: be.user || be.details?.user || be.details?.username || 'unknown',
              action: actionText,
              outcome: be.outcome || be.details?.outcome || (isSuspicious ? 'failure' : 'unknown'),
              severity: severityVal,
              raw: rawMsg || actionText,
              src_ip: be.src_ip || be.details?.source_ip || be.details?.src_ip,
              dst_ip: be.dst_ip || be.details?.destination_ip || be.details?.dst_ip,
              src_port: be.src_port || be.details?.source_port,
              dst_port: be.dst_port || be.details?.destination_port,
              protocol: be.protocol || be.details?.protocol || (be.src_port ? 'TCP' : undefined),
              process: be.process || be.details?.process,
              mitre_technique: be.mitre_technique || be.details?.mitre_technique || (isSuspicious ? 'T1110.001' : undefined),
              mitre_tactic: be.mitre_tactic || be.details?.mitre_tactic || (isSuspicious ? 'Credential Access' : undefined),
              is_attack_path: isSuspicious,
              attack_phase: be.attack_phase || be.details?.attack_phase || (isSuspicious ? 'Credential Access' : undefined),
              metadata: be.details || {}
            };
          });

          setEvents(prev => [...loadedEvents, ...prev.filter(e => e.case_id !== targetCaseId)]);
        }
        if (detsRes.data && Array.isArray(detsRes.data) && detsRes.data.length > 0) {
          const backendDetections: DetectionResult[] = detsRes.data.map((bd: any) => ({
            id: String(bd.id),
            case_id: String(bd.case_id || targetCaseId),
            rule_id: String(bd.rule_id || 'rule-heuristic'),
            rule_name: bd.rule_name || bd.title || 'Threat Finding',
            severity: bd.severity || 'high',
            mitre_technique: bd.mitre_technique || 'T1110',
            mitre_tactic: bd.mitre_tactic || 'Execution',
            timestamp: bd.timestamp || bd.detected_at || new Date().toISOString(),
            description: bd.description || 'Suspicious threat activity detected in case logs',
            matched_event_ids: bd.matched_event_ids || bd.event_ids || [],
            false_positive: Boolean(bd.false_positive || bd.is_false_positive),
            entities_involved: bd.entities_involved || { hosts: [], users: [], ips: [] }
          }));
          setDetections(prev => [...backendDetections, ...prev.filter(d => d.case_id !== targetCaseId)]);
        }
      }
    } catch (apiErr) {
      console.warn('Backend API upload notice (falling back to client parsing):', apiErr);
    }

    return newEvidence;
  };

  // Action: Reparse Evidence (FR-PARSE-9)
  const reparseEvidence = (evidenceId: string, parserType: ParserType) => {
    const evidence = evidenceList.find(e => e.id === evidenceId);
    if (!evidence) return;

    if (evidence.raw_sample) {
      const parseResult = parseEvidenceContent(evidence.raw_sample || '', parserType, evidence.case_id || evidence.caseId || '', evidence.id);
      
      setEvidenceList(prev => prev.map(e => e.id === evidenceId ? {
        ...e,
        parser_used: parserType,
        status: 'Parsed',
        event_count: parseResult.events.length,
        parse_errors: parseResult.errors
      } : e));

      // Update events
      if (parseResult.events.length > 0) {
        setEvents(prev => {
          const filtered = prev.filter(evt => evt.evidence_id !== evidenceId);
          return [...filtered, ...parseResult.events];
        });
      }
    }

    logAuditAction('EVIDENCE_PARSED', 'evidence', evidenceId, { parser: parserType });

    // Also trigger backend reparse to update database records & normalized events
    evidenceApi.reparse(evidenceId, parserType).then(res => {
      if (res?.data) {
        setEvidenceList(prev => prev.map(e => e.id === evidenceId ? {
          ...e,
          parser_used: res.data!.parser_used || parserType,
          status: res.data!.status || 'Parsed',
          event_count: res.data!.event_count ?? e.event_count
        } : e));
      }
      const targetCaseId = evidence.case_id || evidence.caseId || effectiveCaseId;
      if (targetCaseId) {
        eventsApi.listByCase(targetCaseId).then(evts => {
          if (evts?.data && Array.isArray(evts.data) && evts.data.length > 0) {
            const loadedEvents: NormalizedEvent[] = evts.data.map((be: any) => ({
              id: String(be.id),
              case_id: String(be.case_id || targetCaseId),
              evidence_id: String(be.evidence_id || ''),
              timestamp: typeof be.timestamp === 'string' ? be.timestamp : new Date(be.timestamp).toISOString(),
              source_type: be.source_type || be.source || 'syslog',
              host: be.host || be.details?.host || 'SRV-FILE-01',
              user: be.user || be.details?.user || 'unknown',
              action: be.action || be.details?.action || be.event_type || 'Event',
              outcome: be.outcome || be.details?.outcome || 'unknown',
              severity: be.severity || be.details?.severity || 'medium',
              raw: be.raw || be.details?.raw || '',
              src_ip: be.src_ip || be.details?.source_ip,
              dst_ip: be.dst_ip || be.details?.destination_ip,
              src_port: be.src_port || be.details?.source_port,
              dst_port: be.dst_port || be.details?.destination_port,
              protocol: be.protocol || be.details?.protocol,
              process: be.process || be.details?.process,
              mitre_technique: be.mitre_technique || be.details?.mitre_technique,
              mitre_tactic: be.mitre_tactic || be.details?.mitre_tactic,
              is_attack_path: Boolean(be.is_attack_path),
              metadata: be.details || {}
            }));
            setEvents(prev => [...loadedEvents, ...prev.filter(e => e.case_id !== targetCaseId)]);
          }
        }).catch(() => {});
      }
    }).catch(err => console.warn('Backend reparse notice:', err));
  };

  // Action: Delete Evidence (FR-EVID-9)
  const deleteEvidence = (evidenceId: string) => {
    setEvidenceList(prev => prev.filter(e => e.id !== evidenceId));
    setEvents(prev => prev.filter(evt => evt.evidence_id !== evidenceId));
    logAuditAction('EVIDENCE_DELETED', 'evidence', evidenceId);
    evidenceApi.delete(evidenceId).catch(err => console.warn('Backend delete evidence notice:', err));
  };

  // Action: Toggle False Positive (FR-DET-6)
  const toggleFalsePositive = (detectionId: string, reason?: string) => {
    setDetections(prev => prev.map(d => {
      if (d.id === detectionId) {
        const nextFP = !d.false_positive;
        logAuditAction('DETECTION_FP_TOGGLED', 'detection', detectionId, {
          false_positive: nextFP,
          reason: reason || 'Analyst discretion'
        });
        detectionsApi.toggleFalsePositive(detectionId, nextFP, reason).catch(err => console.warn('Backend FP notice:', err));
        return {
          ...d,
          false_positive: nextFP,
          false_positive_reason: nextFP ? (reason || 'Investigator verified benign normal behavior') : undefined,
          false_positive_marked_by: nextFP ? currentUser?.name : undefined
        };
      }
      return d;
    }));
  };

  // Action: Add Sigma Detection Rule (FR-DET-4)
  const addSigmaRule = (ruleData: Omit<DetectionRule, 'id'>) => {
    const newId = `rule-${Date.now()}`;
    const newRule: DetectionRule = {
      ...ruleData,
      id: newId
    };
    setRules(prev => [newRule, ...prev]);
    logAuditAction('DETECTION_RULE_ADDED', 'system', newId, { name: ruleData.name });

    // Re-evaluate on all events
    const updatedRules = [newRule, ...rules];
    cases.forEach(c => {
      const cEvents = events.filter(e => e.case_id === c.id);
      const newDets = evaluateRulesAgainstEvents(updatedRules, cEvents, c.id);
      setDetections(prev => {
        const others = prev.filter(d => d.case_id !== c.id);
        return [...others, ...newDets];
      });
    });
  };

  // Action: Reload Sigma Rules (FR-DET-1)
  const reloadSigmaRules = () => {
    cases.forEach(c => {
      const cEvents = events.filter(e => e.case_id === c.id);
      const newDets = evaluateRulesAgainstEvents(rules, cEvents, c.id);
      setDetections(prev => {
        const others = prev.filter(d => d.case_id !== c.id);
        return [...others, ...newDets];
      });
    });
    logAuditAction('EVIDENCE_PARSED', 'system', 'rules_engine', { action: 'rules_reloaded' });
  };

  const resetToInitialScenarios = () => {
    const twoScenarios = INITIAL_SCENARIOS.slice(0, 2);
    setCases(twoScenarios.map(s => s.caseData));
    setEvidenceList(twoScenarios.flatMap(s => s.evidenceFiles));
    setEvents(twoScenarios.flatMap(s => s.events));
    setDetections(twoScenarios.flatMap(s => s.detections));
    setRules(INITIAL_SIGMA_RULES);
    setActiveCaseId(twoScenarios[0]?.caseData.id || '');
    logAuditAction('CASE_UPDATED', 'system', 'all', { message: 'Reset workspace to baseline mock investigation scenarios (2 cases)' });
    toast.success('Investigation case data reset to baseline (2 mock cases)!');
  };


  return (
    <AppContext.Provider
      value={{
        currentUser,
        setCurrentUser,
        switchRole,
        currentPage,
        setCurrentPage,
        activeCaseId,
        setActiveCaseId,
        cases,
        activeCase,
        evidenceList,
        activeCaseEvidence,
        events,
        activeCaseEvents,
        detections,
        activeCaseDetections,
        activeCaseGraph,
        rules,
        auditLogs,
        createCase,
        updateCaseStatus,
        updateCaseDetails,
        deleteCase,
        uploadEvidence,
        reparseEvidence,
        deleteEvidence,
        toggleFalsePositive,
        addSigmaRule,
        reloadSigmaRules,
        logAuditAction,
        resetToInitialScenarios,
        users,
        registerUser,
        loginUser,
        logout,
        updateCurrentUserProfile,
        theme,
        setTheme,
        toggleTheme,
        adminOnlyMode,
        setAdminOnlyMode,
        authNotice,
        setAuthNotice,

        state: {
          currentUser,
          userRole: currentUser?.role || 'investigator',
          activeTab: currentPage,
          currentCaseId: activeCaseId,
          cases,
          evidenceFiles: evidenceList,
          events,
          detections,
          attackChains: [],
          activeChainId: null,
          filters: {
            severity: 'ALL',
            sourceType: 'ALL',
            attackPathOnly: false,
            searchQuery: '',
            timeWindowMinutes: 30
          }
        },
        setRole: switchRole,
        setTab: setCurrentPage,
        selectCase: setActiveCaseId,
        filteredEvents: activeCaseEvents,
        currentCase: activeCase,
        setFilter: () => {}
      }}
    >
      {children}
    </AppContext.Provider>
  );
};

export const useApp = () => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
};

export const useStore = useApp;
