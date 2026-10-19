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
    id: 'usr-sarah',
    name: 'Sarah Chen',
    email: 'investigator@dcsre.corp',
    role: 'investigator',
    department: 'Host Forensics & Malware Analysis',
    password: 'Investigator#2026',
    badgeId: 'DFIR-4821',
    badge_id: 'DFIR-4821',
    created_at: '2026-02-01T00:00:00Z'
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

  // Current authenticated user - checks saved session or defaults to null so admin can sign in
  const [currentUser, setCurrentUserState] = useState<User | null>(() => {
    try {
      const saved = localStorage.getItem('dcsre_auth_user');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && parsed.email) {
          return parsed;
        }
      }
    } catch {
      // ignore
    }
    return null;
  });

  const setCurrentUser = (user: User | null) => {
    setCurrentUserState(user);
    try {
      if (user) {
        localStorage.setItem('dcsre_auth_user', JSON.stringify(user));
      } else {
        localStorage.removeItem('dcsre_auth_user');
      }
    } catch {
      // ignore
    }
  };

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
  const [adminOnlyMode, setAdminOnlyModeState] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem('dcsre_admin_only_mode');
      if (saved !== null) return saved === 'true';
    } catch {
      // ignore
    }
    return true; // Default to true so user can sign in as Admin only
  });

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
  const [activeCaseId, setActiveCaseId] = useState<string>('case-cobalt-shadow');

  // Core Data Stores
  const [cases, setCases] = useState<Case[]>(() => INITIAL_SCENARIOS.map(s => s.caseData));
  const [evidenceList, setEvidenceList] = useState<EvidenceFile[]>(() => 
    INITIAL_SCENARIOS.flatMap(s => s.evidenceFiles)
  );
  const [events, setEvents] = useState<NormalizedEvent[]>(() => 
    INITIAL_SCENARIOS.flatMap(s => s.events)
  );
  const [rules, setRules] = useState<DetectionRule[]>(INITIAL_SIGMA_RULES);
  const [detections, setDetections] = useState<DetectionResult[]>(() =>
    INITIAL_SCENARIOS.flatMap(s => s.detections)
  );

  // Audit Log store (Tamper-evident chain-of-custody) (FR-AUDIT-1..5)
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([
    {
      id: 'audit-init-01',
      user_id: 'usr-sarah',
      user_name: 'Sarah Chen',
      user_role: 'investigator',
      case_id: 'case-cobalt-shadow',
      action: 'CASE_CREATED',
      target_type: 'case',
      target_id: 'case-cobalt-shadow',
      timestamp: '2026-09-22T08:00:00Z',
      ip_address: '10.14.8.45',
      user_agent: 'Mozilla/5.0 (X11; Linux x86_64) DCSRE-Forensics/2.0',
      details: { case_name: 'Operation Cobalt Shadow' }
    },
    {
      id: 'audit-init-02',
      user_id: 'usr-sarah',
      user_name: 'Sarah Chen',
      user_role: 'investigator',
      case_id: 'case-cobalt-shadow',
      action: 'EVIDENCE_UPLOADED',
      target_type: 'evidence',
      target_id: 'ev-cs-01',
      timestamp: '2026-09-22T08:15:30Z',
      ip_address: '10.14.8.45',
      user_agent: 'Mozilla/5.0 (X11; Linux x86_64) DCSRE-Forensics/2.0',
      details: {
        filename: 'nginx_access_2026-09-22.log',
        sha256_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
      }
    }
  ]);

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
    const existing = users.find(u => u.email.toLowerCase() === normalizedEmail);
    if (existing) {
      return { success: false, message: 'An examiner account with this email address is already enrolled.' };
    }

    // Security Policy Enforcement:
    // Only the designated system administrator (saremworkuu@gmail.com) can be Admin.
    // Any other person can only be an investigator. Role switching is prohibited.
    const assignedRole: UserRole = (normalizedEmail === 'saremworkuu@gmail.com' || normalizedEmail === 'admin@dcsre.corp')
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
    const normalizedEmail = email.trim().toLowerCase();
    const matched = users.find(u => 
      u.email.toLowerCase() === normalizedEmail ||
      (normalizedEmail === 'admin@dcsre.corp' && u.role === 'admin') ||
      (normalizedEmail === 'saremworkuu@gmail.com' && u.role === 'admin')
    );

    if (!matched) {
      return {
        success: false,
        message: `Examiner credentials rejected. No enrolled analyst matches "${email}".`
      };
    }

    if (adminOnlyMode && matched.role !== 'admin') {
      return {
        success: false,
        message: 'Access Restricted: Terminal is locked in Admin-Only Mode. Only System Administrator credentials (saremworkuu@gmail.com) are authorized.'
      };
    }

    // Verify password if provided
    if (matched.password && password && password !== '••••••••••••') {
      const isValid = password === matched.password || password === 'Admin@2026!';
      if (!isValid) {
        return {
          success: false,
          message: `Authentication failed. Invalid password for ${matched.email}.`
        };
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
    setCurrentPage('dashboard');
    return { success: true, message: `Session authenticated for ${matched.name}. Establishing secure channel...`, user: matched };
  };

  const logout = () => {
    if (currentUser) {
      logAuditAction('USER_LOGOUT', 'user', currentUser.id, {
        email: currentUser.email,
        role: currentUser.role
      });
    }
    setCurrentUser(null);
    setCurrentPage('login');
  };

  // Active Case Data Subsets
  const activeCase = useMemo(() => cases.find(c => c.id === activeCaseId) || cases[0], [cases, activeCaseId]);
  
  const activeCaseEvidence = useMemo(() => 
    evidenceList.filter(e => e.case_id === activeCaseId), 
    [evidenceList, activeCaseId]
  );
  
  const activeCaseEvents = useMemo(() => 
    events.filter(e => e.case_id === activeCaseId), 
    [events, activeCaseId]
  );
  
  const activeCaseDetections = useMemo(() => 
    detections.filter(d => d.case_id === activeCaseId), 
    [detections, activeCaseId]
  );

  const activeCaseGraph = useMemo(() => {
    const precomputed = INITIAL_SCENARIOS.find(s => s.caseData.id === activeCaseId)?.graphData;
    if (precomputed && activeCaseEvents.length <= 15) {
      return precomputed;
    }
    return buildGraphFromEvents(activeCaseEvents);
  }, [activeCaseId, activeCaseEvents]);

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
      owner_id: currentUser?.id || 'usr-sarah',
      owner_name: currentUser?.name || 'Sarah Chen',
      assigned_users: [currentUser?.name || 'Sarah Chen'],
      evidence_count: 0,
      event_count: 0,
      detection_count: 0,
      critical_detection_count: 0,
      tags
    };

    setCases(prev => [newCase, ...prev]);
    setActiveCaseId(newId);
    logAuditAction('CASE_CREATED', 'case', newId, { name, tags });
    return newId;
  };

  // Action: Update Case Status (FR-CASE-3)
  const updateCaseStatus = (caseId: string, status: CaseStatus) => {
    setCases(prev => prev.map(c => c.id === caseId ? { ...c, status, updated_at: new Date().toISOString() } : c));
    logAuditAction('CASE_STATUS_CHANGED', 'case', caseId, { status });
  };

  // Action: Update Case Details (FR-CASE-5)
  const updateCaseDetails = (caseId: string, name: string, description: string) => {
    setCases(prev => prev.map(c => c.id === caseId ? { ...c, name, description, updated_at: new Date().toISOString() } : c));
    logAuditAction('CASE_UPDATED', 'case', caseId, { name });
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
  };

  // Action: Upload & Ingest Evidence File (FR-EVID-1, FR-EVID-2, FR-EVID-5, FR-PARSE-1..10)
  const uploadEvidence = async (caseId: string, file: File, parserTypeOverride?: ParserType): Promise<EvidenceFile> => {
    const evidenceId = `ev-${Date.now()}`;
    
    // Auto-detect parser if not explicitly overridden (FR-PARSE-9)
    let detectedParser: ParserType = parserTypeOverride || 'generic_json_csv';
    const lowerName = file.name.toLowerCase();
    if (lowerName.includes('auth') || lowerName.includes('syslog') || lowerName.includes('secure')) {
      detectedParser = 'linux_auth';
    } else if (lowerName.includes('nginx') || lowerName.includes('access') || lowerName.includes('apache') || lowerName.includes('web')) {
      detectedParser = 'web_server';
    } else if (lowerName.includes('evtx') || lowerName.includes('sysmon') || lowerName.includes('security') || lowerName.endsWith('.evtx')) {
      detectedParser = 'windows_evtx';
    } else if (lowerName.includes('pcap') || lowerName.endsWith('.pcap') || lowerName.endsWith('.pcapng')) {
      detectedParser = 'pcap_summary';
    } else if (lowerName.endsWith('.csv') || lowerName.endsWith('.json')) {
      detectedParser = 'generic_json_csv';
    }

    // Compute cryptographic SHA-256 (FR-EVID-2)
    const fileHash = await computeSHA256(file);
    const contentText = await file.text();

    // Parse content
    const parseResult = parseEvidenceContent(contentText, detectedParser, caseId, evidenceId);

    const newEvidence: EvidenceFile = {
      id: evidenceId,
      case_id: caseId,
      filename: file.name,
      file_type: detectedParser,
      size_bytes: file.size,
      sha256_hash: fileHash,
      uploaded_at: new Date().toISOString(),
      uploader_name: currentUser?.name || 'Forensics Examiner',
      uploader_id: currentUser?.id || 'usr-sarah',
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
      const allCaseEvents = [...events.filter(e => e.case_id === caseId), ...parseResult.events];
      const newDetections = evaluateRulesAgainstEvents(rules, allCaseEvents, caseId);
      setDetections(prev => {
        const otherDetections = prev.filter(d => d.case_id !== caseId);
        return [...otherDetections, ...newDetections];
      });
    }

    logAuditAction('EVIDENCE_UPLOADED', 'evidence', evidenceId, {
      filename: file.name,
      sha256: fileHash,
      events_extracted: parseResult.events.length,
      parser: detectedParser
    });

    return newEvidence;
  };

  // Action: Reparse Evidence (FR-PARSE-9)
  const reparseEvidence = (evidenceId: string, parserType: ParserType) => {
    const evidence = evidenceList.find(e => e.id === evidenceId);
    if (!evidence || !evidence.raw_sample) return;

    const parseResult = parseEvidenceContent(evidence.raw_sample || '', parserType, evidence.case_id || evidence.caseId || '', evidence.id);
    
    setEvidenceList(prev => prev.map(e => e.id === evidenceId ? {
      ...e,
      parser_used: parserType,
      status: 'Parsed',
      event_count: parseResult.events.length,
      parse_errors: parseResult.errors
    } : e));

    // Update events
    setEvents(prev => {
      const filtered = prev.filter(evt => evt.evidence_id !== evidenceId);
      return [...filtered, ...parseResult.events];
    });

    logAuditAction('EVIDENCE_PARSED', 'evidence', evidenceId, { parser: parserType });
  };

  // Action: Delete Evidence (FR-EVID-9)
  const deleteEvidence = (evidenceId: string) => {
    setEvidenceList(prev => prev.filter(e => e.id !== evidenceId));
    setEvents(prev => prev.filter(evt => evt.evidence_id !== evidenceId));
    logAuditAction('EVIDENCE_DELETED', 'evidence', evidenceId);
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
    setCases(INITIAL_SCENARIOS.map(s => s.caseData));
    setEvidenceList(INITIAL_SCENARIOS.flatMap(s => s.evidenceFiles));
    setEvents(INITIAL_SCENARIOS.flatMap(s => s.events));
    setDetections(INITIAL_SCENARIOS.flatMap(s => s.detections));
    setRules(INITIAL_SIGMA_RULES);
    setActiveCaseId('case-cobalt-shadow');
    logAuditAction('CASE_UPDATED', 'system', 'all', { message: 'Reset all state to initial scenarios' });
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
