export type Case = {
  id: string;
  case_id: string;
  title: string;
  description: string;
  status: string;
  created_by: string;
  created_at: string;
  updated_at: string;
};

export type Playbook = {
  id: number;
  name: string;
  incident_type: string;
  description: string;
  steps: {
    id: number;
    order_index: number;
    phase: string;
    title: string;
    guidance: string;
    recommended_action: string;
  }[];
};

export type Task = {
  id: number;
  case_id: string;
  playbook_step_id: number | null;
  phase: string;
  title: string;
  guidance: string;
  recommended_action: string;
  status: string;
  owner: string;
  linked_event_id: number | null;
  linked_ioc_id: number | null;
  completed_at: string | null;
  created_at: string;
};

export type IOC = {
  id: number;
  case_id: string;
  ioc_type: string;
  value: string;
  status: string;
  severity: string;
  notes: string;
  recommended_response: string;
  created_at: string;
};

export type Technique = {
  id: number;
  case_id: string;
  mitre_id: string;
  name: string;
  tactic: string;
  confidence: number;
  evidence_summary: string;
  linked_event_id: number | null;
  created_at: string;
};

export type TimelineEvent = {
  id: number;
  case_id: string;
  timestamp: string;
  source: string;
  host: string;
  user: string;
  summary: string;
  severity: string;
  is_suspicious: boolean;
};

export type PhaseProgress = {
  phase: string;
  total: number;
  done: number;
  percent: number;
};

export type ResponseSummary = {
  case: Case;
  phase_progress: PhaseProgress[];
  open_tasks: number;
  completed_tasks: number;
  ioc_counts: Record<string, number>;
  technique_count: number;
  next_actions: Task[];
  narrative: string;
};

export type AuditLog = {
  id: number;
  case_id: string;
  actor: string;
  action: string;
  detail: string;
  created_at: string;
};

const API = import.meta.env.VITE_API_URL || "/api";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    headers: { "Content-Type": "application/json", ...(options?.headers || {}) },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  if (res.status === 204) return undefined as T;
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) return res.json();
  return (await res.text()) as T;
}

export const api = {
  listCases: () => request<Case[]>("/cases"),
  nextCaseId: () => request<{ case_id: string }>("/cases/next-id"),
  createCase: (body: { title: string; case_id: string; description?: string; created_by?: string }) =>
    request<Case>("/cases", { method: "POST", body: JSON.stringify(body) }),
  getCase: (id: string) => request<Case>(`/cases/${id}`),
  updateCase: (id: string, body: Partial<Case>) =>
    request<Case>(`/cases/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteCase: (id: string) => request<void>(`/cases/${id}`, { method: "DELETE" }),
  listTimeline: (id: string) => request<TimelineEvent[]>(`/cases/${id}/timeline`),
  createTimeline: (
    caseId: string,
    body: {
      timestamp: string;
      source?: string;
      host?: string;
      user?: string;
      summary: string;
      severity?: string;
      is_suspicious?: boolean;
    },
  ) =>
    request<TimelineEvent>(`/cases/${caseId}/timeline`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  listPlaybooks: () => request<Playbook[]>("/playbooks"),
  applyPlaybook: (caseId: string, playbook_id: number, owner = "analyst") =>
    request<Task[]>(`/cases/${caseId}/apply-playbook`, {
      method: "POST",
      body: JSON.stringify({ playbook_id, owner }),
    }),
  listTasks: (id: string) => request<Task[]>(`/cases/${id}/tasks`),
  updateTask: (caseId: string, taskId: number, body: Partial<Task>) =>
    request<Task>(`/cases/${caseId}/tasks/${taskId}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  createTask: (caseId: string, body: Partial<Task>) =>
    request<Task>(`/cases/${caseId}/tasks`, { method: "POST", body: JSON.stringify(body) }),
  listIocs: (id: string) => request<IOC[]>(`/cases/${id}/iocs`),
  createIoc: (caseId: string, body: Partial<IOC>) =>
    request<IOC>(`/cases/${caseId}/iocs`, { method: "POST", body: JSON.stringify(body) }),
  updateIoc: (caseId: string, iocId: number, body: Partial<IOC>) =>
    request<IOC>(`/cases/${caseId}/iocs/${iocId}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  listTechniques: (id: string) => request<Technique[]>(`/cases/${id}/techniques`),
  createTechnique: (caseId: string, body: Partial<Technique>) =>
    request<Technique>(`/cases/${caseId}/techniques`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  responseSummary: (id: string) => request<ResponseSummary>(`/cases/${id}/response-summary`),
  listAudit: (id: string) => request<AuditLog[]>(`/cases/${id}/audit`),
  irHandoffUrl: (id: string) => `${API}/cases/${id}/reports/ir-handoff`,
};
