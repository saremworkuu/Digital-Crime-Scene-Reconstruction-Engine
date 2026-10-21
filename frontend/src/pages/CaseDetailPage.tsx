import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import type {
  AuditLog,
  Case,
  IOC,
  Playbook,
  ResponseSummary,
  Task,
  Technique,
  TimelineEvent,
} from "../api";
import {
  IOC_HINTS,
  IOC_PLACEHOLDERS,
  IOC_STATUS,
  IOC_TYPES,
  MITRE_CATALOG,
  validateIocValue,
  type IocType,
} from "../iocUtils";

type Tab = "response" | "timeline" | "iocs" | "techniques" | "audit";

const PHASES = ["identify", "contain", "eradicate", "recover", "lessons"];

function formatDelta(prev: string | null, curr: string): string {
  if (!prev) return "T+0";
  const ms = new Date(curr).getTime() - new Date(prev).getTime();
  if (Number.isNaN(ms) || ms < 0) return "";
  const mins = Math.round(ms / 60000);
  if (mins < 60) return `+${mins}m`;
  const hrs = Math.round(mins / 60);
  if (hrs < 48) return `+${hrs}h`;
  return `+${Math.round(hrs / 24)}d`;
}

function toLocalInputValue(d = new Date()): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export default function CaseDetailPage() {
  const { id } = useParams();
  const caseId = id || "";

  const [tab, setTab] = useState<Tab>("response");
  const [caseData, setCaseData] = useState<Case | null>(null);
  const [summary, setSummary] = useState<ResponseSummary | null>(null);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<number | "">("");
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [techniques, setTechniques] = useState<Technique[]>([]);
  const [audit, setAudit] = useState<AuditLog[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const [iocType, setIocType] = useState<IocType>("ip");
  const [iocValue, setIocValue] = useState("");
  const [iocFormError, setIocFormError] = useState("");

  const [mitreId, setMitreId] = useState("");
  const [mitreName, setMitreName] = useState("");
  const [mitreTactic, setMitreTactic] = useState("");

  const [tlSummary, setTlSummary] = useState("");
  const [tlSource, setTlSource] = useState("manual");
  const [tlHost, setTlHost] = useState("");
  const [tlUser, setTlUser] = useState("");
  const [tlSeverity, setTlSeverity] = useState("medium");
  const [tlSuspicious, setTlSuspicious] = useState(true);
  const [tlWhen, setTlWhen] = useState(toLocalInputValue());
  const [tlFilter, setTlFilter] = useState<"all" | "suspicious">("all");

  const refresh = useCallback(async () => {
    if (!caseId) return;
    try {
      const [c, s, t, p, tl, i, tech, a] = await Promise.all([
        api.getCase(caseId),
        api.responseSummary(caseId),
        api.listTasks(caseId),
        api.listPlaybooks(),
        api.listTimeline(caseId),
        api.listIocs(caseId),
        api.listTechniques(caseId),
        api.listAudit(caseId),
      ]);
      setCaseData(c);
      setSummary(s);
      setTasks(t);
      setPlaybooks(p);
      setTimeline(tl);
      setIocs(i);
      setTechniques(tech);
      setAudit(a);
      setSelectedPlaybook((prev) => {
        if (prev !== "" || !p.length) return prev;
        return p[0].id;
      });
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load case");
    }
  }, [caseId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const filteredTimeline = useMemo(() => {
    if (tlFilter === "suspicious") return timeline.filter((e) => e.is_suspicious);
    return timeline;
  }, [timeline, tlFilter]);

  async function applyPlaybook() {
    if (!selectedPlaybook) return;
    setBusy(true);
    try {
      await api.applyPlaybook(caseId, Number(selectedPlaybook), "analyst");
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Playbook apply failed");
    } finally {
      setBusy(false);
    }
  }

  async function setTaskStatus(task: Task, status: string) {
    await api.updateTask(caseId, task.id, { status });
    await refresh();
  }

  async function setCaseStatus(status: string) {
    await api.updateCase(caseId, { status });
    await refresh();
  }

  async function addIoc(e: FormEvent) {
    e.preventDefault();
    const err = validateIocValue(iocType, iocValue);
    if (err) {
      setIocFormError(err);
      return;
    }
    setIocFormError("");
    try {
      await api.createIoc(caseId, {
        ioc_type: iocType,
        value: iocValue.trim(),
        severity: "high",
        recommended_response: IOC_HINTS[iocType],
      });
      setIocValue("");
      await refresh();
    } catch (ex) {
      setIocFormError(ex instanceof Error ? ex.message : "Failed to add IOC");
    }
  }

  function onMitreIdChange(raw: string) {
    const id = raw.trim().toUpperCase();
    setMitreId(raw);
    const hit = MITRE_CATALOG[id];
    if (hit) {
      setMitreName(hit.name);
      setMitreTactic(hit.tactic);
    }
  }

  async function addTechnique(e: FormEvent) {
    e.preventDefault();
    try {
      await api.createTechnique(caseId, {
        mitre_id: mitreId.trim(),
        name: mitreName.trim(),
        tactic: mitreTactic.trim(),
        confidence: 0.8,
        evidence_summary: "Mapped from investigation timeline",
      });
      setMitreId("");
      setMitreName("");
      setMitreTactic("");
      await refresh();
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : "Failed to add technique");
    }
  }

  async function addTimelineEvent(e: FormEvent) {
    e.preventDefault();
    if (!tlSummary.trim()) return;
    try {
      await api.createTimeline(caseId, {
        timestamp: new Date(tlWhen).toISOString(),
        source: tlSource.trim() || "manual",
        host: tlHost.trim(),
        user: tlUser.trim(),
        summary: tlSummary.trim(),
        severity: tlSeverity,
        is_suspicious: tlSuspicious,
      });
      setTlSummary("");
      setTlHost("");
      setTlUser("");
      setTlWhen(toLocalInputValue());
      await refresh();
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : "Failed to add timeline event");
    }
  }

  if (!caseData) {
    return (
      <div className="app-shell">
        <p className="muted">{error || "Loading case…"}</p>
        <Link to="/">← Back</Link>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <Link to="/" className="muted">
            ← Cases
          </Link>
          <div className="brand" style={{ marginTop: "0.35rem" }}>
            <span className="mono">{caseData.case_id}</span> {caseData.title}
          </div>
          <div className="brand-sub">
            status {caseData.status} · created {new Date(caseData.created_at).toLocaleString()}
          </div>
        </div>
        <div className="header-actions">
          <select
            value={caseData.status}
            onChange={(e) => setCaseStatus(e.target.value)}
            style={{
              background: "var(--bg-elevated)",
              color: "var(--text)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              padding: "0.35rem 0.5rem",
            }}
          >
            {["open", "in_progress", "closed"].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <a className="btn btn-primary" href={api.irHandoffUrl(caseId)} target="_blank" rel="noreferrer">
            Export IR handoff
          </a>
        </div>
      </header>

      {error && <p className="error">{error}</p>}

      <div className="tabs">
        {(
          [
            ["response", "Response"],
            ["timeline", "Timeline"],
            ["iocs", "IOCs"],
            ["techniques", "ATT&CK"],
            ["audit", "Audit"],
          ] as [Tab, string][]
        ).map(([key, label]) => (
          <button
            key={key}
            className={`tab ${tab === key ? "active" : ""}`}
            onClick={() => setTab(key)}
            type="button"
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "response" && summary && (
        <div className="stack">
          <section className="panel">
            <h2>IR phase progress</h2>
            <div className="stat-row">
              <div className="stat">
                Open tasks: <strong>{summary.open_tasks}</strong>
              </div>
              <div className="stat">
                Completed: <strong>{summary.completed_tasks}</strong>
              </div>
              <div className="stat">
                Techniques: <strong>{summary.technique_count}</strong>
              </div>
            </div>
            <div className="phase-bar">
              {summary.phase_progress.map((p) => (
                <div key={p.phase} className="phase-card">
                  <div className="label">{p.phase}</div>
                  <div className="pct">{p.percent}%</div>
                  <div className="muted mono">
                    {p.done}/{p.total}
                  </div>
                  <div className="progress-track">
                    <div className="progress-fill" style={{ width: `${p.percent}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="panel">
            <h2>Apply response playbook</h2>
            <p className="muted">
              Advisory checklists only — tracks containment/eradication work; does not execute
              network actions.
            </p>
            <div className="header-actions">
              <select
                value={selectedPlaybook}
                onChange={(e) => setSelectedPlaybook(Number(e.target.value))}
                style={{
                  background: "var(--bg)",
                  color: "var(--text)",
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  padding: "0.45rem 0.65rem",
                  minWidth: 240,
                }}
              >
                {playbooks.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              <button className="btn btn-primary" type="button" onClick={applyPlaybook} disabled={busy}>
                {busy ? "Applying…" : "Apply playbook"}
              </button>
            </div>
          </section>

          <section className="panel">
            <h2>Response tasks</h2>
            {tasks.length === 0 ? (
              <p className="muted">No tasks yet. Apply a playbook to generate the IR checklist.</p>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th>Phase</th>
                    <th>Task</th>
                    <th>Recommended</th>
                    <th>Status</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {tasks.map((t) => (
                    <tr key={t.id}>
                      <td>
                        <span className="badge">{t.phase}</span>
                      </td>
                      <td>
                        <div>{t.title}</div>
                        <div className="muted">{t.guidance}</div>
                      </td>
                      <td className="mono">{t.recommended_action || "—"}</td>
                      <td>
                        <span className={`badge ${t.status}`}>{t.status}</span>
                      </td>
                      <td>
                        <div className="row-actions">
                          {t.status !== "in_progress" && (
                            <button className="btn btn-sm" type="button" onClick={() => setTaskStatus(t, "in_progress")}>
                              Start
                            </button>
                          )}
                          {t.status !== "done" && (
                            <button className="btn btn-sm btn-primary" type="button" onClick={() => setTaskStatus(t, "done")}>
                              Done
                            </button>
                          )}
                          {t.status !== "skipped" && (
                            <button className="btn btn-sm" type="button" onClick={() => setTaskStatus(t, "skipped")}>
                              Skip
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <div className="grid-2">
            <section className="panel">
              <h3>Next actions</h3>
              {summary.next_actions.length === 0 ? (
                <p className="muted">All response tasks cleared.</p>
              ) : (
                <ul>
                  {summary.next_actions.map((t) => (
                    <li key={t.id}>
                      <span className="badge">{t.phase}</span> {t.title}
                    </li>
                  ))}
                </ul>
              )}
            </section>
            <section className="panel">
              <h3>Investigation narrative</h3>
              <pre className="narrative">{summary.narrative}</pre>
            </section>
          </div>
        </div>
      )}

      {tab === "timeline" && (
        <div className="grid-2">
          <section className="panel">
            <div className="tl-header">
              <h2>Reconstructed timeline</h2>
              <div className="tl-filters">
                <button
                  type="button"
                  className={`btn btn-sm ${tlFilter === "all" ? "btn-primary" : ""}`}
                  onClick={() => setTlFilter("all")}
                >
                  All ({timeline.length})
                </button>
                <button
                  type="button"
                  className={`btn btn-sm ${tlFilter === "suspicious" ? "btn-primary" : ""}`}
                  onClick={() => setTlFilter("suspicious")}
                >
                  Suspicious ({timeline.filter((e) => e.is_suspicious).length})
                </button>
              </div>
            </div>
            {filteredTimeline.length === 0 ? (
              <p className="muted">No events yet. Add evidence below.</p>
            ) : (
              <div className="timeline">
                {filteredTimeline.map((ev, idx) => {
                  const prev = idx > 0 ? filteredTimeline[idx - 1].timestamp : null;
                  return (
                    <div key={ev.id} className={`tl-item ${ev.is_suspicious ? "suspicious" : ""}`}>
                      <div className="tl-meta">
                        <span className="mono muted">{new Date(ev.timestamp).toLocaleString()}</span>
                        <span className="tl-delta mono">{formatDelta(prev, ev.timestamp)}</span>
                        <span className={`badge ${ev.severity}`}>{ev.severity}</span>
                        {ev.is_suspicious && <span className="badge high">suspicious</span>}
                      </div>
                      <div className="tl-summary">{ev.summary}</div>
                      <div className="muted mono">
                        {ev.source}
                        {ev.host ? ` · ${ev.host}` : ""}
                        {ev.user ? ` · ${ev.user}` : ""}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>

          <section className="panel">
            <h2>Add timeline event</h2>
            <form onSubmit={addTimelineEvent}>
              <div className="field">
                <label>When</label>
                <input type="datetime-local" value={tlWhen} onChange={(e) => setTlWhen(e.target.value)} required />
              </div>
              <div className="field">
                <label>Summary</label>
                <input
                  value={tlSummary}
                  onChange={(e) => setTlSummary(e.target.value)}
                  placeholder="What happened"
                  required
                />
              </div>
              <div className="field-row">
                <div className="field">
                  <label>Source</label>
                  <select value={tlSource} onChange={(e) => setTlSource(e.target.value)}>
                    {["manual", "edr", "siem", "proxy", "auth", "mail_gateway", "firewall", "dns"].map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="field">
                  <label>Severity</label>
                  <select value={tlSeverity} onChange={(e) => setTlSeverity(e.target.value)}>
                    {["info", "low", "medium", "high", "critical"].map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="field-row">
                <div className="field">
                  <label>Host</label>
                  <input value={tlHost} onChange={(e) => setTlHost(e.target.value)} placeholder="ws-1042" />
                </div>
                <div className="field">
                  <label>User</label>
                  <input value={tlUser} onChange={(e) => setTlUser(e.target.value)} placeholder="jdoe" />
                </div>
              </div>
              <label className="check-row">
                <input type="checkbox" checked={tlSuspicious} onChange={(e) => setTlSuspicious(e.target.checked)} />
                Mark as suspicious
              </label>
              <button className="btn btn-primary" type="submit">
                Add event
              </button>
            </form>
          </section>
        </div>
      )}

      {tab === "iocs" && (
        <div className="grid-2">
          <section className="panel">
            <h2>Indicators</h2>
            <table className="table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Status / Response</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc) => (
                  <tr key={ioc.id}>
                    <td className="mono">{ioc.ioc_type}</td>
                    <td className="mono">{ioc.value}</td>
                    <td>
                      <div className="ioc-status-cell">
                        <select
                          className={`ioc-status-select ${ioc.status}`}
                          value={ioc.status}
                          onChange={(e) =>
                            api.updateIoc(caseId, ioc.id, { status: e.target.value }).then(refresh)
                          }
                          aria-label={`Status for ${ioc.value}`}
                        >
                          {IOC_STATUS.map((st) => (
                            <option key={st} value={st}>
                              {st}
                            </option>
                          ))}
                        </select>
                        <div className="ioc-hint muted" title={ioc.recommended_response}>
                          {ioc.recommended_response || IOC_HINTS[ioc.ioc_type as IocType] || "—"}
                        </div>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {iocs.length === 0 && <p className="muted">No IOCs yet.</p>}
          </section>
          <section className="panel">
            <h2>Add IOC</h2>
            <form onSubmit={addIoc}>
              <div className="field">
                <label>Type</label>
                <select
                  value={iocType}
                  onChange={(e) => {
                    setIocType(e.target.value as IocType);
                    setIocFormError("");
                  }}
                >
                  {IOC_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </div>
              <div className="field">
                <label>Value</label>
                <input
                  value={iocValue}
                  onChange={(e) => {
                    setIocValue(e.target.value);
                    setIocFormError("");
                  }}
                  placeholder={IOC_PLACEHOLDERS[iocType]}
                  autoComplete="off"
                  spellCheck={false}
                />
                <div className="field-hint muted">
                  Hint: {IOC_HINTS[iocType]} · expects {IOC_PLACEHOLDERS[iocType]}
                </div>
              </div>
              {iocFormError && <p className="error">{iocFormError}</p>}
              <button className="btn btn-primary" type="submit">
                Add IOC
              </button>
            </form>
          </section>
        </div>
      )}

      {tab === "techniques" && (
        <div className="grid-2">
          <section className="panel">
            <h2>ATT&CK technique hits</h2>
            <table className="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Name</th>
                  <th>Tactic</th>
                  <th>Conf.</th>
                </tr>
              </thead>
              <tbody>
                {techniques.map((t) => (
                  <tr key={t.id}>
                    <td className="mono">
                      {t.mitre_id}
                      {t.mitre_id.startsWith("CUSTOM-") && (
                        <span className="badge" style={{ marginLeft: "0.35rem" }}>
                          local
                        </span>
                      )}
                    </td>
                    <td>{t.name}</td>
                    <td>{t.tactic}</td>
                    <td className="mono">{t.confidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {techniques.length === 0 && <p className="muted">No techniques mapped yet.</p>}
          </section>
          <section className="panel">
            <h2>Map technique</h2>
            <form onSubmit={addTechnique}>
              <div className="field">
                <label>MITRE ID</label>
                <input
                  list="mitre-catalog"
                  value={mitreId}
                  onChange={(e) => onMitreIdChange(e.target.value)}
                  placeholder="T1059 or leave blank for CUSTOM-NNN"
                />
                <datalist id="mitre-catalog">
                  {Object.keys(MITRE_CATALOG).map((id) => (
                    <option key={id} value={id} />
                  ))}
                </datalist>
                <div className="field-hint muted">
                  Known IDs autofill name/tactic. Unknown or blank → we assign CUSTOM-001, CUSTOM-002, …
                </div>
              </div>
              <div className="field">
                <label>Name</label>
                <input
                  value={mitreName}
                  onChange={(e) => setMitreName(e.target.value)}
                  placeholder="Technique name"
                />
              </div>
              <div className="field">
                <label>Tactic</label>
                <input
                  value={mitreTactic}
                  onChange={(e) => setMitreTactic(e.target.value)}
                  placeholder="Execution, Persistence, …"
                />
              </div>
              <button className="btn btn-primary" type="submit">
                Add technique
              </button>
            </form>
            <p className="muted" style={{ marginTop: "0.75rem" }}>
              Suggested phases for current work: {PHASES.join(" → ")}
            </p>
          </section>
        </div>
      )}

      {tab === "audit" && (
        <section className="panel">
          <h2>Investigation audit trail</h2>
          <table className="table">
            <thead>
              <tr>
                <th>When</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {audit.map((a) => (
                <tr key={a.id}>
                  <td className="mono muted">{new Date(a.created_at).toLocaleString()}</td>
                  <td>{a.actor}</td>
                  <td className="mono">{a.action}</td>
                  <td>{a.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
