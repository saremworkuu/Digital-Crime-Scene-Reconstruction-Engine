import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import type { Case } from "../api";

const CASE_ID_RE = /^[A-Z]{2,8}-\d{4}-\d{3,6}$/;
/** Letters only (spaces between words OK); at least 2 letters total */
const TITLE_RE = /^[A-Za-z]+(?:\s+[A-Za-z]+)*$/;

function titleLetterCount(value: string): number {
  return (value.match(/[A-Za-z]/g) || []).join("").length;
}

export default function CasesPage() {
  const [cases, setCases] = useState<Case[]>([]);
  const [error, setError] = useState("");
  const [caseId, setCaseId] = useState("");
  const [title, setTitle] = useState("");
  const [titleError, setTitleError] = useState("");
  const [busy, setBusy] = useState(false);
  const [dangerOpen, setDangerOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<Case | null>(null);
  const [confirmId, setConfirmId] = useState("");
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteMsg, setDeleteMsg] = useState("");

  const closedCases = cases.filter((c) => c.status === "closed");

  async function load() {
    try {
      setCases(await api.listCases());
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load cases");
    }
  }

  async function loadSuggestedId() {
    try {
      const { case_id } = await api.nextCaseId();
      setCaseId(case_id);
    } catch {
      /* optional */
    }
  }

  useEffect(() => {
    load();
    loadSuggestedId();
  }, []);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    const normalized = caseId.trim().toUpperCase();
    const cleanedTitle = title.trim().replace(/\s+/g, " ");
    if (!CASE_ID_RE.test(normalized)) {
      setError("Case ID must look like INC-2026-0042 (PREFIX-YEAR-NUMBER)");
      return;
    }
    if (!TITLE_RE.test(cleanedTitle) || titleLetterCount(cleanedTitle) < 2) {
      setTitleError("Title must be letters only (spaces OK) and at least 2 letters");
      return;
    }
    setTitleError("");
    setBusy(true);
    try {
      await api.createCase({
        case_id: normalized,
        title: cleanedTitle,
        description: "Investigation opened from IR workspace",
      });
      setTitle("");
      await load();
      await loadSuggestedId();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Create failed");
    } finally {
      setBusy(false);
    }
  }

  async function onDeleteClosed() {
    if (!deleteTarget) return;
    if (confirmId.trim().toUpperCase() !== deleteTarget.case_id) {
      setDeleteMsg(`Type ${deleteTarget.case_id} exactly to confirm`);
      return;
    }
    setDeleteBusy(true);
    setDeleteMsg("");
    try {
      await api.deleteCase(deleteTarget.id);
      setDeleteMsg(`Deleted ${deleteTarget.case_id}`);
      setDeleteTarget(null);
      setConfirmId("");
      await load();
    } catch (err) {
      setDeleteMsg(err instanceof Error ? err.message : "Delete failed");
    } finally {
      setDeleteBusy(false);
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <div className="brand">
            support<span>4</span>IR
          </div>
          <div className="brand-sub">Incident Response & Investigation Support</div>
        </div>
      </header>

      <div className="grid-2">
        <section className="panel">
          <h2>Open investigations</h2>
          <p className="muted">
            Cases track IR lifecycle: identify → contain → eradicate → recover → lessons.
          </p>
          {error && <p className="error">{error}</p>}
          <div className="case-list">
            {cases.length === 0 && <p className="muted">No cases yet. Create one to start.</p>}
            {cases.map((c) => (
              <Link key={c.id} to={`/cases/${c.id}`} className="case-row">
                <div>
                  <div>
                    <span className="mono">{c.case_id}</span> {c.title}
                  </div>
                  <div className="muted mono" style={{ fontSize: "0.8rem" }}>
                    opened {new Date(c.created_at).toLocaleString()}
                  </div>
                </div>
                <div className="row-actions">
                  <span className="badge">{c.status}</span>
                </div>
              </Link>
            ))}
          </div>
        </section>

        <section className="panel">
          <h2>New investigation</h2>
          <form onSubmit={onCreate}>
            <div className="field">
              <label>Case ID</label>
              <input
                className="mono"
                value={caseId}
                onChange={(e) => setCaseId(e.target.value.toUpperCase())}
                placeholder="INC-2026-0042"
                required
              />
              <span className="muted" style={{ fontSize: "0.8rem" }}>
                Format: PREFIX-YEAR-NUMBER (e.g. INC-2026-0042). Suggested ID is prefilled.
              </span>
            </div>
            <div className="field">
              <label>Title</label>
              <input
                value={title}
                onChange={(e) => {
                  setTitle(e.target.value);
                  setTitleError("");
                }}
                placeholder="e.g. Suspected Account Takeover"
                pattern="[A-Za-z]+(\s+[A-Za-z]+)*"
                minLength={2}
                title="Letters only, at least 2 letters"
                required
              />
              <span className="muted" style={{ fontSize: "0.8rem" }}>
                Letters only (spaces between words OK). At least 2 letters — no digits or symbols.
              </span>
              {titleError && <p className="error">{titleError}</p>}
            </div>
            <button className="btn btn-primary" type="submit" disabled={busy}>
              {busy ? "Creating…" : "Create case"}
            </button>
          </form>
        </section>
      </div>

      <section className="panel danger-zone">
        <button
          type="button"
          className="danger-zone-toggle"
          onClick={() => setDangerOpen((o) => !o)}
          aria-expanded={dangerOpen}
        >
          <h2>Danger zone</h2>
          <span className="muted">{dangerOpen ? "Hide" : "Show"} settings</span>
        </button>
        {dangerOpen && (
          <div className="danger-zone-body">
            <p className="muted">
              Permanently delete <strong>closed</strong> investigations. Open or in-progress cases
              cannot be removed — set status to <span className="mono">closed</span> first.
            </p>
            {closedCases.length === 0 ? (
              <p className="muted">No finished (closed) investigations to delete.</p>
            ) : (
              <ul className="danger-list">
                {closedCases.map((c) => (
                  <li key={c.id}>
                    <div>
                      <span className="mono">{c.case_id}</span> {c.title}
                      <div className="muted mono" style={{ fontSize: "0.8rem" }}>
                        closed
                      </div>
                    </div>
                    <button
                      type="button"
                      className="btn btn-sm btn-danger"
                      onClick={() => {
                        setDeleteTarget(c);
                        setConfirmId("");
                        setDeleteMsg("");
                      }}
                    >
                      Delete
                    </button>
                  </li>
                ))}
              </ul>
            )}
            {deleteTarget && (
              <div className="danger-confirm">
                <p>
                  Delete <span className="mono">{deleteTarget.case_id}</span> —{" "}
                  {deleteTarget.title}? This removes timeline, IOCs, tasks, and audit history.
                </p>
                <div className="field">
                  <label>
                    Type <span className="mono">{deleteTarget.case_id}</span> to confirm
                  </label>
                  <input
                    className="mono"
                    value={confirmId}
                    onChange={(e) => setConfirmId(e.target.value.toUpperCase())}
                    placeholder={deleteTarget.case_id}
                    autoFocus
                  />
                </div>
                <div className="header-actions">
                  <button
                    type="button"
                    className="btn btn-danger"
                    disabled={deleteBusy || confirmId.trim().toUpperCase() !== deleteTarget.case_id}
                    onClick={onDeleteClosed}
                  >
                    {deleteBusy ? "Deleting…" : "Permanently delete"}
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => {
                      setDeleteTarget(null);
                      setConfirmId("");
                      setDeleteMsg("");
                    }}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
            {deleteMsg && <p className={deleteMsg.startsWith("Deleted") ? "muted" : "error"}>{deleteMsg}</p>}
          </div>
        )}
      </section>
    </div>
  );
}
