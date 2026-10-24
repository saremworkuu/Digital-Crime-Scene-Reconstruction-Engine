"""
DCSRE Forensic Report Generator (Stage 8)

C2 fixes:
- Report marked DRAFT until human approval.
- SHA-256 is computed over the report's own content (excluding the hash line itself).
- Chain of custody is computed from evidence facts, not boilerplate.
- Section 6 remediation directives are generated from findings, with finding IDs cited.
- No NIST SP 800-86 compliance claim.
- If a section has no data, says "None identified".
- Methodology and Limitations section added.
- Attack sequence ordered by event_time grouped by tactic.

B1 fix:
- adversary_infrastructure is only addresses confirmed by findings (actor_role /
  target_role), not any non-RFC1918 address.
"""
import hashlib
import html
import json
import uuid
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Dict, List, Optional

from .report_fixes import (
    dedupe_detections,
    build_ip_host_map,
    resolve_hosts,
    unique_users,
    norm_user,
    merge_timeline,
    hash_status,
    esc,
    build_executive_summary,
    tactic_for_tracked,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _compute_report_hash(report_dict: Dict[str, Any]) -> str:
    """SHA-256 over the serialised report, excluding the hash field itself."""
    scratch = {k: v for k, v in report_dict.items() if k != "report_hash"}
    canonical = json.dumps(scratch, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _is_private(ip: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(ip.strip())
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Main report builder
# ---------------------------------------------------------------------------

def generate_forensic_report_data(
    case_dict: Dict[str, Any],
    evidence_list: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    detections: List[Dict[str, Any]],
    generator_user: Any = None,
    audit_entries: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Synthesizes case metadata, evidence ledger, timeline, and MITRE detections
    into a formal forensic reconstruction report.
    """
    case_id = str(case_dict.get("id", ""))
    case_name = case_dict.get("name", "Untitled Incident")
    now_iso = _now_iso()
    tactic_warnings: List[str] = []
    detections = dedupe_detections(detections, warnings=tactic_warnings)
    ip_map = build_ip_host_map(events)

    gen_name = (
        getattr(generator_user, "name", None)
        or getattr(generator_user, "username", "Lead Forensics Investigator")
    )
    gen_role = getattr(generator_user, "role", "investigator")
    if hasattr(gen_role, "value"):
        gen_role = gen_role.value

    # ------------------------------------------------------------------
    # B1: Determine compromised / adversary entities from *findings* only
    # ------------------------------------------------------------------
    compromised_hosts: set = set()
    compromised_users: set = set()
    adversary_infra: set = set()   # Only addresses confirmed by role classification

    for finding in detections:
        # Use the role fields set by detection_engine._determine_roles
        actor = finding.get("actor")
        actor_role = finding.get("actor_role")
        target = finding.get("target_host")
        target_role = finding.get("target_role")
        user = finding.get("user")

        if actor_role == "adversary_infrastructure" and actor:
            adversary_infra.add(actor)
        if target_role == "compromised_host" and target:
            compromised_hosts.add(target)
        if actor_role == "compromised_account" or finding.get("mitre_tactic") in (
            "Execution", "Privilege Escalation", "Persistence",
            "Defense Evasion", "Exfiltration"
        ):
            if user and user not in ("unknown", "SYSTEM", "-"):
                compromised_users.add(user)

    # Fallback: if no role-tagged findings, derive from events (less precise)
    if not compromised_hosts and not adversary_infra:
        for ev in events:
            is_attack = ev.get("is_attack_path") or str(ev.get("severity", "")).lower() in ("critical", "high")
            if is_attack:
                host = ev.get("host")
                src_ip = ev.get("src_ip")
                if host and host != "unknown_host":
                    compromised_hosts.add(host)
                # External sources only become adversary if they're the *actor*
                # in a specific attack tactic — we can't determine this from raw
                # events without tactic context, so we leave adversary_infra empty.
                _ = src_ip  # intentionally not used

    compromised_hosts = set(resolve_hosts(compromised_hosts, ip_map))

    # Sort attack timeline events by event_time (A4 fix: timestamp is event_time)
    attack_events = merge_timeline(
        [ev for ev in events if ev.get("is_attack_path") or str(ev.get("severity", "")).lower() in ("critical", "high")],
        ip_map=ip_map,
    )

    # Group findings by tactic for attack sequence
    findings_by_tactic: Dict[str, List] = {}
    for f in sorted(detections, key=lambda x: str(x.get("first_seen", ""))):
        tactic = f.get("mitre_tactic", "Unknown")
        findings_by_tactic.setdefault(tactic, []).append(f)

    # Compute dwell time
    dwell_time_str = "Not determinable"
    if len(attack_events) >= 2:
        try:
            t0 = datetime.fromisoformat(str(attack_events[0]["timestamp"]).replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(str(attack_events[-1]["timestamp"]).replace("Z", "+00:00"))
            delta_mins = int((t1 - t0).total_seconds() / 60)
            dwell_time_str = f"{delta_mins} minutes" if delta_mins < 60 else f"{delta_mins / 60:.1f} hours"
        except Exception:
            pass

    # ------------------------------------------------------------------
    # C2: Computed chain of custody
    # ------------------------------------------------------------------
    chain_of_custody: List[Dict[str, Any]] = []
    for ev in evidence_list:
        stored_hash = ev.get("sha256_hash", "")
        chain_of_custody.append({
            "filename": ev.get("filename"),
            "sha256_hash": stored_hash,
            "hash_status": hash_status(ev),
            "uploaded_by": ev.get("uploader_name", "Unknown"),
            "uploaded_at": ev.get("uploaded_at"),
            "ingested_at": ev.get("ingested_at"),
            "event_count": ev.get("event_count", 0),
        })

    audit_count = len(audit_entries) if audit_entries else "N/A"

    # ------------------------------------------------------------------
    # C2: Generated remediation from findings (no boilerplate)
    # ------------------------------------------------------------------
    remediation: List[Dict[str, str]] = []

    if adversary_infra:
        finding_ids = [
            f.get("id", "") for f in detections
            if f.get("actor_role") == "adversary_infrastructure" or f.get("actor") in adversary_infra
        ]
        finding_ids = [fid for fid in finding_ids if fid]
        remediation.append({
            "action": f"Block adversary infrastructure at perimeter: {', '.join(sorted(adversary_infra))}",
            "finding_refs": ", ".join(finding_ids[:5]),
        })

    if compromised_hosts:
        finding_ids = [
            f.get("id", "") for f in detections if f.get("target_role") == "compromised_host"
        ]
        finding_ids = [fid for fid in finding_ids if fid]
        remediation.append({
            "action": f"Isolate and reimagine compromised hosts: {', '.join(sorted(compromised_hosts))}",
            "finding_refs": ", ".join(finding_ids[:5]),
        })

    if compromised_users:
        norm_comp_users = {norm_user(u) for u in compromised_users if norm_user(u)}
        finding_ids = [
            f.get("id", "") for f in detections
            if norm_user(f.get("user")) in norm_comp_users or f.get("actor_role") == "compromised_account"
        ]
        finding_ids = [fid for fid in finding_ids if fid]
        remediation.append({
            "action": f"Disable and reset compromised accounts: {', '.join(unique_users(compromised_users))}",
            "finding_refs": ", ".join(finding_ids[:5]),
        })

    # Tactic-specific remediations
    tactics_seen = {f.get("mitre_tactic") for f in detections}
    if "Persistence" in tactics_seen:
        persist_ids = [f.get("id", "") for f in detections if f.get("mitre_tactic") == "Persistence"]
        persist_ids = [fid for fid in persist_ids if fid]
        remediation.append({
            "action": "Audit and remove persistence mechanisms: crontabs, authorized_keys, new accounts, cron jobs, webshells.",
            "finding_refs": ", ".join(persist_ids[:5]),
        })
    if "Exfiltration" in tactics_seen:
        exfil_ids = [f.get("id", "") for f in detections if f.get("mitre_tactic") == "Exfiltration"]
        exfil_ids = [fid for fid in exfil_ids if fid]
        remediation.append({
            "action": "Assess data exposure: identify what data was accessed or transferred in the exfiltration findings.",
            "finding_refs": ", ".join(exfil_ids[:5]),
        })
    vuln_findings = [f for f in detections if f.get("mitre_tactic") == "Initial Access" and "vuln" in str(f.get("rule_id", "")).lower()]
    if vuln_findings:
        vuln_ids = [f.get("id", "") for f in vuln_findings if f.get("id")]
        remediation.append({
            "action": "Patch exploited weaknesses identified in initial-access findings: " + "; ".join(f.get("rule_name", "") for f in vuln_findings[:3]),
            "finding_refs": ", ".join(vuln_ids[:5]),
        })

    if not remediation:
        remediation = [{"action": "None identified", "finding_refs": ""}]

    # ------------------------------------------------------------------
    # Executive summary
    # ------------------------------------------------------------------
    first_seen = attack_events[0].get("timestamp") if attack_events else None
    last_seen = attack_events[-1].get("timestamp") if attack_events else None
    exec_summary = build_executive_summary(
        case_name=case_name,
        n_evidence=len(evidence_list),
        n_events=len(events),
        detections=detections,
        hosts=sorted(compromised_hosts),
        users=unique_users(compromised_users),
        dwell=dwell_time_str,
        first_seen=str(first_seen)[:19] if first_seen else None,
        last_seen=str(last_seen)[:19] if last_seen else None,
    )

    # ------------------------------------------------------------------
    # Evidence manifest (all hashes)
    # ------------------------------------------------------------------
    evidence_manifest = [
        {
            "filename": ev.get("filename"),
            "sha256_hash": ev.get("sha256_hash"),
            "size_bytes": ev.get("size_bytes") or ev.get("file_size", 0),
            "event_count": ev.get("event_count", 0),
            "uploaded_at": ev.get("uploaded_at"),
            "uploader": ev.get("uploader_name", "Unknown"),
        }
        for ev in evidence_list
    ]

    # ------------------------------------------------------------------
    # Assemble report dict (hash computed last)
    # ------------------------------------------------------------------
    report_dict: Dict[str, Any] = {
        "id": f"rep-{case_id[:8]}-{uuid.uuid4().hex[:6]}",
        "case_id": case_id,
        "case_name": case_name,
        "generated_at": now_iso,
        "generator_name": gen_name,
        "generator_role": str(gen_role),
        "version": "1.0",
        "status": "DRAFT",  # C2: DRAFT until human approval
        "classification": "CONFIDENTIAL // TLP:AMBER - DFIR EVIDENTIARY",
        "draft_notice": "DRAFT: auto-generated by DCSRE rule engine. Requires examiner review and approval before use as legal evidence.",
        "executive_summary": exec_summary,
        # C2: full evidence manifest with all hashes
        "evidence_manifest": evidence_manifest,
        # Legacy field name kept for backwards compat
        "evidence_inventory": evidence_manifest,
        # C2: computed chain of custody
        "chain_of_custody": chain_of_custody,
        "chain_of_custody_note": (
            f"Evidence integrity verified via SHA-256 at upload time. "
            f"{audit_count} audit log entries recorded for this case. "
            f"Hash re-verification results shown per file above."
        ),
        "mitre_coverage": detections,
        # Attack sequence ordered by event_time, grouped by tactic
        "attack_sequence_by_tactic": {
            tactic: [
                {
                    "id": f.get("id"),
                    "rule_name": f.get("rule_name"),
                    "first_seen": f.get("first_seen"),
                    "last_seen": f.get("last_seen"),
                    "host": f.get("target_host") or f.get("host"),
                    "actor": f.get("actor"),
                    "user": f.get("user"),
                    "source_file": f.get("source_file"),
                    "source_record_references": f.get("source_record_references"),
                }
                for f in findings
            ]
            for tactic, findings in findings_by_tactic.items()
        },
        "attack_timeline_summary": attack_events,
        "compromised_assets": {
            "hosts": sorted(compromised_hosts) or ["None identified"],
            "users": unique_users(compromised_users) or ["None identified"],
            "adversary_infrastructure": sorted(adversary_infra) or ["None identified"],
            "dwell_time": dwell_time_str,
        },
        # C2: generated, not boilerplate
        "remediation": remediation,
        # Legacy field kept
        "recommendations": [r["action"] for r in remediation],
        # C2: Methodology and Limitations
        "methodology": (
            "This report was produced by the DCSRE rule-based forensic engine. "
            "All detections are deterministic Sigma-style rules evaluated against normalized events. "
            "No AI, ML, or statistical inference was used. "
            "The engine detects only what its rule set describes; unknown or novel techniques "
            "not covered by the current rule set will not appear in findings."
        ),
        "limitations": (
            "Detections are limited to the current parser and rule-set versions in use at generation time. "
            "Event timestamps are sourced from the evidence files (event_time); "
            "upload times (ingested_at) are stored separately and do not appear as event times. "
            "All timestamps are normalised to UTC. "
            "Rule coverage gaps are listed in the rule coverage matrix."
            + (
                " TACTIC WARNINGS: " + " | ".join(tactic_warnings)
                if tactic_warnings else ""
            )
        ),
        "rule_set_version": "1.1.0",
        "parser_versions": {
            "auth_log": "1.0", "windows_evtx": "1.0", "pcap": "1.0",
            "generic_csv_json": "1.1", "auditd": "1.0", "structured_log": "1.0",
            "web_access": "1.0",
        },
        "timezone": "UTC",
    }

    # C2: compute content hash over report body (excluding hash line itself)
    report_dict["report_hash"] = _compute_report_hash(report_dict)

    return report_dict


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

def render_report_html(report_data: Dict[str, Any]) -> str:
    is_draft = report_data.get("status", "DRAFT") == "DRAFT"

    def _hash_cls(st: Any) -> str:
        s = str(st or "")
        if s == "match":
            return "match"
        if s == "MISMATCH":
            return "mismatch"
        return ""

    evidence_rows = "".join([
        f"<tr><td><code>{esc(e.get('filename'))}</code></td>"
        f"<td><code>{esc(e.get('sha256_hash', ''))}</code></td>"
        f"<td>{e.get('size_bytes', 0):,} B</td>"
        f"<td>{e.get('event_count', 0)}</td>"
        f"<td>{esc(e.get('uploader', 'Unknown'))}</td>"
        f"<td>{esc(e.get('uploaded_at', ''))}</td></tr>"
        for e in report_data.get("evidence_manifest", [])
    ]) or "<tr><td colspan='6'>None identified</td></tr>"

    custody_rows = "".join([
        f"<tr><td><code>{esc(c.get('filename'))}</code></td>"
        f"<td><code>{esc(str(c.get('sha256_hash', ''))[:32])}…</code></td>"
        f"<td class='{_hash_cls(c.get('hash_status'))}'>{esc(c.get('hash_status'))}</td>"
        f"<td>{esc(c.get('uploaded_by', 'Unknown'))}</td>"
        f"<td>{esc(c.get('uploaded_at', ''))}</td></tr>"
        for c in report_data.get("chain_of_custody", [])
    ]) or "<tr><td colspan='5'>None identified</td></tr>"

    timeline_rows = "".join([
        f"<tr><td><code>{esc(ev.get('timestamp'))}</code></td>"
        f"<td><span class='badge'>{esc(str(ev.get('severity', '')).upper())}</span></td>"
        f"<td>{esc(ev.get('host', 'N/A'))}</td>"
        f"<td>{esc(ev.get('user', 'N/A'))}</td>"
        f"<td>{esc(ev.get('action', ''))}</td></tr>"
        for ev in report_data.get("attack_timeline_summary", [])
    ]) or "<tr><td colspan='5'>None identified</td></tr>"

    detection_rows = "".join([
        f"<tr><td><strong>{esc(d.get('rule_name'))}</strong></td>"
        f"<td><code>{esc(', '.join(d.get('mitre_techniques_all') or [d.get('mitre_technique', 'N/A')]))}</code></td>"
        f"<td>{esc(d.get('mitre_tactic', 'N/A'))}</td>"
        f"<td><span class='badge badge-{str(d.get('severity', '')).lower()}'>{esc(str(d.get('severity', '')).upper())}</span></td>"
        f"<td>{esc(d.get('description', ''))}</td></tr>"
        for d in report_data.get("mitre_coverage", [])
    ]) or "<tr><td colspan='5'>None identified</td></tr>"

    rems_html = "".join([
        f"<li><strong>{html.escape(str(r.get('action', r if isinstance(r, str) else '')))}</strong>"
        f"{(' <em>(findings: ' + html.escape(str(r.get('finding_refs', ''))) + ')</em>') if isinstance(r, dict) and r.get('finding_refs') else ''}</li>"
        for r in report_data.get("remediation", [])
    ]) or "<li>None identified</li>"

    comp = report_data.get("compromised_assets", {})
    comp_rows = (
        "".join(f"<tr><td>Host</td><td><strong>{h}</strong></td><td>COMPROMISED</td></tr>" for h in comp.get("hosts", []) if h != "None identified")
        + "".join(f"<tr><td>User Account</td><td><strong>{u}</strong></td><td>COMPROMISED</td></tr>" for u in comp.get("users", []) if u != "None identified")
        + "".join(f"<tr><td>Adversary Infrastructure</td><td><strong>{ip}</strong></td><td>ADVERSARY</td></tr>" for ip in comp.get("adversary_infrastructure", []) if ip != "None identified")
    ) or "<tr><td colspan='3'>None identified</td></tr>"

    draft_banner = ""
    if is_draft:
        draft_banner = "<div class='draft-banner'>⚠ DRAFT — AUTO-GENERATED, REQUIRES EXAMINER REVIEW BEFORE USE AS EVIDENCE</div>"

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>DCSRE Forensic Report — {html.escape(report_data.get('case_name', ''))}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #fff; color: #111; padding: 40px; max-width: 960px; margin: 0 auto; line-height: 1.5; }}
    h1, h2, h3 {{ font-family: ui-monospace, Menlo, Monaco, Consolas, monospace; color: #0f172a; }}
    h1 {{ border-bottom: 3px solid #f95721; padding-bottom: 8px; }}
    h2 {{ border-bottom: 1.5px solid #e2e8f0; padding-bottom: 6px; margin-top: 32px; color: #ea580c; }}
    .draft-banner {{ background: #fef3c7; border: 2px solid #d97706; color: #92400e; font-weight: bold; padding: 12px 20px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; }}
    .classification {{ display: inline-block; padding: 4px 10px; background: #ffedd5; color: #c2410c; font-weight: bold; border-radius: 4px; font-size: 11px; margin-bottom: 12px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 12px; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 8px; text-align: left; }}
    th {{ background: #f1f5f9; font-weight: 600; }}
    .badge {{ padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold; background: #e2e8f0; }}
    .badge-critical {{ background: #fee2e2; color: #991b1b; }}
    .badge-high {{ background: #ffedd5; color: #c2410c; }}
    .badge-medium {{ background: #fef3c7; color: #92400e; }}
    .match {{ color: #166534; font-weight: bold; }}
    .mismatch {{ color: #991b1b; font-weight: bold; }}
    code {{ font-family: ui-monospace, Menlo, monospace; font-size: 11px; color: #0369a1; word-break: break-all; }}
    ul {{ padding-left: 20px; }}
    li {{ margin-bottom: 6px; font-size: 14px; }}
    .hash-line {{ font-size: 11px; font-family: monospace; color: #64748b; margin-top: 20px; border-top: 1px solid #e2e8f0; padding-top: 8px; }}
    @media print {{ body {{ padding: 0; }} }}
  </style>
</head>
<body>
  <div class="classification">{html.escape(report_data.get('classification', ''))}</div>
  {draft_banner}
  <h1>DCSRE DIGITAL FORENSIC RECONSTRUCTION REPORT</h1>
  <table>
    <tr><th>Incident</th><td>{html.escape(report_data.get('case_name', ''))}</td><th>Report ID</th><td>{report_data.get('id', '')}</td></tr>
    <tr><th>Generated (UTC)</th><td>{report_data.get('generated_at', '')}</td><th>Investigator</th><td>{html.escape(str(report_data.get('generator_name', '')))}</td></tr>
    <tr><th>Status</th><td class="{'mismatch' if is_draft else 'match'}">{report_data.get('status', 'DRAFT')}</td><th>Timezone</th><td>UTC</td></tr>
  </table>

  <h2>1. Executive Summary</h2>
  <p>{html.escape(report_data.get('executive_summary', 'None identified'))}</p>

  <h2>2. Chain-of-Custody — Evidence Manifest (all SHA-256 hashes)</h2>
  <p>{html.escape(report_data.get('chain_of_custody_note', ''))}</p>
  <table>
    <thead><tr><th>Filename</th><th>SHA-256</th><th>Hash Status</th><th>Uploaded By</th><th>Uploaded At (UTC)</th></tr></thead>
    <tbody>{custody_rows}</tbody>
  </table>

  <h2>3. Compromised Assets &amp; Adversary Infrastructure</h2>
  <table>
    <thead><tr><th>Entity Type</th><th>Identifier</th><th>Status</th></tr></thead>
    <tbody>{comp_rows}</tbody>
  </table>

  <h2>4. MITRE ATT&amp;CK Threat Detections (event_time used throughout)</h2>
  <table>
    <thead><tr><th>Rule</th><th>Technique</th><th>Tactic</th><th>Severity</th><th>Description</th></tr></thead>
    <tbody>{detection_rows}</tbody>
  </table>

  <h2>5. Reconstructed Attack Timeline (ordered by event_time)</h2>
  <table>
    <thead><tr><th>Event Time (UTC)</th><th>Severity</th><th>Host</th><th>User</th><th>Activity</th></tr></thead>
    <tbody>{timeline_rows}</tbody>
  </table>

  <h2>6. Remediation Directives (generated from findings)</h2>
  <ul>{rems_html}</ul>

  <h2>7. Methodology &amp; Limitations</h2>
  <p><strong>Methodology:</strong> {html.escape(report_data.get('methodology', ''))}</p>
  <p><strong>Limitations:</strong> {html.escape(report_data.get('limitations', ''))}</p>

  <div class="hash-line">
    Report content SHA-256: <code>{report_data.get('report_hash', 'not computed')}</code>
    &nbsp;|&nbsp; Rule-set version: {report_data.get('rule_set_version', 'N/A')}
  </div>
</body>
</html>"""


def render_report_pdf(report_data: Dict[str, Any]) -> bytes:
    """Renders a complete PDF document for the forensic report using ReportLab."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.pdfgen import canvas

    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_page_states = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            num_pages = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self.draw_page_decorations(num_pages)
                super().showPage()
            super().save()

        def draw_page_decorations(self, page_count):
            self.saveState()
            self.setFont("Helvetica-Bold", 7.5)
            self.setFillColor(colors.HexColor("#c2410c"))
            self.drawString(36, 762, "CONFIDENTIAL // TLP:AMBER - DFIR EVIDENTIARY")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.6)
            self.line(36, 32, 576, 32)
            self.setFont("Helvetica", 7.5)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawString(36, 22, "DCSRE Digital Crime Scene Reconstruction Engine — Official Forensic Record")
            self.drawRightString(576, 22, f"Page {self._pageNumber} of {page_count}")
            self.restoreState()

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=42, bottomMargin=42)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'],
        fontName='Helvetica-Bold', fontSize=15, leading=18,
        textColor=colors.HexColor('#0f172a'), spaceAfter=3)
    h2_style = ParagraphStyle('SectionH2', parent=styles['Heading2'],
        fontName='Helvetica-Bold', fontSize=10.5, leading=13,
        textColor=colors.HexColor('#ea580c'), spaceBefore=11, spaceAfter=5, keepWithNext=True)
    body_style = ParagraphStyle('Body', parent=styles['Normal'],
        fontName='Helvetica', fontSize=8.5, leading=12, textColor=colors.HexColor('#1e293b'))
    cell_style = ParagraphStyle('Cell', parent=styles['Normal'],
        fontName='Helvetica', fontSize=7.5, leading=10, textColor=colors.HexColor('#1e293b'))
    cell_bold = ParagraphStyle('CellBold', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=7.5, leading=10, textColor=colors.HexColor('#0f172a'))
    cell_code = ParagraphStyle('Code', parent=styles['Normal'],
        fontName='Courier', fontSize=7, leading=9, textColor=colors.HexColor('#0369a1'))
    cell_crit = ParagraphStyle('Crit', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=7, leading=9, textColor=colors.HexColor('#991b1b'))

    story = []

    is_draft = report_data.get("status", "DRAFT") == "DRAFT"
    story.append(Paragraph("DCSRE DIGITAL FORENSIC RECONSTRUCTION REPORT", title_style))
    if is_draft:
        draft_style = ParagraphStyle('Draft', parent=styles['Normal'],
            fontName='Helvetica-Bold', fontSize=9, leading=12,
            textColor=colors.HexColor('#92400e'), backColor=colors.HexColor('#fef3c7'),
            spaceAfter=8)
        story.append(Paragraph("⚠ DRAFT — AUTO-GENERATED, REQUIRES EXAMINER REVIEW BEFORE USE AS EVIDENCE", draft_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#f95721"), spaceAfter=8))

    meta = [
        [Paragraph(f"<b>Incident:</b> {html.escape(str(report_data.get('case_name', '')))}",  cell_style),
         Paragraph(f"<b>Report ID:</b> {html.escape(str(report_data.get('id', '')))}",          cell_style),
         Paragraph(f"<b>Generated:</b> {html.escape(str(report_data.get('generated_at', '')))}",cell_style)],
        [Paragraph(f"<b>Investigator:</b> {html.escape(str(report_data.get('generator_name', '')))}",cell_style),
         Paragraph(f"<b>Status:</b> {html.escape(str(report_data.get('status', 'DRAFT')))}",    cell_style),
         Paragraph(f"<b>Timezone:</b> UTC",                                                      cell_style)],
    ]
    t = Table(meta, colWidths=[180, 180, 180])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 4), ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 6))

    story.append(Paragraph("1. Executive Summary", h2_style))
    story.append(Paragraph(html.escape(report_data.get("executive_summary", "None identified")), body_style))
    story.append(Spacer(1, 4))

    story.append(Paragraph("2. Chain-of-Custody Evidence Manifest", h2_style))
    story.append(Paragraph(html.escape(report_data.get("chain_of_custody_note", "")), body_style))
    ev_hdr = [[Paragraph(f"<b>{x}</b>", cell_bold) for x in ["Filename", "SHA-256 (32 chars)", "Hash Status", "Uploaded By", "Uploaded At"]]]
    ev_rows = [
        [Paragraph(html.escape(str(c.get("filename",""))), cell_code),
         Paragraph(html.escape(str(c.get("sha256_hash",""))[:32]) + "…", cell_code),
         Paragraph(str(c.get("hash_status","?")), cell_crit if str(c.get("hash_status","")) == "MISMATCH" else cell_style),
         Paragraph(html.escape(str(c.get("uploaded_by",""))), cell_style),
         Paragraph(html.escape(str(c.get("uploaded_at",""))), cell_style)]
        for c in report_data.get("chain_of_custody", [])
    ]
    ev_table_data = ev_hdr + (ev_rows if ev_rows else [[Paragraph("None identified", cell_style)] + [""]*4])
    t2 = Table(ev_table_data, colWidths=[110, 155, 70, 95, 110], repeatRows=1)
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 3), ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t2)
    story.append(Spacer(1, 4))

    story.append(Paragraph("3. Compromised Assets & Adversary Infrastructure", h2_style))
    comp = report_data.get("compromised_assets", {})
    comp_data = [
        [Paragraph("<b>Entity Type</b>", cell_bold), Paragraph("<b>Identifier</b>", cell_bold), Paragraph("<b>Status</b>", cell_bold)]
    ]
    for h in comp.get("hosts", []):
        if h != "None identified": comp_data.append([Paragraph("Host", cell_style), Paragraph(html.escape(str(h)), cell_bold), Paragraph("COMPROMISED", cell_crit)])
    for u in comp.get("users", []):
        if u != "None identified": comp_data.append([Paragraph("User Account", cell_style), Paragraph(html.escape(str(u)), cell_bold), Paragraph("COMPROMISED", cell_crit)])
    for ip in comp.get("adversary_infrastructure", []):
        if ip != "None identified": comp_data.append([Paragraph("Adversary Infra", cell_style), Paragraph(html.escape(str(ip)), cell_bold), Paragraph("ADVERSARY", cell_crit)])
    if len(comp_data) == 1:
        comp_data.append([Paragraph("None identified", cell_style), "", ""])
    t3 = Table(comp_data, colWidths=[130, 220, 190], repeatRows=1)
    t3.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 3), ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t3)
    story.append(Spacer(1, 4))

    story.append(Paragraph("4. Threat Detections", h2_style))
    det_hdr = [[Paragraph(f"<b>{x}</b>", cell_bold) for x in ["Rule", "Technique", "Tactic", "Severity", "Description"]]]
    det_rows = [
        [Paragraph(html.escape(str(d.get("rule_name",""))), cell_bold),
         Paragraph(html.escape(", ".join(d.get("mitre_techniques_all") or [d.get("mitre_technique", "N/A")])), cell_code),
         Paragraph(html.escape(str(d.get("mitre_tactic","N/A"))), cell_style),
         Paragraph(str(d.get("severity","")).upper(), cell_crit if str(d.get("severity","")) in ("critical","high") else cell_style),
         Paragraph(html.escape(str(d.get("description",""))), cell_style)]
        for d in report_data.get("mitre_coverage", [])
    ]
    det_data = det_hdr + (det_rows if det_rows else [[Paragraph("None identified", cell_style)] + [""]*4])
    t4 = Table(det_data, colWidths=[130, 65, 85, 60, 200], repeatRows=1)
    t4.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 3), ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t4)
    story.append(Spacer(1, 4))

    story.append(Paragraph("5. Attack Timeline (event_time, UTC)", h2_style))
    tl_hdr = [[Paragraph(f"<b>{x}</b>", cell_bold) for x in ["Event Time (UTC)", "Severity", "Host", "User", "Activity"]]]
    tl_rows = [
        [Paragraph(html.escape(str(ev.get("timestamp",""))), cell_code),
         Paragraph(str(ev.get("severity","")).upper(), cell_style),
         Paragraph(html.escape(str(ev.get("host","N/A"))), cell_style),
         Paragraph(html.escape(str(ev.get("user","N/A"))), cell_style),
         Paragraph(html.escape(str(ev.get("action",""))), cell_style)]
        for ev in report_data.get("attack_timeline_summary", [])
    ]
    tl_data = tl_hdr + (tl_rows if tl_rows else [[Paragraph("None identified", cell_style)] + [""]*4])
    t5 = Table(tl_data, colWidths=[110, 50, 75, 75, 230], repeatRows=1)
    t5.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 3), ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t5)
    story.append(Spacer(1, 4))

    story.append(Paragraph("6. Remediation Directives (generated from findings)", h2_style))
    for idx, r in enumerate(report_data.get("remediation", []), 1):
        action = r.get("action", r) if isinstance(r, dict) else str(r)
        refs = r.get("finding_refs", "") if isinstance(r, dict) else ""
        txt = f"<b>{idx}.</b> {html.escape(str(action))}"
        if refs:
            txt += f" <i>(findings: {html.escape(str(refs))})</i>"
        story.append(Paragraph(txt, body_style))
        story.append(Spacer(1, 2))

    story.append(Paragraph("7. Methodology & Limitations", h2_style))
    story.append(Paragraph(f"<b>Methodology:</b> {html.escape(report_data.get('methodology',''))}", body_style))
    story.append(Spacer(1, 3))
    story.append(Paragraph(f"<b>Limitations:</b> {html.escape(report_data.get('limitations',''))}", body_style))
    story.append(Spacer(1, 6))

    hash_style = ParagraphStyle('Hash', parent=styles['Normal'],
        fontName='Courier', fontSize=7, leading=9, textColor=colors.HexColor('#64748b'))
    story.append(Paragraph(f"Report content SHA-256: {report_data.get('report_hash','not computed')}", hash_style))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()
