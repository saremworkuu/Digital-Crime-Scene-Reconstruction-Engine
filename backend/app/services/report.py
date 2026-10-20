# Report service
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List


def generate_forensic_report_data(
    case_dict: Dict[str, Any],
    evidence_list: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    detections: List[Dict[str, Any]],
    generator_user: Any = None,
) -> Dict[str, Any]:
    """
    Synthesizes case metadata, evidence ledger, timeline progression,
    and MITRE ATT&CK detections into a formal forensic reconstruction report.
    """
    case_id = str(case_dict.get("id", ""))
    case_name = case_dict.get("name", "Untitled Incident")
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    gen_name = getattr(generator_user, "name", None) or getattr(generator_user, "username", "Lead Forensics Investigator")
    gen_role = getattr(generator_user, "role", "investigator")
    if hasattr(gen_role, "value"):
        gen_role = gen_role.value

    # Identify compromised entities
    compromised_hosts = set()
    compromised_users = set()
    external_ips = set()
    attack_events = []

    for ev in events:
        is_attack = ev.get("is_attack_path") or str(ev.get("severity", "")).lower() in ("critical", "high")
        host = ev.get("host")
        user = ev.get("user")
        src_ip = ev.get("src_ip")
        dst_ip = ev.get("dst_ip")

        if is_attack:
            attack_events.append(ev)
            if host:
                compromised_hosts.add(host)
            if user and user not in ("SYSTEM", "unknown"):
                compromised_users.add(user)

        if src_ip and not src_ip.startswith(("10.", "192.168.", "172.16.", "127.")):
            external_ips.add(src_ip)
        if dst_ip and not dst_ip.startswith(("10.", "192.168.", "172.16.", "127.")):
            external_ips.add(dst_ip)

    # Sort attack timeline events chronologically
    attack_events.sort(key=lambda x: str(x.get("timestamp", "")))

    # Compute dwell time
    dwell_time_str = "Immediate / Single Event"
    if len(attack_events) >= 2:
        try:
            t0 = datetime.fromisoformat(attack_events[0]["timestamp"].replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(attack_events[-1]["timestamp"].replace("Z", "+00:00"))
            delta_mins = int((t1 - t0).total_seconds() / 60)
            if delta_mins < 60:
                dwell_time_str = f"{delta_mins} minutes"
            else:
                dwell_time_str = f"{(delta_mins / 60):.1f} hours"
        except Exception:
            pass

    # Build executive summary
    exec_summary = (
        f"Forensic investigation report for incident '{case_name}'. "
        f"A total of {len(evidence_list)} digital evidence artifacts were ingested and forensically validated "
        f"via SHA-256 cryptographic hashing. Analysis reconstructed {len(events)} normalized events and identified "
        f"{len(detections)} threat detections across the MITRE ATT&CK framework. "
        f"Adversary activity impacted {len(compromised_hosts)} host(s) and {len(compromised_users)} user account(s) "
        f"over an estimated dwell time of {dwell_time_str}."
    )

    # Format recommendations based on detections
    recommendations = [
        "Isolate all identified compromised hosts from the internal network immediately.",
        "Revoke active sessions and force cryptographic password resets with MFA for affected user accounts.",
        "Block identified adversary infrastructure IP addresses and C2 endpoints at perimeter firewalls.",
        "Verify system restore points and inspect backup volume shadow copies for unauthorized tampering.",
        "Submit SHA-256 evidence hashes and chain-of-custody audit logs to legal and compliance counsel.",
    ]

    return {
        "id": f"rep-{case_id[:8]}-{uuid.uuid4().hex[:6]}",
        "case_id": case_id,
        "case_name": case_name,
        "generated_at": now_iso,
        "generator_name": gen_name,
        "generator_role": str(gen_role),
        "version": "1.0",
        "classification": "CONFIDENTIAL // TLP:AMBER - DFIR EVIDENTIARY",
        "executive_summary": exec_summary,
        "evidence_inventory": evidence_list,
        "mitre_coverage": detections,
        "attack_timeline_summary": attack_events,
        "compromised_assets": {
            "hosts": list(compromised_hosts),
            "users": list(compromised_users),
            "external_ips": list(external_ips),
            "dwell_time": dwell_time_str,
        },
        "recommendations": recommendations,
    }


def render_report_html(report_data: Dict[str, Any]) -> str:
    """Renders a standalone printable HTML document for the forensic report."""
    evidence_rows = "".join([
        f"<tr><td><code>{e.get('filename')}</code></td><td><code>{e.get('sha256_hash')}</code></td><td>{e.get('size_bytes', 0):,} B</td><td>{e.get('event_count', 0)}</td><td>{e.get('uploaded_at')}</td></tr>"
        for e in report_data.get("evidence_inventory", [])
    ])

    timeline_rows = "".join([
        f"<tr><td><code>{ev.get('timestamp')}</code></td><td><span class='badge'>{ev.get('severity', '').upper()}</span></td><td>{ev.get('host', 'N/A')}</td><td>{ev.get('user', 'N/A')}</td><td>{ev.get('action', '')}</td></tr>"
        for ev in report_data.get("attack_timeline_summary", [])[:25]
    ])

    detection_rows = "".join([
        f"<tr><td><strong>{d.get('rule_name')}</strong></td><td><code>{d.get('mitre_technique', 'N/A')}</code></td><td>{d.get('mitre_tactic', 'N/A')}</td><td><span class='badge badge-{str(d.get('severity', '')).lower()}'>{str(d.get('severity', '')).upper()}</span></td><td>{d.get('description', '')}</td></tr>"
        for d in report_data.get("mitre_coverage", [])
    ])

    recs_list = "".join([f"<li>{r}</li>" for r in report_data.get("recommendations", [])])

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>DCSRE Forensic Report - {report_data.get('case_name')}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #ffffff; color: #111; padding: 40px; max-width: 960px; margin: 0 auto; line-height: 1.5; }}
    h1, h2, h3 {{ font-family: ui-monospace, Menlo, Monaco, Consolas, monospace; color: #0f172a; }}
    h1 {{ border-bottom: 3px solid #f95721; padding-bottom: 8px; margin-bottom: 4px; }}
    h2 {{ border-bottom: 1.5px solid #e2e8f0; padding-bottom: 6px; margin-top: 32px; color: #ea580c; }}
    .meta-box {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 20px 0; font-size: 13px; font-family: ui-monospace, monospace; }}
    .classification {{ display: inline-block; padding: 4px 10px; background: #ffedd5; color: #c2410c; font-weight: bold; border-radius: 4px; font-size: 11px; margin-bottom: 12px; letter-spacing: 0.5px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 12px; font-family: ui-monospace, monospace; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 8px; text-align: left; }}
    th {{ background: #f1f5f9; color: #334155; font-weight: 600; }}
    .badge {{ padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold; background: #e2e8f0; color: #334155; }}
    .badge-critical {{ background: #fee2e2; color: #991b1b; }}
    .badge-high {{ background: #ffedd5; color: #c2410c; }}
    .badge-medium {{ background: #fef3c7; color: #92400e; }}
    ul {{ padding-left: 20px; }}
    li {{ margin-bottom: 6px; font-size: 14px; }}
    code {{ font-family: ui-monospace, Menlo, monospace; font-size: 11px; color: #0369a1; word-break: break-all; }}
    @media print {{ body {{ padding: 0; }} }}
  </style>
</head>
<body>
  <div class="classification">{report_data.get('classification')}</div>
  <h1>DCSRE DIGITAL FORENSIC RECONSTRUCTION REPORT</h1>
  <div class="meta-box">
    <div><strong>Incident:</strong> {report_data.get('case_name')}</div>
    <div><strong>Report ID:</strong> {report_data.get('id')}</div>
    <div><strong>Generated:</strong> {report_data.get('generated_at')}</div>
    <div><strong>Investigator:</strong> {report_data.get('generator_name')}</div>
    <div><strong>Investigator Role:</strong> {report_data.get('generator_role')}</div>
    <div><strong>Report Version:</strong> {report_data.get('version')}</div>
  </div>

  <h2>1. Executive Summary</h2>
  <p>{report_data.get('executive_summary')}</p>

  <h2>2. Chain-of-Custody Digital Evidence Ledger</h2>
  <table>
    <thead>
      <tr><th>Filename</th><th>SHA-256 Hash</th><th>File Size</th><th>Events</th><th>Uploaded UTC</th></tr>
    </thead>
    <tbody>
      {evidence_rows or "<tr><td colspan='5'>No digital evidence records ingested.</td></tr>"}
    </tbody>
  </table>

  <h2>3. MITRE ATT&CK Threat Detections</h2>
  <table>
    <thead>
      <tr><th>Rule / Threat</th><th>Technique</th><th>Tactic</th><th>Severity</th><th>Description</th></tr>
    </thead>
    <tbody>
      {detection_rows or "<tr><td colspan='5'>No threat detections triggered.</td></tr>"}
    </tbody>
  </table>

  <h2>4. Reconstructed Attack Timeline Progression</h2>
  <table>
    <thead>
      <tr><th>Timestamp (UTC)</th><th>Severity</th><th>Target Host</th><th>User / Actor</th><th>Forensic Activity</th></tr>
    </thead>
    <tbody>
      {timeline_rows or "<tr><td colspan='5'>No chronological events available.</td></tr>"}
    </tbody>
  </table>

  <h2>5. Remediation & Incident Response Recommendations</h2>
  <ul>
    {recs_list}
  </ul>
</body>
</html>"""
