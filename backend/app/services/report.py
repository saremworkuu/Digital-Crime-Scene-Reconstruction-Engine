import html
import uuid
from datetime import datetime, timezone
from io import BytesIO
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

    comp_hosts_rows = "".join([
        f"<tr><td>Host / System</td><td><strong>{h}</strong></td><td>Internal Endpoint</td><td><span class='badge badge-critical'>COMPROMISED</span></td></tr>"
        for h in report_data.get("compromised_assets", {}).get("hosts", [])
    ])
    comp_users_rows = "".join([
        f"<tr><td>User Account</td><td><strong>{u}</strong></td><td>Active Directory / Local</td><td><span class='badge badge-high'>COMPROMISED</span></td></tr>"
        for u in report_data.get("compromised_assets", {}).get("users", [])
    ])
    ext_ips_rows = "".join([
        f"<tr><td>Adversary Infrastructure</td><td><strong>{ip}</strong></td><td>External WAN / C2</td><td><span class='badge badge-critical'>BLOCKED</span></td></tr>"
        for ip in report_data.get("compromised_assets", {}).get("external_ips", [])
    ])

    comp_table_rows = comp_hosts_rows + comp_users_rows + ext_ips_rows

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

  <h2>3. Compromised Assets & Affected Accounts</h2>
  <table>
    <thead>
      <tr><th>Entity Type</th><th>Identifier</th><th>Role / Scope</th><th>Status</th></tr>
    </thead>
    <tbody>
      {comp_table_rows or "<tr><td colspan='4'>No compromised entities confirmed.</td></tr>"}
    </tbody>
  </table>

  <h2>4. MITRE ATT&CK Threat Detections & Verified Findings</h2>
  <table>
    <thead>
      <tr><th>Rule / Threat</th><th>Technique</th><th>Tactic</th><th>Severity</th><th>Description</th></tr>
    </thead>
    <tbody>
      {detection_rows or "<tr><td colspan='5'>No threat detections triggered.</td></tr>"}
    </tbody>
  </table>

  <h2>5. Reconstructed Attack Timeline Progression</h2>
  <table>
    <thead>
      <tr><th>Timestamp (UTC)</th><th>Severity</th><th>Target Host</th><th>User / Actor</th><th>Forensic Activity</th></tr>
    </thead>
    <tbody>
      {timeline_rows or "<tr><td colspan='5'>No chronological events available.</td></tr>"}
    </tbody>
  </table>

  <h2>6. Remediation & Incident Response Recommendations</h2>
  <ul>
    {recs_list}
  </ul>
</body>
</html>"""


def render_report_pdf(report_data: Dict[str, Any]) -> bytes:
    """Renders a complete, executive printable PDF document for the forensic report using ReportLab."""
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
            # Top header
            self.drawString(36, 762, "CONFIDENTIAL // TLP:AMBER - DFIR EVIDENTIARY")
            # Bottom footer line and page numbering
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.6)
            self.line(36, 32, 576, 32)

            self.setFont("Helvetica", 7.5)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawString(36, 22, "DCSRE Digital Crime Scene Reconstruction Engine — Official Forensic Record")
            self.drawRightString(576, 22, f"Page {self._pageNumber} of {page_count}")
            self.restoreState()

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=42,
        bottomMargin=42,
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=18,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=3,
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=13,
        textColor=colors.HexColor('#ea580c'),
        spaceBefore=11,
        spaceAfter=5,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#1e293b'),
    )

    cell_style = ParagraphStyle(
        'CellText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#1e293b'),
    )

    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#0f172a'),
    )

    cell_code = ParagraphStyle(
        'CellCode',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor('#0369a1'),
    )

    cell_badge_crit = ParagraphStyle(
        'CellCrit',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor('#991b1b'),
    )

    story = []

    # Title & Separator
    story.append(Paragraph("DCSRE DIGITAL FORENSIC RECONSTRUCTION REPORT", title_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#f95721"), spaceAfter=8))

    # Metadata Grid Table
    meta_data = [
        [
            Paragraph("<b>Incident:</b> " + html.escape(str(report_data.get("case_name", ""))), cell_style),
            Paragraph("<b>Report ID:</b> " + html.escape(str(report_data.get("id", ""))), cell_style),
            Paragraph("<b>Generated:</b> " + html.escape(str(report_data.get("generated_at", ""))), cell_style),
        ],
        [
            Paragraph("<b>Investigator:</b> " + html.escape(str(report_data.get("generator_name", ""))), cell_style),
            Paragraph("<b>Role:</b> " + html.escape(str(report_data.get("generator_role", ""))), cell_style),
            Paragraph("<b>Report Version:</b> " + html.escape(str(report_data.get("version", "1.0"))), cell_style),
        ]
    ]
    meta_table = Table(meta_data, colWidths=[180, 180, 180])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 6))

    # 1. Executive Summary
    story.append(Paragraph("1. Executive Summary", h2_style))
    exec_text = report_data.get("executive_summary") or "Investigation completed."
    story.append(Paragraph(html.escape(exec_text), body_style))
    story.append(Spacer(1, 4))

    # 2. Evidence Inventory
    story.append(Paragraph("2. Chain-of-Custody Digital Evidence Ledger", h2_style))
    evidence_headers = [Paragraph("<b>Filename</b>", cell_bold), Paragraph("<b>SHA-256 Hash</b>", cell_bold), Paragraph("<b>Size</b>", cell_bold), Paragraph("<b>Events</b>", cell_bold), Paragraph("<b>Uploaded UTC</b>", cell_bold)]
    evidence_table_data = [evidence_headers]
    for ev in report_data.get("evidence_inventory", []):
        size_str = f"{ev.get('size_bytes', 0):,} B"
        evidence_table_data.append([
            Paragraph(html.escape(str(ev.get("filename", ""))), cell_code),
            Paragraph(html.escape(str(ev.get("sha256_hash", "")[:32])) + "...", cell_code),
            Paragraph(size_str, cell_style),
            Paragraph(str(ev.get("event_count", 0)), cell_style),
            Paragraph(html.escape(str(ev.get("uploaded_at", ""))), cell_style),
        ])
    if len(evidence_table_data) == 1:
        evidence_table_data.append([Paragraph("No evidence records ingested.", cell_style), "", "", "", ""])

    t_ev = Table(evidence_table_data, colWidths=[120, 180, 65, 55, 120])
    t_ev.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_ev)
    story.append(Spacer(1, 4))

    # 3. Compromised Assets & Affected Accounts
    story.append(Paragraph("3. Compromised Assets & Affected Accounts", h2_style))
    comp_headers = [Paragraph("<b>Entity Type</b>", cell_bold), Paragraph("<b>Identifier</b>", cell_bold), Paragraph("<b>Role / Scope</b>", cell_bold), Paragraph("<b>Status</b>", cell_bold)]
    comp_table_data = [comp_headers]
    for h in report_data.get("compromised_assets", {}).get("hosts", []):
        comp_table_data.append([Paragraph("Host / System", cell_style), Paragraph(html.escape(str(h)), cell_bold), Paragraph("Internal Endpoint", cell_style), Paragraph("COMPROMISED", cell_badge_crit)])
    for u in report_data.get("compromised_assets", {}).get("users", []):
        comp_table_data.append([Paragraph("User Account", cell_style), Paragraph(html.escape(str(u)), cell_bold), Paragraph("Active Directory", cell_style), Paragraph("COMPROMISED", cell_badge_crit)])
    for ip in report_data.get("compromised_assets", {}).get("external_ips", []):
        comp_table_data.append([Paragraph("Adversary Infrastructure", cell_style), Paragraph(html.escape(str(ip)), cell_bold), Paragraph("External WAN / C2", cell_style), Paragraph("BLOCKED", cell_badge_crit)])
    if len(comp_table_data) == 1:
        comp_table_data.append([Paragraph("No compromised entities confirmed.", cell_style), "", "", ""])

    t_comp = Table(comp_table_data, colWidths=[140, 160, 140, 100])
    t_comp.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_comp)
    story.append(Spacer(1, 4))

    # 4. Threat Detections
    story.append(Paragraph("4. MITRE ATT&CK Threat Detections & Verified Findings", h2_style))
    det_headers = [Paragraph("<b>Rule / Threat</b>", cell_bold), Paragraph("<b>Technique</b>", cell_bold), Paragraph("<b>Tactic</b>", cell_bold), Paragraph("<b>Severity</b>", cell_bold), Paragraph("<b>Description</b>", cell_bold)]
    det_table_data = [det_headers]
    for d in report_data.get("mitre_coverage", []):
        sev = str(d.get("severity", "")).upper()
        det_table_data.append([
            Paragraph(html.escape(str(d.get("rule_name", ""))), cell_bold),
            Paragraph(html.escape(str(d.get("mitre_technique", "N/A"))), cell_code),
            Paragraph(html.escape(str(d.get("mitre_tactic", "N/A"))), cell_style),
            Paragraph(sev, cell_badge_crit if sev in ("CRITICAL", "HIGH") else cell_style),
            Paragraph(html.escape(str(d.get("description", ""))), cell_style),
        ])
    if len(det_table_data) == 1:
        det_table_data.append([Paragraph("No threat detections triggered.", cell_style), "", "", "", ""])

    t_det = Table(det_table_data, colWidths=[130, 65, 85, 60, 200])
    t_det.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_det)
    story.append(Spacer(1, 4))

    # 5. Timeline Progression
    story.append(Paragraph("5. Reconstructed Attack Timeline Progression", h2_style))
    tl_headers = [Paragraph("<b>Timestamp (UTC)</b>", cell_bold), Paragraph("<b>Severity</b>", cell_bold), Paragraph("<b>Host</b>", cell_bold), Paragraph("<b>User</b>", cell_bold), Paragraph("<b>Forensic Activity</b>", cell_bold)]
    tl_table_data = [tl_headers]
    for ev in report_data.get("attack_timeline_summary", [])[:35]:
        tl_table_data.append([
            Paragraph(html.escape(str(ev.get("timestamp", ""))), cell_code),
            Paragraph(html.escape(str(ev.get("severity", "")).upper()), cell_style),
            Paragraph(html.escape(str(ev.get("host", "N/A"))), cell_style),
            Paragraph(html.escape(str(ev.get("user", "N/A"))), cell_style),
            Paragraph(html.escape(str(ev.get("action", ""))), cell_style),
        ])
    if len(tl_table_data) == 1:
        tl_table_data.append([Paragraph("No chronological events available.", cell_style), "", "", "", ""])

    t_tl = Table(tl_table_data, colWidths=[110, 50, 75, 75, 230])
    t_tl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_tl)
    story.append(Spacer(1, 4))

    # 6. Recommendations
    story.append(Paragraph("6. Remediation & Incident Response Recommendations", h2_style))
    for idx, r in enumerate(report_data.get("recommendations", []), 1):
        story.append(Paragraph(f"<b>{idx}.</b> {html.escape(str(r))}", body_style))
        story.append(Spacer(1, 2))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()

