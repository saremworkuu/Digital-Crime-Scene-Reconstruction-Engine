"""
DCSRE Forensic Report Generator (Stage 8)

C2 fixes:
- Report marked DRAFT until human approval.
- SHA-256 is computed over the report's own content (excluding the hash line itself).
- Chain of custody is computed from evidence facts, not boilerplate.
- Section 6 remediation directives are generated from findings, with finding IDs cited.
- No external compliance claim is made.
- If a section has no data, says "None identified".
- Methodology and Limitations section added.
- Attack sequence ordered by event_time grouped by tactic.

B1 fix:
- external addresses are reported as observed indicators; they are not called
  adversary infrastructure solely because they are public or appear in an event.
"""
import hashlib
import html
import json
import copy
import uuid
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Dict, List, Optional
from .entity_classification import is_internal_ip, infrastructure_role

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
    """Hash substantive report content, excluding its hash and volatile metadata."""
    scratch = copy.deepcopy({k: v for k, v in report_dict.items() if k not in {"report_hash", "id", "generated_at"}})
    for entry in scratch.get("evidence_manifest", []) + scratch.get("evidence_inventory", []):
        if isinstance(entry, dict):
            entry.pop("hash_verified_at", None)
    for entry in scratch.get("chain_of_custody", []):
        if isinstance(entry, dict):
            entry.pop("hash_verified_at", None)
    canonical = json.dumps(scratch, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _format_size(value: Any) -> str:
    try:
        size = int(value or 0)
    except (TypeError, ValueError):
        size = 0
    return f"{size:,} bytes ({size / 1024:.2f} KiB)"


def _format_event_time(value: Any) -> str:
    raw = str(value or "")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError):
        return "Not available"


def _format_timeline_time(event: Dict[str, Any]) -> str:
    if event.get("timestamp_timezone_known") is False:
        raw = str(event.get("timestamp") or "")
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            value = parsed.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            value = raw or "Not available"
        return f"{value} (source timezone unspecified)"
    return _format_event_time(event.get("timestamp"))


def _is_private(ip: str) -> bool:
    return is_internal_ip(ip)


def _looks_like_ip(value: Any) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
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
    version: str = "1.0",
) -> Dict[str, Any]:
    """
    Synthesizes case metadata, evidence ledger, timeline, and MITRE detections
    into a formal forensic reconstruction report.
    """
    case_id = str(case_dict.get("id", ""))
    case_name = case_dict.get("name", "Untitled Incident")
    now_iso = _now_iso()
    tactic_warnings: List[str] = []
    ip_map = build_ip_host_map(events)
    event_hosts = {
        str(ev.get("id") or ev.get("event_id")): resolve_hosts([str(ev.get("host"))], ip_map)[0]
        for ev in events
        if (ev.get("id") or ev.get("event_id")) and ev.get("host")
    }
    detections = dedupe_detections(detections, warnings=tactic_warnings, event_hosts=event_hosts)
    valid_event_ids = {str(ev.get("id") or ev.get("event_id") or "") for ev in events} - {""}
    detections = [
        finding for finding in detections
        if set(map(str, finding.get("matching_event_ids") or [])) & valid_event_ids
    ]
    for finding in detections:
        if finding.get("mitre_technique") == "T1041":
            finding["rule_name"] = "Potential Data Exfiltration Activity"
            finding["mitre_tactic"] = "Exfiltration"
        description = str(finding.get("description") or "")
        if finding.get("mitre_technique") == "T1567.002" and "adversary exfiltration" in description.lower():
            finding["description"] = "Detection rule matched rclone-associated outbound transfer activity; transfer purpose and attribution have not been independently confirmed."
    gen_name = (
        getattr(generator_user, "name", None)
        or getattr(generator_user, "username", "Lead Forensics Investigator")
    )
    gen_role = getattr(generator_user, "role", "investigator")
    if hasattr(gen_role, "value"):
        gen_role = gen_role.value

    # ------------------------------------------------------------------
    # Report observed entities without promoting detections to proof of compromise.
    # ------------------------------------------------------------------
    compromised_hosts: set = set()
    compromised_users: set = set()
    adversary_infra: set = set()
    infrastructure_roles: Dict[str, set] = {}

    # Resolve only evidence-linked finding events; use conservative text matching
    # when legacy detections lack persisted associations. Never substitute a
    # detection-run or upload timestamp for an event timestamp.
    finding_event_ids: set = set()
    def _ev_id(ev: Any) -> str:
        return str(ev.get("id", "") or ev.get("event_id", "") or "")

    events_by_id = {_ev_id(ev): ev for ev in events if _ev_id(ev)}
    def _flat(value: Any) -> str:
        return "".join(ch.lower() for ch in str(value or "") if ch.isalnum())

    for finding in detections:
        matched = {
            str(eid) for eid in (finding.get("matching_event_ids") or [])
            if str(eid) in events_by_id
        }
        if not matched:
            name = _flat(finding.get("rule_name") or finding.get("rule_id"))
            target = str(finding.get("target_host") or finding.get("host") or "").casefold()
            if len(name) >= 10:
                for ev in events:
                    ev_host = str(ev.get("host") or "").casefold()
                    if target and not target.startswith("unknown") and ev_host != target:
                        continue
                    details = ev.get("details") or {}
                    searchable = " ".join(str(v) for v in (
                        ev.get("action"), ev.get("event_type"), ev.get("message"),
                        details.get("action"), details.get("message"), details.get("rule_name"),
                    ) if v)
                    if name in _flat(searchable) and _ev_id(ev):
                        matched.add(_ev_id(ev))
        finding["matching_event_ids"] = sorted(matched)
        finding_event_ids.update(matched)
        linked_events = [events_by_id[eid] for eid in matched]
        times = sorted(str(ev.get("timestamp") or "") for ev in linked_events if ev.get("timestamp"))
        finding["first_seen"] = times[0] if times else None
        finding["last_seen"] = times[-1] if times else None
        if not finding.get("user") or str(finding.get("user")).lower().startswith("unknown"):
            linked_users = {str(ev.get("user")) for ev in linked_events
                            if ev.get("user") and str(ev.get("user")).upper() not in ("SYSTEM", "-")
                            and not str(ev.get("user")).lower().startswith("unknown")}
            if len(linked_users) == 1:
                finding["user"] = next(iter(linked_users))
        elif str(finding.get("user")).upper().startswith("DOMAIN\\"):
            account_name = str(finding["user"]).split("\\", 1)[-1].casefold()
            linked_accounts = {
                str(ev.get("user")) for ev in linked_events
                if ev.get("user") and "\\" in str(ev.get("user"))
                and str(ev.get("user")).split("\\", 1)[-1].casefold() == account_name
            }
            if len(linked_accounts) == 1:
                finding["user"] = next(iter(linked_accounts))

        target = finding.get("target_host") or finding.get("host")
        compromise_tactics = {"Execution", "Privilege Escalation", "Persistence", "Defense Evasion", "Credential Access", "Exfiltration", "Impact", "Lateral Movement"}
        if target and str(target).lower() not in ("unknown", "unknown_host") and (finding.get("target_role") == "compromised_host" or finding.get("mitre_tactic") in compromise_tactics):
            resolved_target = resolve_hosts([str(target)], ip_map)[0]
            if not _looks_like_ip(resolved_target):
                compromised_hosts.add(resolved_target)
        user = finding.get("user")
        if user and str(user).upper() not in ("SYSTEM", "-") and not str(user).lower().startswith("unknown"):
            compromised_users.add(str(user))
        actor = finding.get("actor")
        if finding.get("actor_role") == "adversary_infrastructure" and actor and _looks_like_ip(actor) and not _is_private(str(actor)):
            actor_role = infrastructure_role(tactic=str(finding.get("mitre_tactic") or ""), field_role=str((finding.get("rule_information") or {}).get("infrastructure_role") or "attack_source")) or "Other Observed Addresses"
            infrastructure_roles.setdefault(str(actor), set()).add(actor_role)
            adversary_infra.add(str(actor))
        rule_info = finding.get("rule_information") or {}
        for value in (rule_info.get("destination_ip"), rule_info.get("dest_ip"), finding.get("dst_ip")):
            if value and _looks_like_ip(value) and not _is_private(str(value)):
                role = infrastructure_role(tactic=str(finding.get("mitre_tactic") or ""), field_role=str(rule_info.get("infrastructure_role") or ""))
                if role:
                    infrastructure_roles.setdefault(str(value), set()).add(role)
                    adversary_infra.add(str(value))
        role = infrastructure_role(tactic=str(finding.get("mitre_tactic") or ""), field_role=str(rule_info.get("infrastructure_role") or ""))
        domains = rule_info.get("domains") or rule_info.get("domain") or []
        if isinstance(domains, str):
            domains = [domains]
        # Correlate closely timed network evidence with a finding when the
        # network record is not itself one of the detector's matched rows.
        linked_times = []
        for linked_id in finding.get("matching_event_ids") or []:
            linked = events_by_id.get(str(linked_id))
            if linked and linked.get("timestamp"):
                try:
                    linked_times.append(datetime.fromisoformat(str(linked["timestamp"]).replace("Z", "+00:00")))
                except ValueError:
                    pass
        tactic = str(finding.get("mitre_tactic") or "")
        if linked_times and tactic in {"Execution", "Initial Access", "Exfiltration"}:
            for support in events:
                details = support.get("details") or {}
                if not any(token in str(support.get("event_type") or "").lower() for token in ("network", "connection", "flow", "pcap")):
                    continue
                destination = support.get("dst_ip") or details.get("dst_ip") or details.get("destination_ip")
                if not destination or not _looks_like_ip(destination) or _is_private(str(destination)):
                    continue
                try:
                    support_time = datetime.fromisoformat(str(support.get("timestamp") or "").replace("Z", "+00:00"))
                except ValueError:
                    continue
                if min(abs((support_time - linked_time).total_seconds()) for linked_time in linked_times) > 10:
                    continue
                port = str(details.get("dst_port") or details.get("destination_port") or "")
                support_role = "Exfiltration" if tactic == "Exfiltration" else "Payload" if tactic in {"Execution", "Initial Access"} and port in {"80", "443"} else None
                if support_role:
                    infrastructure_roles.setdefault(str(destination), set()).add(support_role)
                    adversary_infra.add(str(destination))

    # Include every event explicitly associated with a finding, as well as
    # separately marked attack-path events. Severity alone does not prove an
    # event is attack activity.
    related_addresses = set()
    for event_id in finding_event_ids:
        ev = events_by_id.get(event_id, {})
        for address in (ev.get("src_ip"), ev.get("dst_ip"), (ev.get("details") or {}).get("source_ip"), (ev.get("details") or {}).get("destination_ip")):
            if address and _looks_like_ip(address) and not _is_private(str(address)):
                related_addresses.add(str(address))
    selected_events = []
    for ev in events:
        details = ev.get("details") or {}
        observed = {str(v) for v in (ev.get("src_ip"), ev.get("dst_ip"), details.get("source_ip"), details.get("destination_ip"), details.get("src_ip"), details.get("dst_ip")) if v}
        is_network = any(word in str(ev.get("event_type", "")).lower() for word in ("network", "dns", "http", "connection", "flow", "pcap"))
        if _ev_id(ev) in finding_event_ids or ev.get("is_attack_path") or (is_network and observed & related_addresses):
            selected_events.append(ev)

    for selected in selected_events:
        selected_id = _ev_id(selected)
        linked_findings = [f for f in detections if selected_id in {str(v) for v in (f.get("matching_event_ids") or [])}]
        selected["mitre_tactic"] = ", ".join(sorted({str(f.get("mitre_tactic")) for f in linked_findings if f.get("mitre_tactic")}))
        selected["mitre_technique"] = ", ".join(sorted({str(f.get("mitre_technique")) for f in linked_findings if f.get("mitre_technique")}))
        selected["source_record_references"] = [str((selected.get("details") or {}).get(k)) for k in ("source_record_id", "record_id", "event_record_id") if (selected.get("details") or {}).get(k)]
    attack_events = merge_timeline(
        selected_events,
        ip_map=ip_map,
    )

    # Timeline events and findings make observed scope; they do not by
    # themselves establish that an account or endpoint was compromised.
    compromised_event_ids = {
        str(event_id)
        for finding in detections
        if finding.get("target_role") == "compromised_host" or finding.get("mitre_tactic") in {"Execution", "Privilege Escalation", "Persistence", "Defense Evasion", "Credential Access", "Exfiltration", "Impact", "Lateral Movement"}
        for event_id in (finding.get("matching_event_ids") or [])
    }
    for ev in attack_events:
        if str(ev.get("id") or "") not in compromised_event_ids:
            continue
        host = str(ev.get("host") or "")
        if host and host.lower() not in ("unknown", "unknown_host", "n/a") and not _looks_like_ip(host):
            compromised_hosts.add(host)
        user = ev.get("user")
        if user and str(user).upper() not in ("SYSTEM", "-") and not str(user).lower().startswith("unknown"):
            compromised_users.add(str(user))
    compromised_hosts = set(resolve_hosts(compromised_hosts, ip_map))
    observed_ips = set()
    indicators: List[Dict[str, Any]] = []
    for ev in events:
        for ip in (ev.get("src_ip"), ev.get("dst_ip"),
                   (ev.get("details") or {}).get("source_ip"),
                   (ev.get("details") or {}).get("destination_ip")):
            if ip and _looks_like_ip(ip):
                observed_ips.add(str(ip))
        details = ev.get("details") or {}
        domain = details.get("query_name") or details.get("query") or details.get("domain")
        if domain:
            indicators.append({"type": "domain", "value": str(domain).rstrip("."), "source_event_id": _ev_id(ev), "source_file": ev.get("source_file") or ev.get("source")})
        for key, kind in (("filename", "file"), ("target_file", "file"), ("target_filename", "file"), ("TargetFilename", "file"), ("hash", "file_hash"), ("sha256", "file_hash"), ("file_hash", "file_hash"), ("SHA256", "file_hash"), ("service_name", "service"), ("ServiceName", "service"), ("registry_key", "registry_run_key"), ("TargetObject", "registry_run_key")):
            value = details.get(key)
            if value and str(value).strip().lower() not in {"-", "unknown", "n/a", "none"} and (kind != "registry_run_key" or "\\run" in str(value).lower() or "\\runonce" in str(value).lower()):
                indicators.append({"type": kind, "value": str(value), "source_event_id": _ev_id(ev), "source_file": ev.get("source_file") or ev.get("source")})
    for finding in detections:
        if finding.get("src_ip") and _looks_like_ip(finding["src_ip"]):
            observed_ips.add(str(finding["src_ip"]))
        ref = finding.get("id") or finding.get("rule_id") or finding.get("rule_name")
        for key, kind in (("attachment_names", "file"), ("domains", "domain"), ("destination_ip", "ip"), ("src_ip", "ip")):
            values = (finding.get("rule_information") or {}).get(key) or finding.get(key)
            if isinstance(values, str):
                values = [values]
            for value in values or []:
                if kind != "ip" or not _is_private(str(value)):
                    role = infrastructure_role(tactic=str(finding.get("mitre_tactic") or ""), field_role=str((finding.get("rule_information") or {}).get("infrastructure_role") or "")) if kind == "ip" else None
                    indicators.append({"type": kind, "value": str(value), "role": role, "source_finding": ref})
    for evidence in evidence_list:
        evidence_name = str(evidence.get("filename") or "")
        if evidence_name:
            indicators.append({"type": "file", "value": evidence_name, "source_finding": "Evidence inventory"})
        if evidence.get("sha256_hash"):
            indicators.append({"type": "file_hash", "value": str(evidence["sha256_hash"]), "source_finding": "Evidence inventory"})
    for indicator in indicators:
        indicator.setdefault("source_finding", next((str(f.get("id") or f.get("rule_id")) for f in detections if set(f.get("matching_event_ids") or []) & {indicator.get("source_event_id")}), "Observed event"))
    for roles in infrastructure_roles.values():
        if "C2" in roles:
            roles.discard("Payload")
    for address, roles in infrastructure_roles.items():
        source_finding = next((str(f.get("rule_name") or f.get("rule_id")) for f in detections if address in {str(f.get("actor") or ""), str(f.get("dst_ip") or ""), str((f.get("rule_information") or {}).get("destination_ip") or "")} or address in [str(v) for v in ((f.get("rule_information") or {}).get("destinations") or [])]), "Finding-linked network evidence")
        indicators.append({"type": "ip" if _looks_like_ip(address) else "domain", "value": address, "role": ", ".join(sorted(roles)), "source_finding": source_finding})
    indicator_rows = {(i["type"], i["value"], i.get("role"), i.get("source_finding"), i.get("source_file")) for i in indicators}
    indicators = [dict(type=t, value=v, role=role, source_finding=fr, source_file=sf) for t, v, role, fr, sf in sorted(indicator_rows, key=lambda row: tuple(str(value or "") for value in row))]

    # Group findings by tactic for attack sequence
    findings_by_tactic: Dict[str, List] = {}
    for f in sorted(detections, key=lambda x: str(x.get("first_seen", ""))):
        tactic = f.get("mitre_tactic", "Unknown")
        findings_by_tactic.setdefault(tactic, []).append(f)

    # Compute dwell time
    dwell_time_str = "Not determinable"
    timed_attack_events = [ev for ev in attack_events if ev.get("timestamp_timezone_known") is not False]
    if len(timed_attack_events) >= 2:
        try:
            t0 = datetime.fromisoformat(str(timed_attack_events[0]["timestamp"]).replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(str(timed_attack_events[-1]["timestamp"]).replace("Z", "+00:00"))
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
        # fix-6: use real uploader name (never "Unknown" when a name is stored)
        uploader_raw = ev.get("uploader_name") or ev.get("uploaded_by") or ""
        uploader = uploader_raw.strip() if uploader_raw.strip() else "Unattributed"
        chain_of_custody.append({
            "filename": ev.get("filename"),
            "sha256_hash": stored_hash,
            "hash_status": ev.get("hash_status") or hash_status(ev),
            "hash_verified_at": ev.get("hash_verified_at"),
            "uploaded_by": uploader,
            "uploaded_at": ev.get("uploaded_at"),
            "ingested_at": ev.get("ingested_at"),
            "event_count": ev.get("event_count", 0),
            "size_bytes": ev.get("size_bytes", 0),
            "hash_verified_at": ev.get("hash_verified_at"),
            "document_artifact": (ev.get("event_count", 0) == 0 and str(ev.get("filename", "")).lower().endswith((".txt", ".pdf", ".docx", ".doc", ".eml", ".msg", ".md", ".rtf"))),
        })

    audit_count = len(audit_entries) if audit_entries else None

    # ------------------------------------------------------------------
    # fix-8: Generated remediation from findings (no boilerplate)
    # ------------------------------------------------------------------
    def _short_ref(f: Dict[str, Any]) -> str:
        """Short, human-readable finding reference (rule name or short ID)."""
        name = f.get("rule_name") or f.get("rule_id") or f.get("id", "")
        # Remove UUID-like suffixes from rule IDs
        name = str(name).split("-")[:4]  # keep up to 4 segments
        return "-".join(name)

    remediation: List[Dict[str, str]] = []

    if adversary_infra:
        finding_ids = [
            _short_ref(f) for f in detections
            if f.get("actor_role") == "adversary_infrastructure"
            or (f.get("src_ip") and f.get("src_ip") in adversary_infra)
            or (f.get("actor") and f.get("actor") in adversary_infra)
        ]
        finding_ids = list(dict.fromkeys(fid for fid in finding_ids if fid))  # dedupe
        remediation.append({
            "action": f"Block at perimeter only after examiner review confirms the infrastructure indicators explicitly tagged by findings: {', '.join(sorted(adversary_infra))}.",
            "finding_refs": ", ".join(finding_ids[:6]),
        })

    if compromised_hosts:
        finding_ids = [
            _short_ref(f) for f in detections if f.get("target_role") == "compromised_host" or f.get("target_host") in compromised_hosts
        ]
        finding_ids = list(dict.fromkeys(fid for fid in finding_ids if fid))
        remediation.append({
            "action": f"Review hosts with matching detections ({', '.join(sorted(compromised_hosts))}); isolate or reimage only if examiner review confirms compromise.",
            "finding_refs": ", ".join(finding_ids[:6]),
        })

    if compromised_users:
        norm_comp_users = {norm_user(u) for u in compromised_users if norm_user(u)}
        finding_ids = [
            _short_ref(f) for f in detections
            if norm_user(f.get("user")) in norm_comp_users or f.get("actor_role") == "compromised_account"
        ]
        finding_ids = list(dict.fromkeys(fid for fid in finding_ids if fid))
        remediation.append({
            "action": f"Review accounts associated with detections ({', '.join(unique_users(compromised_users))}); reset credentials if examiner review confirms compromise.",
            "finding_refs": ", ".join(finding_ids[:6]),
        })

    # Tactic-specific remediations
    tactics_seen = {f.get("mitre_tactic") for f in detections}
    techniques_seen = {f.get("mitre_technique") for f in detections} | {
        t for f in detections for t in (f.get("mitre_techniques_all") or [])
    }

    if "Persistence" in tactics_seen:
        persist_findings = [f for f in detections if f.get("mitre_tactic") == "Persistence"]
        persist_ids = list(dict.fromkeys(_short_ref(f) for f in persist_findings if f.get("id")))
        # fix-8: tailor persistence advice to actual finding names
        persist_names = [f.get("rule_name", "") for f in persist_findings[:4]]
        advice_parts = ["Review persistence detections and confirm the mechanism before removal"]
        for pn in persist_names:
            pnl = pn.lower()
            if "run key" in pnl or "registry" in pnl:
                advice_parts.append("if confirmed, remove unauthorized Windows Run/RunOnce registry entries")
            if "authorized_keys" in pnl or "ssh" in pnl:
                advice_parts.append("if confirmed, remove unauthorized SSH authorized_keys entries")
            if "cron" in pnl:
                advice_parts.append("if confirmed, review and remove unauthorized crontab entries")
            if "webshell" in pnl or "web shell" in pnl:
                advice_parts.append("if confirmed, remove the web shell from the web root")
        remediation.append({
            "action": "; ".join(dict.fromkeys(advice_parts)) + ".",
            "finding_refs": ", ".join(persist_ids[:6]),
        })

    if "Exfiltration" in tactics_seen:
        exfil_ids = list(dict.fromkeys(_short_ref(f) for f in detections if f.get("mitre_tactic") == "Exfiltration" and f.get("id")))
        remediation.append({
            "action": "Review transfer detections and determine whether data was accessed or transferred; follow applicable response and notification procedures if exposure is confirmed.",
            "finding_refs": ", ".join(exfil_ids[:6]),
        })

    if "Impact" in tactics_seen:
        impact_findings = [f for f in detections if f.get("mitre_tactic") == "Impact"]
        impact_ids = list(dict.fromkeys(_short_ref(f) for f in impact_findings if f.get("id")))
        # fix-8: restore from backups for ransomware/destructive findings
        remediation.append({
            "action": "Review impact detections and confirm data loss or encryption before restoration. If confirmed, validate offline backup integrity and avoid connecting backup media to a host that has not been cleared.",
            "finding_refs": ", ".join(impact_ids[:6]),
        })

    # fix-8: krbtgt reset for NTDS.dit extraction
    if any(t in techniques_seen for t in ("T1003.003", "T1558", "T1558.001", "T1558.002", "T1558.003")):
        ntds_ids = list(dict.fromkeys(
            _short_ref(f) for f in detections
            if f.get("mitre_technique") in ("T1003.003", "T1558", "T1558.001", "T1558.002", "T1558.003")
            or any(t in (f.get("mitre_techniques_all") or []) for t in ("T1003.003", "T1558", "T1558.001"))
        ))
        remediation.append({
            "action": "If the NTDS.dit extraction detection is confirmed, follow domain recovery procedures, including two krbtgt password resets 48 hours apart and rotation of privileged and service-account credentials.",
            "finding_refs": ", ".join(ntds_ids[:6]),
        })

    vuln_findings = [f for f in detections if f.get("mitre_tactic") == "Initial Access" and "vuln" in str(f.get("rule_id", "")).lower()]
    if vuln_findings:
        vuln_ids = list(dict.fromkeys(_short_ref(f) for f in vuln_findings if f.get("id")))
        remediation.append({
            "action": "Review potential initial-access weaknesses identified by these detections and patch where exploitation is confirmed: " + "; ".join(f.get("rule_name", "") for f in vuln_findings[:3]) + ".",
            "finding_refs": ", ".join(vuln_ids[:5]),
        })

    if not remediation:
        remediation = [{"action": "None identified", "finding_refs": ""}]

    # ------------------------------------------------------------------
    # fix-9: Executive summary with GiB, ransomware family, phishing facts
    # ------------------------------------------------------------------
    first_seen = timed_attack_events[0].get("timestamp") if timed_attack_events else None
    last_seen = timed_attack_events[-1].get("timestamp") if timed_attack_events else None

    # Compute summary facts from evidence and detections
    total_bytes = sum(ev.get("size_bytes") or ev.get("file_size") or 0 for ev in evidence_list)
    exfil_gib = None
    for f in detections:
        ri = f.get("rule_information") or {}
        if ri.get("bytes_transferred"):
            try:
                exfil_gib = round(int(ri["bytes_transferred"]) / (1024**3), 2)
            except (TypeError, ValueError):
                pass

    facts: Dict[str, Any] = {}
    if total_bytes >= 1024:
        facts["evidence_gib"] = round(total_bytes / (1024**3), 3)
    if exfil_gib is not None:
        facts["exfil_gib"] = exfil_gib
    # Ransomware family / encrypted file count from mass-rename finding
    for f in detections:
        if f.get("mitre_technique") == "T1486" or "ransom" in str(f.get("rule_name", "")).lower() or "encrypt" in str(f.get("rule_name", "")).lower():
            desc = str(f.get("description", ""))
            # Try to extract file count
            import re as _re
            m = _re.search(r'(\d+)\s+(?:file|operation)', desc, _re.I)
            if m and not facts.get("encrypted_files"):
                facts["encrypted_files"] = int(m.group(1))
            # Try to extract extension / family name
            m2 = _re.search(r"'?\.([a-z0-9]{3,12})'?\s+(?:ransom|extension)", desc, _re.I)
            if m2 and not facts.get("ransomware_family"):
                facts["ransomware_family"] = m2.group(1).upper()
        # Phishing email from T1566.001 finding description
        if f.get("mitre_technique") in ("T1566", "T1566.001") and not facts.get("initial_access"):
            facts["initial_access"] = "macro-capable or script-bearing attachment delivery was observed; malicious content and execution are not established"

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
        facts=facts,
    )

    # ------------------------------------------------------------------
    # Evidence manifest (all hashes)
    # ------------------------------------------------------------------
    evidence_manifest = [
        {
            "filename": ev.get("filename"),
            "sha256_hash": ev.get("sha256_hash"),
            "size_bytes": ev.get("size_bytes") if ev.get("size_bytes") is not None else ev.get("file_size", 0),
            "size_display": _format_size(ev.get("size_bytes") if ev.get("size_bytes") is not None else ev.get("file_size", 0)),
            "hash_status": ev.get("hash_status") or "recorded (not re-verified)",
            "hash_verified_at": ev.get("hash_verified_at"),
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
        "id": f"rep-{case_id[:8]}-v{str(version).replace('.', '-')}",
        "case_id": case_id,
        "case_name": case_name,
        "generated_at": now_iso,
        "generator_name": gen_name,
        "generator_role": str(gen_role),
        "version": str(version),
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
        # fix-6: omit N/A audit line when no audit data
        "chain_of_custody_note": (
            "SHA-256 values are recorded at upload; current file comparisons were performed at the generation time shown for each file. "
            + (f"{audit_count} audit log entries are recorded for this case. " if audit_count is not None else "")
            + "A match reflects only the file available at generation time."
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
            "observed_ips": sorted(observed_ips) or ["None identified"],
            "dwell_time": dwell_time_str,
        },
        "entity_groups": {
            "compromised_hosts": sorted(compromised_hosts),
            "compromised_accounts": unique_users(compromised_users),
            "adversary_infrastructure": [
                {"address": address, "roles": sorted(roles)}
                for address, roles in sorted(infrastructure_roles.items())
            ],
            "other_observed_addresses": sorted(ip for ip in observed_ips if ip not in adversary_infra),
        },
        "indicators": indicators,
        # C2: generated, not boilerplate
        "remediation": remediation,
        # Legacy field kept
        "recommendations": [r["action"] for r in remediation],
        # C2: Methodology and Limitations
        "methodology": (
            "This report was produced by the DCSRE rule-based forensic engine. "
            "Detections are rule matches evaluated against normalized events; a match records a detection and does not by itself establish compromise or attribution. "
            "No AI, ML, or statistical inference was used. "
            "The engine detects only what its rule set describes; unknown or novel techniques "
            "not covered by the current rule set will not appear in findings."
        ),
        "limitations": (
            "Detections are limited to the current parser and rule-set versions in use at generation time. "
            "Event timestamps are sourced from the evidence files (event_time); "
            "upload times (ingested_at) are stored separately and do not appear as event times. "
            "All timestamps are normalised to UTC. "
            "Coverage depends on the enabled deterministic rules and parsers."
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

def _custody_entries(report_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    custody = report_data.get("chain_of_custody") or []
    if custody:
        return custody
    # Older saved snapshots may have the manifest but no custody list.
    return [
        {
            "filename": evidence.get("filename"),
            "sha256_hash": evidence.get("sha256_hash", ""),
            "hash_status": (
                "recorded (not re-verified)"
                if evidence.get("sha256_hash")
                else "not recorded"
            ),
            "uploaded_by": evidence.get("uploader") or evidence.get("uploaded_by") or "Unattributed",
            "uploaded_at": evidence.get("uploaded_at"),
            "event_count": evidence.get("event_count", 0),
            "size_bytes": evidence.get("size_bytes", 0),
        }
        for evidence in report_data.get("evidence_manifest") or report_data.get("evidence_inventory") or []
    ]

def render_report_html(report_data: Dict[str, Any]) -> str:
    is_draft = report_data.get("status", "DRAFT") == "DRAFT"

    def _hash_cls(st: Any) -> str:
        s = str(st or "")
        if s == "match":
            return "match"
        if "MISMATCH" in s:
            return "mismatch"
        return ""

    evidence_rows = "".join([
        f"<tr><td><code>{esc(e.get('filename'))}</code></td>"
        f"<td><code>{esc(e.get('sha256_hash', ''))}</code></td>"
        f"<td>{esc(e.get('size_display') or _format_size(e.get('size_bytes')))}</td>"
        f"<td>{'Document artifact' if e.get('document_artifact') else e.get('event_count', 0)}</td>"
        f"<td>{esc(e.get('uploader', 'Unknown'))}</td>"
        f"<td>{esc(e.get('uploaded_at', ''))}</td></tr>"
        for e in report_data.get("evidence_manifest", [])
    ]) or "<tr><td colspan='6'>None identified</td></tr>"

    custody_rows = "".join([
        f"<tr><td><code>{esc(c.get('filename'))}</code></td>"
        f"<td><code style='word-break:break-all;font-size:9px'>{esc(str(c.get('sha256_hash', '')))}</code></td>"
        f"<td class='{_hash_cls(c.get('hash_status'))}'>{esc(c.get('hash_status'))}</td>"
        f"<td>{esc(c.get('hash_verified_at') or 'Not available')}</td>"
        f"<td>{esc(_format_size(c.get('size_bytes')))}</td>"
        f"<td>{esc(c.get('uploaded_by', 'Unattributed'))}</td>"
        f"<td>{esc(c.get('uploaded_at', ''))}</td></tr>"
        for c in _custody_entries(report_data)
    ]) or "<tr><td colspan='7'>None identified</td></tr>"

    timeline_rows = "".join([
        f"<tr><td><code>{esc(_format_timeline_time(ev))}</code></td>"
        f"<td>{esc(ev.get('host', 'N/A'))}</td><td>{esc(ev.get('user', 'N/A'))}</td>"
        f"<td>{esc(ev.get('mitre_tactic', ''))}</td><td><code>{esc(ev.get('mitre_technique', ''))}</code></td>"
        f"<td>{esc(ev.get('action', ''))}</td><td>{esc(', '.join(ev.get('corroborated_by') or []))}</td>"
        f"<td>{esc(ev.get('source_file') or ev.get('source') or '')}</td>"
        f"<td>{esc(', '.join(ev.get('source_record_references') or []))}</td></tr>"
        for ev in report_data.get("attack_timeline_summary", [])
    ]) or "<tr><td colspan='9'>None identified</td></tr>"

    detection_rows = "".join([
        f"<tr><td><strong>{esc(d.get('rule_name'))}</strong></td>"
        f"<td><code>{esc(', '.join(d.get('mitre_techniques_all') or [d.get('mitre_technique', 'N/A')]))}</code></td>"
        f"<td>{esc(d.get('mitre_tactic', 'N/A'))}</td>"
        f"<td><span class='badge badge-{str(d.get('severity', '')).lower()}'>{esc(str(d.get('severity', '')).upper())}</span></td>"
        f"<td>{esc(d.get('target_host') or d.get('host', 'N/A'))}</td>"
        f"<td><code>{esc(_format_event_time(d.get('first_seen')))}</code></td>"
        f"<td>{esc(d.get('description', ''))}</td></tr>"
        for d in report_data.get("mitre_coverage", [])
    ]) or "<tr><td colspan='7'>None identified</td></tr>"
    indicator_rows = "".join(
        f"<tr><td>{esc(item.get('type'))}</td><td><code>{esc(item.get('value'))}</code></td><td>{esc(item.get('role') or 'Observed')}</td><td>{esc(item.get('source_finding') or 'Observed event')}</td></tr>"
        for item in report_data.get("indicators", [])
    ) or "<tr><td colspan='4'>None identified</td></tr>"
    artifact_rows = "".join(
        f"<li><strong>{esc(e.get('filename'))}</strong> — document artifact; {esc(e.get('size_display', _format_size(e.get('size_bytes'))))}</li>"
        for e in report_data.get("evidence_manifest", []) if e.get("document_artifact")
    ) or "<li>None identified</li>"

    rems_html = "".join([
        f"<li><strong>{html.escape(str(r.get('action', r if isinstance(r, str) else '')))}</strong>"
        f"{(' <em>(findings: ' + html.escape(str(r.get('finding_refs', ''))) + ')</em>') if isinstance(r, dict) and r.get('finding_refs') else ''}</li>"
        for r in report_data.get("remediation", [])
    ]) or "<li>None identified</li>"

    comp = report_data.get("compromised_assets", {})
    groups = report_data.get("entity_groups", {})
    comp_rows = (
        "".join(f"<tr><td>Compromised Host</td><td><strong>{esc(h)}</strong></td><td>Observed in finding-linked events</td></tr>" for h in groups.get("compromised_hosts", comp.get("hosts", [])) if h != "None identified")
        + "".join(f"<tr><td>Compromised Account</td><td><strong>{esc(u)}</strong></td><td>Observed in finding-linked events</td></tr>" for u in groups.get("compromised_accounts", comp.get("users", [])) if u != "None identified")
        + "".join(f"<tr><td>Adversary Infrastructure: {esc(', '.join(item.get('roles') or ['Other Observed Addresses']))}</td><td><strong>{esc(item.get('address'))}</strong></td><td>Finding-linked indicator; attribution requires review</td></tr>" for item in groups.get("adversary_infrastructure", []))
        + "".join(f"<tr><td>Other Observed Address</td><td><strong>{esc(ip)}</strong></td><td>Observed in evidence; no adversary role assigned</td></tr>" for ip in groups.get("other_observed_addresses", []))
    ) or "<tr><td colspan='3'>None identified</td></tr>"

    draft_banner = ""
    if is_draft:
        draft_banner = "<div class='draft-banner'>DRAFT - AUTO-GENERATED; EXAMINER REVIEW AND APPROVAL REQUIRED BEFORE USE AS EVIDENCE</div>"

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>DCSRE Forensic Report - {html.escape(report_data.get('case_name', ''))}</title>
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
    <tr><th>Report Version</th><td>{esc(report_data.get('version', '1.0'))}</td><th>Status</th><td class="{'mismatch' if is_draft else 'match'}">{report_data.get('status', 'DRAFT')}</td></tr>
  </table>

  <h2>1. Executive Summary</h2>
  <p>{html.escape(report_data.get('executive_summary', 'None identified'))}</p>

  <h2>2. Evidence Custody Manifest (all SHA-256 hashes)</h2>
  <p>{html.escape(report_data.get('chain_of_custody_note', ''))}</p>
  <table>
    <thead><tr><th>Filename</th><th>SHA-256 (full)</th><th>Hash Status</th><th>Verified At (UTC)</th><th>Size</th><th>Uploaded By</th><th>Uploaded At (UTC)</th></tr></thead>
    <tbody>{custody_rows}</tbody>
  </table>

  <h3>Document artifacts</h3><ul>{artifact_rows}</ul>

  <h2>3. Chronological Attack Sequence</h2>
  <table><thead><tr><th>Event Time (UTC where source specifies it)</th><th>Host</th><th>User</th><th>Tactic</th><th>Technique</th><th>Activity</th><th>Sources</th><th>Source File</th><th>Record References</th></tr></thead><tbody>{timeline_rows}</tbody></table>

  <h2>4. MITRE ATT&amp;CK Detections (first matching event time, UTC)</h2>
  <table>
    <thead><tr><th>Rule</th><th>Technique</th><th>Tactic</th><th>Severity</th><th>Host</th><th>First Seen (UTC)</th><th>Description</th></tr></thead>
    <tbody>{detection_rows}</tbody>
  </table>

  <h2>5. Compromised Scope &amp; Adversary Infrastructure</h2>
  <table>
    <thead><tr><th>Entity Type</th><th>Identifier</th><th>Status</th></tr></thead>
    <tbody>{comp_rows}</tbody>
  </table>

  <h2>6. Indicators</h2><table><thead><tr><th>Type</th><th>Indicator</th><th>Role</th><th>Source Finding</th></tr></thead><tbody>{indicator_rows}</tbody></table>

  <h2>7. Remediation Directives (generated from findings)</h2>
  <ul>{rems_html}</ul>

  <h2>8. Methodology &amp; Limitations</h2>
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
            footer = (
                "DCSRE REPORT - DRAFT; examiner approval required"
                if report_data.get("status", "DRAFT") == "DRAFT"
                else "DCSRE Forensic Report"
            )
            self.drawString(36, 22, footer)
            self.drawRightString(576, 22, f"Page {self._pageNumber} of {page_count}")
            self.restoreState()

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=70, bottomMargin=42)
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
        story.append(Paragraph("DRAFT - AUTO-GENERATED; EXAMINER REVIEW AND APPROVAL REQUIRED BEFORE USE AS EVIDENCE", draft_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#f95721"), spaceAfter=8))

    meta = [
        [Paragraph(f"<b>Incident:</b> {html.escape(str(report_data.get('case_name', '')))}",  cell_style),
         Paragraph(f"<b>Report ID:</b> {html.escape(str(report_data.get('id', '')))}",          cell_style),
         Paragraph(f"<b>Generated (UTC):</b> {html.escape(str(report_data.get('generated_at', '')))}",cell_style)],
        [Paragraph(f"<b>Investigator:</b> {html.escape(str(report_data.get('generator_name', '')))}",cell_style),
         Paragraph(f"<b>Version:</b> {html.escape(str(report_data.get('version', '1.0')))}", cell_style),
         Paragraph(f"<b>Status:</b> {html.escape(str(report_data.get('status', 'DRAFT')))}", cell_style)],
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
    ev_hdr = [[Paragraph(f"<b>{x}</b>", cell_bold) for x in ["Filename", "SHA-256 (full)", "Hash Status", "Uploaded By", "Uploaded At"]]]
    ev_rows = [
        [Paragraph(html.escape(str(c.get("filename",""))) + "<br/>" + html.escape(_format_size(c.get("size_bytes"))), cell_code),
         Paragraph(html.escape(str(c.get("sha256_hash",""))), cell_code),
         Paragraph(html.escape(str(c.get("hash_status","?"))) + "<br/>" + html.escape(str(c.get("hash_verified_at") or "Verification time unavailable")), cell_crit if "MISMATCH" in str(c.get("hash_status","")) else cell_style),
         Paragraph(html.escape(str(c.get("uploaded_by","") or "Unattributed")), cell_style),
         Paragraph(html.escape(str(c.get("uploaded_at",""))), cell_style)]
        for c in _custody_entries(report_data)
    ]
    ev_table_data = ev_hdr + (ev_rows if ev_rows else [[Paragraph("None identified", cell_style)] + [""]*4])
    t2 = Table(ev_table_data, colWidths=[90, 180, 60, 85, 125], repeatRows=1)
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 3), ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('WORDWRAP', (1,1), (1,-1), 1),
    ]))
    story.append(t2)
    story.append(Spacer(1, 4))
    artifact_names = [str(item.get("filename")) for item in report_data.get("evidence_manifest", []) if item.get("document_artifact")]
    story.append(Paragraph("<b>Document artifacts:</b> " + (html.escape(", ".join(artifact_names)) if artifact_names else "None identified"), body_style))

    story.append(Paragraph("5. Compromised Scope & Adversary Infrastructure", h2_style))
    comp = report_data.get("compromised_assets", {})
    comp_data = [
        [Paragraph("<b>Entity Type</b>", cell_bold), Paragraph("<b>Identifier</b>", cell_bold), Paragraph("<b>Status</b>", cell_bold)]
    ]
    for h in comp.get("hosts", []):
        if h != "None identified": comp_data.append([Paragraph("Host", cell_style), Paragraph(html.escape(str(h)), cell_bold), Paragraph("Observed in matching findings/events", cell_style)])
    for u in comp.get("users", []):
        if u != "None identified": comp_data.append([Paragraph("User Account", cell_style), Paragraph(html.escape(str(u)), cell_bold), Paragraph("Observed in matching findings/events", cell_style)])
    groups = report_data.get("entity_groups", {})
    for item in groups.get("adversary_infrastructure", []):
        comp_data.append([Paragraph("Adversary Infrastructure", cell_style), Paragraph(html.escape(str(item.get("address"))), cell_bold), Paragraph(html.escape(", ".join(item.get("roles") or ["Other Observed Addresses"])), cell_style)])
    for ip in groups.get("other_observed_addresses", []):
        comp_data.append([Paragraph("Other Observed Address", cell_style), Paragraph(html.escape(str(ip)), cell_bold), Paragraph("Observed in evidence; no adversary role assigned", cell_style)])
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
    det_hdr = [[Paragraph(f"<b>{x}</b>", cell_bold) for x in ["Rule", "Technique", "Tactic", "Severity", "Host", "First Seen", "Description"]]]
    det_rows = [
        [Paragraph(html.escape(str(d.get("rule_name",""))), cell_bold),
         Paragraph(html.escape(", ".join(d.get("mitre_techniques_all") or [d.get("mitre_technique", "N/A")])), cell_code),
         Paragraph(html.escape(str(d.get("mitre_tactic","N/A"))), cell_style),
         Paragraph(str(d.get("severity","")).upper(), cell_crit if str(d.get("severity","")) in ("critical","high") else cell_style),
         Paragraph(html.escape(str(d.get("target_host") or d.get("host","N/A"))), cell_style),
         Paragraph(html.escape(_format_event_time(d.get("first_seen"))), cell_code),
         Paragraph(html.escape(str(d.get("description",""))), cell_style)]
        for d in report_data.get("mitre_coverage", [])
    ]
    det_data = det_hdr + (det_rows if det_rows else [[Paragraph("None identified", cell_style)] + [""]*6])
    t4 = Table(det_data, colWidths=[100, 55, 75, 45, 65, 75, 125], repeatRows=1)
    t4.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 3), ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t4)
    story.append(Spacer(1, 4))

    story.append(Paragraph("3. Chronological Attack Sequence (event_time, UTC)", h2_style))
    tl_hdr = [[Paragraph(f"<b>{x}</b>", cell_bold) for x in ["Event Time (UTC where source specifies it)", "Host", "User", "Tactic / Technique / Activity", "Source files / records"]]]
    tl_rows = [
        [Paragraph(html.escape(_format_timeline_time(ev)), cell_code),
         Paragraph(html.escape(str(ev.get("host","N/A"))), cell_style),
         Paragraph(html.escape(str(ev.get("user","N/A"))), cell_style),
         Paragraph(html.escape(f"{ev.get('mitre_tactic', '')} {ev.get('mitre_technique', '')}: {ev.get('action', '')}"), cell_style),
         Paragraph(html.escape("; ".join((ev.get("corroborated_by") or []) + [str(ev.get("source_file") or ev.get("source") or ""), ", ".join(ev.get("source_record_references") or [])]).strip("; ")), cell_style)]
        for ev in report_data.get("attack_timeline_summary", [])
    ]
    tl_data = tl_hdr + (tl_rows if tl_rows else [[Paragraph("None identified", cell_style)] + [""]*4])
    t5 = Table(tl_data, colWidths=[100, 80, 80, 165, 115], repeatRows=1)
    t5.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 3), ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t5)
    story.append(Spacer(1, 4))

    story.append(Paragraph("6. Indicators", h2_style))
    ind_hdr = [[Paragraph(f"<b>{x}</b>", cell_bold) for x in ("Type", "Indicator", "Role", "Source Finding")]]
    ind_rows = [
        [Paragraph(html.escape(str(item.get("type", ""))), cell_style),
         Paragraph(html.escape(str(item.get("value", ""))), cell_code),
         Paragraph(html.escape(str(item.get("role") or "Observed")), cell_style),
         Paragraph(html.escape(str(item.get("source_finding") or "Observed event")), cell_style)]
        for item in report_data.get("indicators", [])
    ]
    ind_data = ind_hdr + (ind_rows if ind_rows else [[Paragraph("None identified", cell_style)] + [""] * 3])
    ind_table = Table(ind_data, colWidths=[65, 230, 90, 155], repeatRows=1)
    ind_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
    ]))
    story.append(ind_table)
    story.append(Spacer(1, 4))

    story.append(Paragraph("7. Remediation Directives (generated from findings)", h2_style))
    for idx, r in enumerate(report_data.get("remediation", []), 1):
        action = r.get("action", r) if isinstance(r, dict) else str(r)
        refs = r.get("finding_refs", "") if isinstance(r, dict) else ""
        txt = f"<b>{idx}.</b> {html.escape(str(action))}"
        if refs:
            txt += f" <i>(findings: {html.escape(str(refs))})</i>"
        story.append(Paragraph(txt, body_style))
        story.append(Spacer(1, 2))

    story.append(Paragraph("8. Methodology & Limitations", h2_style))
    story.append(Paragraph(f"<b>Methodology:</b> {html.escape(report_data.get('methodology',''))}", body_style))
    story.append(Spacer(1, 3))
    story.append(Paragraph(f"<b>Limitations:</b> {html.escape(report_data.get('limitations',''))}", body_style))
    story.append(Spacer(1, 6))

    hash_style = ParagraphStyle('Hash', parent=styles['Normal'],
        fontName='Courier', fontSize=7, leading=9, textColor=colors.HexColor('#64748b'))
    story.append(Paragraph(f"Report content SHA-256: {report_data.get('report_hash','not computed')}", hash_style))

    # Keep the PDF's sequence, detections, and scope in the same section order
    # as the HTML report (the builders share the underlying report data).
    def _section_index(prefix: str) -> int:
        return next(i for i, item in enumerate(story) if hasattr(item, "getPlainText") and item.getPlainText().startswith(prefix))
    scope_start = _section_index("5. Compromised Scope")
    detections_start = _section_index("4. Threat Detections")
    sequence_start = _section_index("3. Chronological Attack Sequence")
    indicators_start = _section_index("6. Indicators")
    scope_block = story[scope_start:detections_start]
    detections_block = story[detections_start:sequence_start]
    sequence_block = story[sequence_start:indicators_start]
    story[scope_start:indicators_start] = sequence_block + detections_block + scope_block

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()
