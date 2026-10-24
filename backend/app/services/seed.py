from sqlalchemy.orm import Session

from app.models.models import Playbook, PlaybookStep, User


def ensure_default_user(db: Session) -> User:
    """Ensure a default analyst user exists for case authorship (MVP)."""
    user = db.query(User).filter(User.username == "analyst").first()
    if user:
        return user
    user = User(username="analyst", display_name="Default Analyst")
    db.add(user)
    db.flush()
    return user

# Core digital forensics / DFIR playbooks (advisory checklists).
PLAYBOOKS = [
    {
        "name": "Evidence Collection & Chain of Custody",
        "incident_type": "evidence_collection",
        "description": "Foundational DFIR intake: preserve, hash, document, and transfer evidence.",
        "steps": [
            ("identify", "Define evidence scope", "List systems, accounts, media, and logs in scope.", "Write evidence request list"),
            ("identify", "Photograph / inventory physical media", "Label drives, bags, and seizure location.", "Complete evidence inventory form"),
            ("contain", "Isolate source without altering clocks", "Avoid powering off if volatile capture is needed; document state.", "Record system state"),
            ("contain", "Acquire forensic images", "Bit-for-bit disk/volume images with write-blockers where applicable.", "Create forensic image"),
            ("eradicate", "N/A — preservation focus", "Do not remediate until images and hashes are secured.", "Hold remediation"),
            ("recover", "Transfer to evidence vault", "Store originals and working copies separately.", "Secure evidence vault entry"),
            ("lessons", "Verify chain-of-custody log", "Confirm every handoff has actor, time, hash, and purpose.", "Sign CoC log"),
        ],
    },
    {
        "name": "Disk / Host Forensic Acquisition",
        "incident_type": "disk_forensics",
        "description": "Acquire and verify host disk images for offline analysis.",
        "steps": [
            ("identify", "Identify target volumes", "Map physical disks, VMs, snapshots, and cloud volumes.", "List target volumes"),
            ("identify", "Select acquisition method", "Live vs dead box; E01/AFF/raw; network or local.", "Document acquisition plan"),
            ("contain", "Attach write-blocker / snapshot", "Prevent writes to original evidence.", "Enable write protection"),
            ("contain", "Capture image + compute hashes", "SHA-256 (and MD5 if required) of source and image.", "Record hash set"),
            ("eradicate", "Create working copy", "Analyze only on verified working copies.", "Clone working image"),
            ("recover", "Return system to operations if cleared", "Only after counsel/IR lead approval.", "Release host if approved"),
            ("lessons", "Archive acquisition notes", "Tool versions, operator, time, hash mismatch checks.", "File acquisition report"),
        ],
    },
    {
        "name": "Memory Forensics",
        "incident_type": "memory_forensics",
        "description": "Capture and analyze volatile memory for malware, credentials, and injections.",
        "steps": [
            ("identify", "Confirm live system suitability", "Check RAM size, OS, and whether dump tools are approved.", "Approve memory capture"),
            ("contain", "Acquire memory dump", "Use validated tool; note tool hash and command line.", "Capture RAM image"),
            ("contain", "Collect supporting artifacts", "Running process list, netstat, loaded drivers if available.", "Export volatile snapshot notes"),
            ("eradicate", "Analyze for malware / injections", "Process trees, hollowed processes, injected DLLs, kernels.", "Run memory analysis"),
            ("recover", "Extract IOCs from memory", "IPs, domains, mutexes, injected PE hashes.", "Add IOCs to case"),
            ("lessons", "Document tool chain", "Volatility/Rekall profile, plugins, false positives.", "Update analysis notes"),
        ],
    },
    {
        "name": "Network Traffic / PCAP Investigation",
        "incident_type": "network_forensics",
        "description": "Investigate PCAP, flow, and proxy logs for C2, exfil, and lateral movement.",
        "steps": [
            ("identify", "Collect PCAP / NetFlow window", "Align capture window to suspected dwell time.", "Export PCAP/flow set"),
            ("identify", "Baseline normal traffic", "Identify expected services vs anomalies.", "Note baseline deviations"),
            ("contain", "Identify C2 / beaconing", "Periodic connections, rare destinations, DNS anomalies.", "List candidate C2"),
            ("contain", "Block confirmed malicious destinations", "Firewall/DNS sinkhole for confirmed IOCs.", "Apply network blocks"),
            ("eradicate", "Map lateral movement paths", "SMB, RDP, WinRM, SSH between hosts.", "Draw attack path"),
            ("recover", "Restore monitoring coverage", "Ensure sensors catch similar patterns.", "Validate sensor health"),
            ("lessons", "Tune IDS/NSM signatures", "Promote high-confidence detections.", "Update detection rules"),
        ],
    },
    {
        "name": "Log Analysis & Timeline Reconstruction",
        "incident_type": "log_timeline",
        "description": "Normalize multi-source logs into a forensic timeline.",
        "steps": [
            ("identify", "Inventory log sources", "EDR, auth, firewall, mail, cloud audit, host logs.", "Complete source checklist"),
            ("identify", "Normalize timestamps to UTC", "Resolve timezone and clock skew.", "Build UTC timeline"),
            ("contain", "Flag gaps / log clearing", "Detect Event ID 1102, audit policy changes, missing ranges.", "Document integrity issues"),
            ("eradicate", "Correlate across hosts/users", "Join by user, host, IP, hash within windows.", "Create correlation groups"),
            ("recover", "Publish investigator timeline", "Export annotated timeline for IR lead.", "Export timeline report"),
            ("lessons", "Improve log retention", "Note sources that were missing or rotated too soon.", "Raise retention ticket"),
        ],
    },
    {
        "name": "Malware Infection / Endpoint Compromise",
        "incident_type": "malware",
        "description": "Investigate and remediate endpoint malware infections.",
        "steps": [
            ("identify", "Triage alert & collect sample", "Preserve binary, script, and detonation notes.", "Quarantine sample"),
            ("identify", "Scope affected endpoints", "Hash/filename/behavior hunt across fleet.", "Build host hit list"),
            ("contain", "Isolate infected hosts", "EDR network isolation; preserve memory if needed.", "Isolate hosts"),
            ("eradicate", "Remove malware & persistence", "Services, Run keys, tasks, WMI, browser extensions.", "Remediate persistence"),
            ("recover", "Reimage or validate clean state", "Prefer reimage for high-confidence compromise.", "Rebuild/validate hosts"),
            ("lessons", "Update AV/EDR detections", "Submit samples; create custom detections.", "Push detection updates"),
        ],
    },
    {
        "name": "Ransomware / Encryption Event",
        "incident_type": "ransomware",
        "description": "Contain and recover from ransomware or mass encryption activity.",
        "steps": [
            ("identify", "Scope encrypted / targeted assets", "Identify patient-zero host and blast radius.", "Build affected-asset list"),
            ("identify", "Preserve ransom note & samples", "Do not delete notes; hash encryptor samples.", "Bag evidence package"),
            ("contain", "Isolate affected hosts", "Remove from network; preserve volatile evidence first if possible.", "Network-isolate hosts"),
            ("contain", "Disable privileged accounts used", "Disable service accounts or admins seen in the attack path.", "Disable abused accounts"),
            ("eradicate", "Remove malware & persistence", "Clear scheduled tasks, services, and dropper artifacts.", "Remediate persistence"),
            ("recover", "Restore from known-good backups", "Validate backup integrity before restore.", "Restore critical systems"),
            ("recover", "Validate business services", "Confirm apps and data integrity post-restore.", "Service health checks"),
            ("lessons", "Improve backup & segmentation", "Capture gaps that enabled spread.", "Update IR runbook"),
        ],
    },
    {
        "name": "Phishing / Malicious Mail",
        "incident_type": "phishing",
        "description": "Investigate and contain phishing campaigns and payload deliveries.",
        "steps": [
            ("identify", "Collect original message & headers", "Preserve .eml, headers, URLs, and attachments.", "Quarantine sample message"),
            ("identify", "Identify clicked recipients", "Correlate mail gateway / EDR click telemetry.", "List clickers"),
            ("contain", "Block sender & URLs", "Block at mail gateway and web proxy.", "Apply mail/URL blocks"),
            ("contain", "Purge remaining copies", "Remove campaign messages from mailboxes.", "Mailbox purge"),
            ("eradicate", "Remediate endpoint payloads", "If attachments executed, hunt and clean hosts.", "Endpoint remediation"),
            ("recover", "User awareness follow-up", "Notify affected users; reset creds if entered.", "User notification"),
            ("lessons", "Tune detections", "Add detections for similar lure patterns.", "Update detections"),
        ],
    },
    {
        "name": "Business Email Compromise (BEC)",
        "incident_type": "bec",
        "description": "Investigate invoice fraud, wire diversion, and mailbox takeover for financial abuse.",
        "steps": [
            ("identify", "Preserve suspect threads", "Keep full headers, forwarding rules, and sent items.", "Export mailbox evidence"),
            ("identify", "Trace financial requests", "Map who approved payments and which accounts were used.", "Build payment timeline"),
            ("contain", "Freeze related transactions", "Coordinate with finance/treasury immediately.", "Notify finance hold"),
            ("contain", "Reset mailbox & revoke sessions", "Disable attacker rules and app passwords.", "Secure mailbox"),
            ("eradicate", "Remove lookalike domains / rules", "Purge malicious inbox rules and delegates.", "Remove persistence"),
            ("recover", "Restore legitimate mail flow", "Confirm VIP mailboxes and vendor contacts.", "Validate mail routing"),
            ("lessons", "Strengthen payment verification", "Out-of-band confirmation procedures.", "Update finance controls"),
        ],
    },
    {
        "name": "Account Compromise",
        "incident_type": "account_compromise",
        "description": "Respond to suspected credential theft or account takeover.",
        "steps": [
            ("identify", "Confirm compromised identity", "Validate anomalous logins, MFA fatigue, or impossible travel.", "Review auth logs for the user"),
            ("identify", "Enumerate session & token exposure", "List active sessions, API keys, and OAuth grants.", "Export active sessions list"),
            ("contain", "Disable or reset credentials", "Force password reset and revoke refresh tokens.", "Reset password + revoke sessions"),
            ("contain", "Block related IOCs", "Block source IPs/ASNs and suspicious user-agents.", "Update blocklists"),
            ("eradicate", "Remove persistence", "Check inbox rules, MFA device changes, and scheduled tasks.", "Audit mailbox rules & MFA devices"),
            ("recover", "Restore legitimate access", "Re-enable account after validation; notify user.", "Re-enable account"),
            ("lessons", "Document root cause", "Capture phishing vector or credential stuffing source.", "Write lessons-learned note"),
        ],
    },
    {
        "name": "Credential Stuffing / Brute Force",
        "incident_type": "credential_attack",
        "description": "Investigate large-scale password guessing against exposed services.",
        "steps": [
            ("identify", "Identify targeted services & accounts", "VPN, SSO, SSH, RDP, web apps.", "List targeted portals"),
            ("contain", "Rate-limit / block source ranges", "WAF, IdP risk policies, firewall blocks.", "Apply rate limits"),
            ("contain", "Force resets for sprayed accounts", "Prioritize privileged and VIP accounts.", "Reset sprayed accounts"),
            ("eradicate", "Remove successful footholds", "Check for new MFA devices and sessions.", "Purge attacker sessions"),
            ("recover", "Restore service availability", "Clear lockouts for legitimate users.", "Clear lockout backlog"),
            ("lessons", "Enforce MFA & monitoring", "Add detections for spray patterns.", "Enable MFA gaps closure"),
        ],
    },
    {
        "name": "Data Exfiltration / Breach",
        "incident_type": "data_exfiltration",
        "description": "Determine what data left, how, and who was affected.",
        "steps": [
            ("identify", "Identify sensitive data stores touched", "DB, file shares, cloud buckets, SaaS exports.", "Map data stores"),
            ("identify", "Quantify volume & content", "Bytes transferred, file types, record counts.", "Estimate exposure"),
            ("contain", "Cut exfil channels", "Block destinations; revoke abused keys.", "Kill exfil path"),
            ("eradicate", "Remove staging artifacts", "Archives, temp shares, attacker tooling.", "Clean staging areas"),
            ("recover", "Notify stakeholders / legal", "Follow breach notification workflow.", "Start notification workflow"),
            ("lessons", "DLP & egress controls", "Close gaps that allowed bulk transfer.", "Tune DLP policies"),
        ],
    },
    {
        "name": "Insider Threat",
        "incident_type": "insider_threat",
        "description": "Investigate misuse by authorized users while preserving legal/HR constraints.",
        "steps": [
            ("identify", "Preserve HR/legal hold evidence", "Coordinate privilege and disclosure rules.", "Open legal hold"),
            ("identify", "Collect user activity artifacts", "Badge, VPN, file access, USB, email, code repos.", "Export activity set"),
            ("contain", "Limit access without tipping off", "Least-privilege reduction per policy.", "Reduce access scope"),
            ("eradicate", "Revoke residual access", "Keys, tokens, shared credentials, VPN certs.", "Full access revocation"),
            ("recover", "Restore team operations", "Reassign ownership of systems/data.", "Reassign ownership"),
            ("lessons", "Improve monitoring & offboarding", "Catch gaps in privileged monitoring.", "Update insider playbook"),
        ],
    },
    {
        "name": "Lateral Movement / Network Intrusion",
        "incident_type": "lateral_movement",
        "description": "Trace attacker movement across hosts after initial access.",
        "steps": [
            ("identify", "Find patient zero", "Earliest compromised host/account.", "Identify patient zero"),
            ("identify", "Map authentication graph", "Kerberos, NTLM, RDP, SSH, cloud assume-role.", "Build auth graph"),
            ("contain", "Isolate high-value targets", "DCs, jump hosts, CI/CD, backup servers.", "Protect crown jewels"),
            ("eradicate", "Evict from each hop", "Reset creds, remove implants per hop.", "Clear each hop"),
            ("recover", "Re-enable segmented access", "Validate trust boundaries.", "Restore segmented access"),
            ("lessons", "Harden privileged paths", "PAW, LAPS, tiering gaps.", "Close privilege gaps"),
        ],
    },
    {
        "name": "Web Application Attack",
        "incident_type": "web_attack",
        "description": "Respond to SQLi, XSS, RCE, defacement, or API abuse against web apps.",
        "steps": [
            ("identify", "Collect WAF/app/access logs", "Preserve request payloads and response codes.", "Export web logs"),
            ("identify", "Confirm exploit success", "Evidence of shell, data dump, or defacement.", "Confirm compromise depth"),
            ("contain", "Block exploit patterns", "WAF rules, IP blocks, disable vulnerable route.", "Apply WAF controls"),
            ("eradicate", "Remove webshells & backdoors", "Scan webroots, cron, new admin users.", "Clean webroot"),
            ("recover", "Patch & redeploy clean build", "From known-good CI artifacts.", "Redeploy clean release"),
            ("lessons", "Secure SDLC fixes", "Add regression tests for the flaw.", "File secure-dev ticket"),
        ],
    },
    {
        "name": "Cloud Account / Infrastructure Compromise",
        "incident_type": "cloud_compromise",
        "description": "Investigate abuse of cloud identities, keys, and workloads (AWS/Azure/GCP).",
        "steps": [
            ("identify", "Pull cloud audit trail", "CloudTrail, Activity Log, Admin Activity, IAM events.", "Export cloud audit"),
            ("identify", "Inventory impacted resources", "Instances, buckets, functions, secrets, IAM roles.", "Resource impact list"),
            ("contain", "Rotate keys & revoke sessions", "Access keys, federation tokens, service principals.", "Rotate credentials"),
            ("contain", "Isolate malicious workloads", "Quarantine SG/NSG; snapshot volumes.", "Quarantine workloads"),
            ("eradicate", "Remove attacker-created resources", "Backdoors, public buckets, rogue users.", "Delete attacker resources"),
            ("recover", "Restore least-privilege baselines", "Reapply IaC/guardrails.", "Reapply baselines"),
            ("lessons", "Strengthen cloud detections", "Alert on rare regions, key creation, privilege escalation.", "Enable cloud detections"),
        ],
    },
    {
        "name": "Supply Chain / Third-Party Compromise",
        "incident_type": "supply_chain",
        "description": "Respond when a vendor, package, or update channel is the intrusion vector.",
        "steps": [
            ("identify", "Identify tainted component", "Package version, update channel, MSP access path.", "Name tainted component"),
            ("contain", "Block / pin known-good versions", "Disable auto-update; revoke vendor access.", "Pin / revoke vendor"),
            ("eradicate", "Hunt for planted backdoors", "Review post-install scripts and new privileges.", "Hunt supply-chain IOCs"),
            ("recover", "Rebuild from trusted sources", "Reinstall from verified hashes/signatures.", "Rebuild trusted stack"),
            ("lessons", "Vendor risk improvements", "SBOM, code signing, least vendor privilege.", "Update vendor controls"),
        ],
    },
    {
        "name": "Lost / Stolen Device",
        "incident_type": "lost_device",
        "description": "Respond to missing laptops, phones, or tokens with potential data exposure.",
        "steps": [
            ("identify", "Confirm device inventory & last seen", "MDM last check-in, user report, location if available.", "Confirm device identity"),
            ("contain", "Remote lock / wipe", "Per policy; preserve forensic hold if criminal case.", "Issue MDM lock/wipe"),
            ("contain", "Revoke credentials & tokens", "VPN, SSO sessions, hardware tokens.", "Revoke access"),
            ("eradicate", "Assess data sensitivity on device", "Local files, cached email, unencrypted media.", "Data exposure assessment"),
            ("recover", "Issue replacement device", "Reprovision with full-disk encryption enforced.", "Provision replacement"),
            ("lessons", "Tighten device controls", "Encryption, short lock, tracking.", "Update device policy"),
        ],
    },
    {
        "name": "USB / Removable Media Incident",
        "incident_type": "removable_media",
        "description": "Investigate malware or data theft via USB and other removable media.",
        "steps": [
            ("identify", "Locate USB insertion events", "Host logs, EDR device control, autorun artifacts.", "List USB events"),
            ("contain", "Seize / image the media", "Write-blocked acquisition of the stick/drive.", "Image removable media"),
            ("eradicate", "Clean infected hosts", "Remove droppers introduced via media.", "Remediate hosts"),
            ("recover", "Restore device-control policy", "Block unapproved classes of devices.", "Enforce USB policy"),
            ("lessons", "User education & exceptions process", "Document approved use cases.", "Update USB exceptions"),
        ],
    },
    {
        "name": "Mobile Device Forensics",
        "incident_type": "mobile_forensics",
        "description": "Acquire and analyze mobile devices related to an investigation.",
        "steps": [
            ("identify", "Document device state", "Make/model, OS, lock status, airplane mode, SIM.", "Device intake form"),
            ("contain", "Isolate from networks", "Faraday bag / airplane; avoid remote wipe.", "RF isolate device"),
            ("contain", "Perform approved acquisition", "Logical/filesystem/physical per capability & warrant.", "Acquire mobile image"),
            ("eradicate", "N/A — analysis focus", "Extract chats, accounts, location, artifacts.", "Parse mobile artifacts"),
            ("recover", "Return or retain per legal hold", "Follow custody instructions.", "Update custody status"),
            ("lessons", "Tool & profile notes", "Record tool versions and parse gaps.", "Archive parse report"),
        ],
    },
    {
        "name": "Cryptomining / Resource Abuse",
        "incident_type": "cryptomining",
        "description": "Investigate unauthorized mining or compute abuse on endpoints or cloud.",
        "steps": [
            ("identify", "Confirm miner process / pool traffic", "CPU spikes, known pool domains, wallet configs.", "Confirm mining indicators"),
            ("contain", "Isolate hosts / kill workloads", "Stop containers/VMs burning spend.", "Stop abusive workloads"),
            ("eradicate", "Remove miner & persistence", "Cron, services, browser extensions, cloud jobs.", "Remove miner"),
            ("recover", "Patch initial access path", "Often exposed RDP/SSH or vulnerable app.", "Close entry point"),
            ("lessons", "Cost & detection alerts", "Budget anomaly + process detections.", "Add spend/process alerts"),
        ],
    },
    {
        "name": "DDoS / Availability Attack",
        "incident_type": "ddos",
        "description": "Mitigate and investigate volumetric or application-layer denial of service.",
        "steps": [
            ("identify", "Characterize attack traffic", "Protocol, source distribution, target URIs.", "Attack profile notes"),
            ("contain", "Enable scrubbing / WAF / rate limits", "CDN/ISP mitigation as applicable.", "Engage mitigation"),
            ("eradicate", "Block persistent sources", "Update ACLs for confirmed bad sources.", "Apply lasting blocks"),
            ("recover", "Restore full service", "Scale down emergency limits carefully.", "Restore capacity"),
            ("lessons", "Hardening & runbooks", "Pre-authorize mitigation contacts.", "Update DDoS runbook"),
        ],
    },
    {
        "name": "DNS / Domain Hijacking",
        "incident_type": "dns_hijack",
        "description": "Respond to unauthorized DNS changes or registrar account compromise.",
        "steps": [
            ("identify", "Diff DNS / registrar changes", "NS, A/AAAA, MX, TXT, registrar contacts.", "Export DNS change log"),
            ("contain", "Lock registrar & revert records", "Enable registry lock; restore known-good DNS.", "Revert DNS + lock"),
            ("eradicate", "Rotate registrar credentials", "Remove rogue users/API tokens.", "Secure registrar account"),
            ("recover", "Validate mail & web resolution", "Check propagation and certificate issuance.", "Validate resolution"),
            ("lessons", "Registrar hardening", "Registry lock, MFA, monitoring.", "Enable registry lock"),
        ],
    },
    {
        "name": "APT / Targeted Intrusion",
        "incident_type": "apt",
        "description": "Long-dwell targeted intrusion requiring stealthy scoping and coordinated eviction.",
        "steps": [
            ("identify", "Establish quiet scoping cell", "Limit knowledge; preserve evidence carefully.", "Form scoped IR cell"),
            ("identify", "Hunt for stealth persistence", "Golden tickets, implants, dual-use tools.", "Stealth persistence hunt"),
            ("contain", "Strategic containment plan", "Avoid tipping adversary before eviction window.", "Approve eviction plan"),
            ("eradicate", "Coordinated eviction", "Reset krbtgt/credentials; remove implants in waves.", "Execute eviction"),
            ("recover", "Heighten monitoring period", "Watch for re-entry attempts.", "Elevated monitoring"),
            ("lessons", "Threat intel packaging", "TTPs, IOCs, attribution caveats.", "Publish TI package"),
        ],
    },
    {
        "name": "Anti-Forensics / Log Tampering",
        "incident_type": "anti_forensics",
        "description": "Detect and respond when an adversary clears logs or destroys evidence.",
        "steps": [
            ("identify", "Detect clearing / timestomping", "Security log clears, USN journal gaps, $MFT anomalies.", "Flag integrity gaps"),
            ("contain", "Snapshot remaining evidence ASAP", "Prioritize volatile + remaining logs.", "Emergency evidence capture"),
            ("eradicate", "Restore logging & harden audit policy", "Re-enable channels; forward logs off-host.", "Fix audit pipeline"),
            ("recover", "Rebuild timeline from alternate sources", "EDR, network, cloud, backups.", "Alternate-source timeline"),
            ("lessons", "Centralize immutable logging", "WORM/SIEM forwarding gaps.", "Close logging gaps"),
        ],
    },
]


def seed_playbooks(db: Session) -> None:
    """Insert any missing playbooks (safe to re-run after expanding the catalog)."""
    existing_names = {name for (name,) in db.query(Playbook.name).all()}
    added = 0
    for pb in PLAYBOOKS:
        if pb["name"] in existing_names:
            continue
        playbook = Playbook(
            name=pb["name"],
            incident_type=pb["incident_type"],
            description=pb["description"],
        )
        db.add(playbook)
        db.flush()
        for idx, (phase, title, guidance, action) in enumerate(pb["steps"]):
            db.add(
                PlaybookStep(
                    playbook_id=playbook.id,
                    order_index=idx,
                    phase=phase,
                    title=title,
                    guidance=guidance,
                    recommended_action=action,
                )
            )
        added += 1
    if added:
        db.commit()
    else:
        db.rollback()
