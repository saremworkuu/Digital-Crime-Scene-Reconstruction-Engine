# Scenario 1: Operation Cobalt Shadow (DMZ to DC Breach)

## Attack Sequence
1. **recon & access**: HTTP requests from external IP `198.51.100.42` targeting `web01.corp.local` (`access.log`).
2. **web shell**: File upload to `/uploads/shell.php` followed by command execution.
3. **privilege escalation**: Sudo caching exploit elevating `www-data` to `root` (`auth.log`).
4. **lateral movement**: SMB pass-the-hash logon from `web01` to Domain Controller `dc01.corp.local` (`windows-security.evtx`).
5. **defense evasion**: Encoded PowerShell command execution and volume shadow copy deletion (`vssadmin.exe`).
6. **exfiltration**: Encrypted egress traffic of Active Directory NTDS database to adversary C2 endpoint (`capture.pcap`).
