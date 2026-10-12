# Forensic Use Cases

## Use Case 1: External Breach to Lateral Movement (Operation Cobalt Shadow)
1. **Initial Access**: Adversary uploads web shell `shell.php` via Apache file upload vulnerability (`T1190`, `T1505.003`).
2. **Execution**: Adversary runs `whoami` and spawns interactive shell (`T1059.004`).
3. **Privilege Escalation**: Adversary abuses cached sudo permissions to elevate from `www-data` to `root` (`T1548.003`).
4. **Credential Access & Lateral Movement**: Adversary extracts credentials and connects to Active Directory DC01 via PsExec (`T1021.002`).
5. **Impact**: Deletion of volume shadow copies (`T1490`) and database exfiltration over TLS (`T1041`).

## Use Case 2: Ransomware Outbreak (DarkLock)
1. Phishing email payload execution via Macro/PowerShell.
2. Volume shadow copies deleted using `vssadmin.exe delete shadows /all /quiet`.
3. System files encrypted and ransom note dropped.
