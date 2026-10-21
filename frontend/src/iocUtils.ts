/** Client-side IOC format checks mirrored from backend. */

export const IOC_TYPES = ["ip", "domain", "hash", "user", "host", "email", "url"] as const;
export type IocType = (typeof IOC_TYPES)[number];

export const IOC_STATUS = ["observed", "blocked", "monitoring", "false_positive"] as const;

export const IOC_PLACEHOLDERS: Record<IocType, string> = {
  ip: "192.0.2.10",
  domain: "evil.example.com",
  hash: "a1b2… (MD5/SHA1/SHA256)",
  user: "DOMAIN\\alice",
  host: "ws-1042",
  email: "phish@evil.example",
  url: "https://evil.example/path",
};

export const IOC_HINTS: Record<IocType, string> = {
  ip: "Block FW → hunt connections",
  domain: "Block DNS/proxy → hunt lookups",
  hash: "Quarantine → hash-hunt endpoints",
  user: "Disable account → revoke sessions",
  host: "Isolate host → preserve volatile",
  email: "Block sender → purge mailboxes",
  url: "Block URL → check click telemetry",
};

const DOMAIN_RE =
  /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$/i;
const EMAIL_RE =
  /^[a-z0-9](?:[a-z0-9._%+-]{0,62}[a-z0-9])?@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const HASH_RE = /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/;
const USER_RE = /^[A-Za-z0-9._\\@-]{1,128}$/;
const HOST_RE =
  /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$/;
const IPV4_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const IPV6_RE = /^[0-9a-f:]+$/i;

function isIp(value: string): boolean {
  if (IPV4_RE.test(value)) return true;
  if (value.includes(":") && IPV6_RE.test(value) && value.split(":").length >= 3) return true;
  return false;
}

export function validateIocValue(iocType: string, value: string): string | null {
  const cleaned = value.trim();
  if (!cleaned) return "Value is required";

  switch (iocType) {
    case "ip":
      return isIp(cleaned) ? null : "Enter a valid IPv4 or IPv6 address (letters alone are not allowed)";
    case "domain":
      return DOMAIN_RE.test(cleaned.replace(/\.$/, ""))
        ? null
        : "Enter a valid domain (e.g. evil.example.com)";
    case "email":
      return EMAIL_RE.test(cleaned) ? null : "Enter a valid email address";
    case "url":
      try {
        const u = new URL(cleaned);
        return u.protocol === "http:" || u.protocol === "https:"
          ? null
          : "URL must start with http:// or https://";
      } catch {
        return "Enter a valid http(s) URL";
      }
    case "hash":
      return HASH_RE.test(cleaned) ? null : "Hash must be MD5 (32), SHA1 (40), or SHA256 (64) hex";
    case "user":
      return USER_RE.test(cleaned) ? null : "Enter a valid username (DOMAIN\\user or user@corp)";
    case "host":
      return isIp(cleaned) || HOST_RE.test(cleaned)
        ? null
        : "Enter a hostname or IP (e.g. ws-1042)";
    default:
      return null;
  }
}

/** Common ATT&CK techniques for autofill. Unknown IDs get CUSTOM-NNN server-side. */
export const MITRE_CATALOG: Record<string, { name: string; tactic: string }> = {
  T1059: { name: "Command and Scripting Interpreter", tactic: "Execution" },
  "T1059.001": { name: "PowerShell", tactic: "Execution" },
  "T1059.003": { name: "Windows Command Shell", tactic: "Execution" },
  T1078: { name: "Valid Accounts", tactic: "Defense Evasion" },
  "T1078.002": { name: "Domain Accounts", tactic: "Defense Evasion" },
  T1021: { name: "Remote Services", tactic: "Lateral Movement" },
  "T1021.001": { name: "Remote Desktop Protocol", tactic: "Lateral Movement" },
  "T1021.002": { name: "SMB/Windows Admin Shares", tactic: "Lateral Movement" },
  T1566: { name: "Phishing", tactic: "Initial Access" },
  "T1566.001": { name: "Spearphishing Attachment", tactic: "Initial Access" },
  "T1566.002": { name: "Spearphishing Link", tactic: "Initial Access" },
  T1204: { name: "User Execution", tactic: "Execution" },
  "T1204.002": { name: "Malicious File", tactic: "Execution" },
  T1003: { name: "OS Credential Dumping", tactic: "Credential Access" },
  "T1003.001": { name: "LSASS Memory", tactic: "Credential Access" },
  T1048: { name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
  T1041: { name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
  T1486: { name: "Data Encrypted for Impact", tactic: "Impact" },
  T1490: { name: "Inhibit System Recovery", tactic: "Impact" },
  T1105: { name: "Ingress Tool Transfer", tactic: "Command and Control" },
  T1071: { name: "Application Layer Protocol", tactic: "Command and Control" },
  "T1071.001": { name: "Web Protocols", tactic: "Command and Control" },
  T1218: { name: "System Binary Proxy Execution", tactic: "Defense Evasion" },
  T1036: { name: "Masquerading", tactic: "Defense Evasion" },
  T1547: { name: "Boot or Logon Autostart Execution", tactic: "Persistence" },
  T1053: { name: "Scheduled Task/Job", tactic: "Persistence" },
  T1110: { name: "Brute Force", tactic: "Credential Access" },
  T1082: { name: "System Information Discovery", tactic: "Discovery" },
  T1083: { name: "File and Directory Discovery", tactic: "Discovery" },
  T1018: { name: "Remote System Discovery", tactic: "Discovery" },
  T1489: { name: "Service Stop", tactic: "Impact" },
};
