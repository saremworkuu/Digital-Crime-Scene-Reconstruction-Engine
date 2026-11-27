import type { DetectionResult, NormalizedEvent } from '../types/index.ts';

export const MITRE_TACTIC_ORDER = [
  'reconnaissance',
  'resource development',
  'initial access',
  'execution',
  'persistence',
  'privilege escalation',
  'defense evasion',
  'credential access',
  'discovery',
  'lateral movement',
  'collection',
  'command and control',
  'exfiltration',
  'impact',
] as const;

const TACTIC_ALIASES: Record<string, string> = {
  'command & control': 'command and control',
  'c2': 'command and control',
  'priv esc': 'privilege escalation',
};

export function normalizeTacticKey(tactic?: string): string {
  const cleaned = String(tactic || '').trim().toLowerCase();
  return TACTIC_ALIASES[cleaned] || cleaned;
}

export function getTacticRank(tactic?: string): number {
  const parts = String(tactic || '')
    .split(',')
    .map((p) => normalizeTacticKey(p))
    .filter(Boolean);
  if (parts.length === 0) return MITRE_TACTIC_ORDER.length;

  let best: number = MITRE_TACTIC_ORDER.length;
  for (const part of parts) {
    const idx = MITRE_TACTIC_ORDER.indexOf(part as (typeof MITRE_TACTIC_ORDER)[number]);
    if (idx !== -1 && idx < best) {
      best = idx;
    }
  }
  return best;
}

export function getDisplayTacticName(tactic?: string): string {
  const parts = String(tactic || '')
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
  if (parts.length === 0) return 'Unclassified';

  let bestPart = parts[0];
  let bestRank = MITRE_TACTIC_ORDER.length + 1;
  for (const part of parts) {
    const rank = getTacticRank(part);
    if (rank < bestRank) {
      bestRank = rank;
      bestPart = part;
    }
  }
  const canonical = normalizeTacticKey(bestPart);
  if (canonical === 'command and control') return 'Command and Control';
  return bestPart;
}

export function parseUtcTimestampMs(ts?: string): number {
  const raw = String(ts || '').trim();
  if (!raw) return Number.MAX_SAFE_INTEGER;
  const isoCandidate =
    /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(raw) && !/[zZ]|[+-]\d{2}:?\d{2}$/.test(raw)
      ? `${raw.replace(' ', 'T')}Z`
      : raw;
  const ms = Date.parse(isoCandidate);
  return Number.isFinite(ms) ? ms : Number.MAX_SAFE_INTEGER;
}

export function resolveFindingFirstSeen(
  finding: DetectionResult,
  eventsById?: Map<string, NormalizedEvent>,
): string {
  const explicit = finding.rule_information?.first_seen;
  if (explicit && parseUtcTimestampMs(String(explicit)) !== Number.MAX_SAFE_INTEGER) {
    return String(explicit);
  }
  if (eventsById && Array.isArray(finding.matched_event_ids)) {
    let earliestTs = '';
    let earliestMs = Number.MAX_SAFE_INTEGER;
    for (const eid of finding.matched_event_ids) {
      const ev = eventsById.get(String(eid));
      if (!ev?.timestamp) continue;
      const ms = parseUtcTimestampMs(ev.timestamp);
      if (ms < earliestMs) {
        earliestMs = ms;
        earliestTs = ev.timestamp;
      }
    }
    if (earliestTs) return earliestTs;
  }
  return String(finding.timestamp || '');
}

export function sortFindingsChronologically(
  findings: DetectionResult[],
  events: NormalizedEvent[] = [],
): DetectionResult[] {
  const eventsById = new Map(events.map((e) => [String(e.id), e]));
  return [...findings].sort((a, b) => {
    const timeDiff =
      parseUtcTimestampMs(resolveFindingFirstSeen(a, eventsById)) -
      parseUtcTimestampMs(resolveFindingFirstSeen(b, eventsById));
    if (timeDiff !== 0) return timeDiff;
    const nameDiff = String(a.rule_name || '').localeCompare(String(b.rule_name || ''));
    if (nameDiff !== 0) return nameDiff;
    return String(a.id || '').localeCompare(String(b.id || ''));
  });
}

export interface TacticGroup {
  tacticKey: string;
  tacticLabel: string;
  tacticRank: number;
  findings: DetectionResult[];
}

export function groupFindingsByTactic(
  findings: DetectionResult[],
  events: NormalizedEvent[] = [],
): TacticGroup[] {
  const eventsById = new Map(events.map((e) => [String(e.id), e]));
  const groupsMap = new Map<string, TacticGroup>();

  for (const finding of findings) {
    const label = getDisplayTacticName(finding.mitre_tactic);
    const key = normalizeTacticKey(label) || 'unclassified';
    const rank = getTacticRank(label);
    let grp = groupsMap.get(key);
    if (!grp) {
      grp = {
        tacticKey: key,
        tacticLabel: label,
        tacticRank: rank,
        findings: [],
      };
      groupsMap.set(key, grp);
    }
    grp.findings.push(finding);
  }

  const groups = Array.from(groupsMap.values());
  groups.sort((a, b) => {
    if (a.tacticRank !== b.tacticRank) return a.tacticRank - b.tacticRank;
    return a.tacticLabel.localeCompare(b.tacticLabel);
  });

  for (const grp of groups) {
    grp.findings.sort((a, b) => {
      const timeDiff =
        parseUtcTimestampMs(resolveFindingFirstSeen(a, eventsById)) -
        parseUtcTimestampMs(resolveFindingFirstSeen(b, eventsById));
      if (timeDiff !== 0) return timeDiff;
      return String(a.rule_name || '').localeCompare(String(b.rule_name || ''));
    });
  }

  return groups;
}
