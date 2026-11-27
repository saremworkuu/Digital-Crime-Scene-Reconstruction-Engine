import test from 'node:test';
import assert from 'node:assert/strict';

import type { DetectionResult } from '../types/index.ts';
import {
  groupFindingsByTactic,
  sortFindingsChronologically,
} from './attackPathOrder.ts';

function makeFinding(overrides: Partial<DetectionResult>): DetectionResult {
  return {
    id: overrides.id || 'det-1',
    rule_id: overrides.rule_id || 'rule-1',
    rule_name: overrides.rule_name || 'Rule 1',
    severity: overrides.severity || 'high',
    mitre_technique: overrides.mitre_technique || 'T1059',
    mitre_tactic: overrides.mitre_tactic || 'Execution',
    timestamp: overrides.timestamp || '2026-07-22T01:00:00Z',
    description: overrides.description || 'desc',
    matched_event_ids: overrides.matched_event_ids || ['ev-1'],
    false_positive: false,
    rule_information: overrides.rule_information || {},
    entities_involved: overrides.entities_involved || { hosts: [], users: [], ips: [] },
  };
}

test('sortFindingsChronologically orders strictly by first_seen and breaks ties by rule_name', () => {
  const fLateInitAccess = makeFinding({
    id: 'f-late-init',
    rule_name: 'SQL Injection',
    mitre_tactic: 'Initial Access',
    rule_information: { first_seen: '2026-07-22 00:30:00' },
  });
  const fEarlyImpact = makeFinding({
    id: 'f-early-impact',
    rule_name: 'Crypto Mining',
    mitre_tactic: 'Impact',
    rule_information: { first_seen: '2026-07-22T00:10:00Z' },
  });

  const sorted = sortFindingsChronologically([fLateInitAccess, fEarlyImpact]);
  assert.deepEqual(
    sorted.map((f) => f.id),
    ['f-early-impact', 'f-late-init'],
  );
});

test('groupFindingsByTactic groups findings into MITRE ATT&CK tactic sequence separately from chronological order', () => {
  const fEarlyImpact = makeFinding({
    id: 'f-impact',
    rule_name: 'Crypto Mining',
    mitre_tactic: 'Impact',
    rule_information: { first_seen: '2026-07-22T00:05:00Z' },
  });
  const fMidPersistA = makeFinding({
    id: 'f-persist-1',
    rule_name: 'Cron Persistence',
    mitre_tactic: 'Persistence',
    rule_information: { first_seen: '2026-07-22T00:10:00Z' },
  });
  const fLateInitAccess = makeFinding({
    id: 'f-init',
    rule_name: 'Web Scanner',
    mitre_tactic: 'Initial Access',
    rule_information: { first_seen: '2026-07-22T00:20:00Z' },
  });
  const fLatestPersistB = makeFinding({
    id: 'f-persist-2',
    rule_name: 'SSH Key Added',
    mitre_tactic: 'Persistence',
    rule_information: { first_seen: '2026-07-22T00:30:00Z' },
  });

  const chron = sortFindingsChronologically([
    fLatestPersistB,
    fLateInitAccess,
    fEarlyImpact,
    fMidPersistA,
  ]);
  assert.deepEqual(
    chron.map((f) => f.id),
    ['f-impact', 'f-persist-1', 'f-init', 'f-persist-2'],
  );

  const grouped = groupFindingsByTactic(chron);
  assert.deepEqual(
    grouped.map((g) => g.tacticLabel),
    ['Initial Access', 'Persistence', 'Impact'],
  );
  assert.deepEqual(
    grouped.flatMap((g) => g.findings.map((f) => f.id)),
    ['f-init', 'f-persist-1', 'f-persist-2', 'f-impact'],
  );
});
