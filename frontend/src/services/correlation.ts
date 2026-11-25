import { DetectionResult, NormalizedEvent } from '../types';
import { isPrivateIpAddress } from '../utils/graphNodes';

export const MIN_CHAIN_CONFIDENCE = 0.70;

export interface AttackChain {
  id: string;
  name: string;
  events: NormalizedEvent[];
  entities: string[];
  startTime: string;
  endTime: string;
  confidenceScore: number; // 0.0 - 1.0 (FR-CORR-3)
  highestSeverity: 'low' | 'medium' | 'high' | 'critical';
}

const UNKNOWN_HOSTS = new Set(['', '-', 'unknown', 'unknown_host']);
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

function isIpLiteral(value?: string): boolean {
  return Boolean(value && IPV4_RE.test(value.trim()));
}

/**
 * Reconstructs detection-backed attack chains grouped by target host (FR-CORR-1..3)
 */
export function correlateAttackChains(
  events: NormalizedEvent[],
  detections: DetectionResult[] = [],
  _windowMinutes = 45,
  minConfidence = MIN_CHAIN_CONFIDENCE
): AttackChain[] {
  if (events.length === 0 || detections.length === 0) return [];

  const eventsById = new Map<string, NormalizedEvent>();
  for (const ev of events) {
    if (ev.id) eventsById.set(String(ev.id), ev);
  }
  if (eventsById.size === 0) return [];

  const nonIpHosts = new Set<string>();
  for (const ev of events) {
    const h = String(ev.host || '').trim();
    if (h && !UNKNOWN_HOSTS.has(h.toLowerCase()) && !isIpLiteral(h)) {
      nonIpHosts.add(h);
    }
  }
  const singleHost = nonIpHosts.size === 1 ? Array.from(nonIpHosts)[0] : '';

  const groups = new Map<string, {
    linkedIds: Set<string>;
    detections: Array<{ ts: number; tactic: string }>;
    detSrcIps: Set<string>;
  }>();

  for (const det of detections) {
    if (det.false_positive) continue;
    const matchedIds = (det.matched_event_ids || []).map(String);
    const linkedEvents = matchedIds
      .map(id => eventsById.get(id))
      .filter((ev): ev is NormalizedEvent => Boolean(ev));
    if (linkedEvents.length === 0) continue;

    let targetHost = String(
      det.target_host || det.host || det.rule_information?.target_host || det.rule_information?.host || det.hosts?.[0] || ''
    ).trim();
    if (!targetHost || UNKNOWN_HOSTS.has(targetHost.toLowerCase()) || isIpLiteral(targetHost)) {
      const fromEvent = linkedEvents.find(
        ev => ev.host && !UNKNOWN_HOSTS.has(ev.host.toLowerCase()) && !isIpLiteral(ev.host)
      )?.host;
      targetHost = fromEvent || singleHost || 'unknown_host';
    }

    let grp = groups.get(targetHost);
    if (!grp) {
      grp = { linkedIds: new Set(), detections: [], detSrcIps: new Set() };
      groups.set(targetHost, grp);
    }
    for (const ev of linkedEvents) grp.linkedIds.add(String(ev.id));
    for (const ip of [...(det.source_ips || []), ...(det.src_ip ? [det.src_ip] : [])]) {
      if (ip && ip !== '-') grp.detSrcIps.add(String(ip).trim());
    }
    const earliestMs = Math.min(...linkedEvents.map(ev => new Date(ev.timestamp).getTime() || 0));
    const tactic = String(det.mitre_tactic || det.rule_information?.tactic || '').trim();
    if (tactic) grp.detections.push({ ts: earliestMs, tactic });
  }

  const sevWeights: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  const chains: AttackChain[] = [];

  for (const [host, grp] of groups.entries()) {
    const orderedDets = [...grp.detections].sort((a, b) => a.ts - b.ts);
    const distinctTactics = new Set(orderedDets.map(d => d.tactic));
    if (distinctTactics.size < 3) continue;

    const confidenceScore = Math.min(0.95, Number((0.40 + 0.08 * distinctTactics.size).toFixed(2)));
    if (confidenceScore < minConfidence) continue;

    const linkedEvents = Array.from(grp.linkedIds)
      .map(id => eventsById.get(id)!)
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    const startTimeMs = new Date(linkedEvents[0].timestamp).getTime();
    const endTimeMs = new Date(linkedEvents[linkedEvents.length - 1].timestamp).getTime();

    const candidateSrcIps = new Set<string>(grp.detSrcIps);
    for (const ev of linkedEvents) {
      const sip = String(ev.src_ip || '').trim();
      if (!sip || sip === '-') continue;
      if (String(ev.host || '').trim() === sip && String(ev.dst_ip || '').trim()) continue;
      candidateSrcIps.add(sip);
    }
    const externalSrcIps = Array.from(candidateSrcIps).filter(ip => isIpLiteral(ip) && !isPrivateIpAddress(ip));
    const chainSrcIps = (externalSrcIps.length > 0 ? externalSrcIps : Array.from(candidateSrcIps)).sort();
    const chainSrcIpSet = new Set(chainSrcIps);

    const chainEventIds = new Set<string>(grp.linkedIds);
    const chainEvents: NormalizedEvent[] = [...linkedEvents];

    for (const ev of events) {
      const evId = String(ev.id);
      if (chainEventIds.has(evId)) continue;
      const isContext =
        ev.category === 'context' ||
        ev.source_type === 'vuln_scan' ||
        ev.metadata?.category === 'context' ||
        (ev as any).event_type === 'metric';
      if (isContext) continue;
      if (!ev.src_ip || !chainSrcIpSet.has(ev.src_ip.trim())) continue;
      const t = new Date(ev.timestamp).getTime();
      if (t < startTimeMs || t > endTimeMs) continue;
      chainEventIds.add(evId);
      chainEvents.push(ev);
    }

    chainEvents.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    const chainEntities = new Set<string>();
    if (host && !UNKNOWN_HOSTS.has(host.toLowerCase())) chainEntities.add(`host:${host}`);
    for (const sip of chainSrcIps) chainEntities.add(`ip:${sip}`);

    let highestSeverity: 'low' | 'medium' | 'high' | 'critical' = 'low';
    let maxWeight = 1;
    for (const e of chainEvents) {
      if (e.host && !UNKNOWN_HOSTS.has(e.host.toLowerCase()) && !isIpLiteral(e.host)) {
        chainEntities.add(`host:${e.host}`);
      }
      if (e.user && e.user !== 'unknown' && e.user !== 'SYSTEM') {
        chainEntities.add(`user:${e.user}`);
      }
      if (e.src_ip && e.src_ip !== '-') chainEntities.add(`ip:${e.src_ip}`);
      if (e.dst_ip && e.dst_ip !== '-') chainEntities.add(`ip:${e.dst_ip}`);
      const w = sevWeights[e.severity] || 1;
      if (w > maxWeight) {
        maxWeight = w;
        highestSeverity = e.severity;
      }
    }

    const firstTactic = orderedDets[0].tactic;
    const lastTactic = orderedDets[orderedDets.length - 1].tactic;
    const srcPrefix = chainSrcIps.join(', ');
    const title = srcPrefix
      ? `${srcPrefix} -> ${host}: ${firstTactic} -> ${lastTactic}`
      : `${host}: ${firstTactic} -> ${lastTactic}`;

    chains.push({
      id: `chain-${chains.length + 1}`,
      name: title,
      events: chainEvents,
      entities: Array.from(chainEntities),
      startTime: chainEvents[0].timestamp,
      endTime: chainEvents[chainEvents.length - 1].timestamp,
      confidenceScore,
      highestSeverity,
    });
  }

  return chains;
}
