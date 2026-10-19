import { NormalizedEvent } from '../types';

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

/**
 * Correlates events sharing common entities within time windows (FR-CORR-1, FR-CORR-2, FR-CORR-3)
 */
export function correlateAttackChains(events: NormalizedEvent[], windowMinutes = 30): AttackChain[] {
  if (events.length === 0) return [];

  const sorted = [...events].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  const chains: AttackChain[] = [];
  const visited = new Set<string>();

  for (let i = 0; i < sorted.length; i++) {
    const root = sorted[i];
    if (visited.has(root.id)) continue;

    const chainEvents: NormalizedEvent[] = [root];
    visited.add(root.id);

    const chainEntities = new Set<string>();
    const addEntities = (e: NormalizedEvent) => {
      if (e.host) chainEntities.add(`host:${e.host}`);
      if (e.user && e.user !== 'unknown') chainEntities.add(`user:${e.user}`);
      if (e.src_ip) chainEntities.add(`ip:${e.src_ip}`);
      if (e.dst_ip) chainEntities.add(`ip:${e.dst_ip}`);
    };
    addEntities(root);

    let lastTime = new Date(root.timestamp).getTime();

    for (let j = i + 1; j < sorted.length; j++) {
      const nextEvt = sorted[j];
      if (visited.has(nextEvt.id)) continue;

      const nextTime = new Date(nextEvt.timestamp).getTime();
      const timeDiffMinutes = (nextTime - lastTime) / (1000 * 60);

      if (timeDiffMinutes > windowMinutes && chainEvents.length >= 3) {
        // Break if exceeds correlation window
        break;
      }

      // Check entity intersection
      let sharesEntity = false;
      if (nextEvt.host && chainEntities.has(`host:${nextEvt.host}`)) sharesEntity = true;
      if (nextEvt.user && chainEntities.has(`user:${nextEvt.user}`)) sharesEntity = true;
      if (nextEvt.src_ip && (chainEntities.has(`ip:${nextEvt.src_ip}`) || chainEntities.has(`ip:${nextEvt.dst_ip}`))) sharesEntity = true;
      if (nextEvt.dst_ip && (chainEntities.has(`ip:${nextEvt.dst_ip}`) || chainEntities.has(`ip:${nextEvt.src_ip}`))) sharesEntity = true;

      if (sharesEntity) {
        chainEvents.push(nextEvt);
        visited.add(nextEvt.id);
        addEntities(nextEvt);
        lastTime = nextTime;
      }
    }

    if (chainEvents.length > 1) {
      // Calculate confidence score (FR-CORR-3)
      const hasCritical = chainEvents.some(e => e.severity === 'critical');
      const hasMitre = chainEvents.some(e => Boolean(e.mitre_technique));
      const entityCount = chainEntities.size;
      let score = 0.5;
      if (hasCritical) score += 0.25;
      if (hasMitre) score += 0.15;
      if (entityCount >= 3) score += 0.1;
      score = Math.min(1.0, score);

      const sevWeights = { critical: 4, high: 3, medium: 2, low: 1 };
      let highestSeverity: 'low' | 'medium' | 'high' | 'critical' = 'low';
      let maxWeight = 1;
      for (const e of chainEvents) {
        const w = sevWeights[e.severity] || 1;
        if (w > maxWeight) {
          maxWeight = w;
          highestSeverity = e.severity;
        }
      }

      chains.push({
        id: `chain-${root.id}`,
        name: `${chainEvents[0].action} -> ${chainEvents[chainEvents.length - 1].action}`,
        events: chainEvents,
        entities: Array.from(chainEntities),
        startTime: chainEvents[0].timestamp,
        endTime: chainEvents[chainEvents.length - 1].timestamp,
        confidenceScore: Number(score.toFixed(2)),
        highestSeverity
      });
    }
  }

  return chains;
}
