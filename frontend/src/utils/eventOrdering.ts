import { NormalizedEvent } from '../types';

function padMicroseconds(ts: string): string {
  const iso = String(ts || '').trim();
  const match = iso.match(/^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:\.(\d+))?(.*)$/);
  if (!match) return iso;
  const frac = (match[2] || '').padEnd(6, '0').slice(0, 6);
  const msTime = new Date(iso).getTime();
  if (Number.isNaN(msTime)) return iso;
  const wholeSec = Math.floor(msTime / 1000);
  const secStr = String(wholeSec).padStart(13, '0');
  return `${secStr}.${frac}`;
}

function extractRecordIndex(ev: NormalizedEvent): [number, number, string] {
  const details = (ev as any).metadata || (ev as any).details || {};
  const candidate =
    (ev as any).source_record_id ??
    details.source_record_id ??
    details.record_id ??
    details.event_record_id ??
    details.line_number ??
    details.record_number ??
    details.packet_number;
  if (candidate === undefined || candidate === null || candidate === '') {
    return [2, 0, ''];
  }
  const str = String(candidate).trim();
  const num = Number(str);
  if (Number.isInteger(num) && /^-?\d+$/.test(str)) {
    return [0, num, ''];
  }
  return [1, 0, str];
}

export function compareEventsDeterministically(a: NormalizedEvent, b: NormalizedEvent): number {
  const tsA = padMicroseconds(a.timestamp);
  const tsB = padMicroseconds(b.timestamp);
  if (tsA !== tsB) return tsA < tsB ? -1 : 1;

  const srcA = String((a as any).source_file || (a as any).metadata?.source_file || a.source_type || '').toLowerCase();
  const srcB = String((b as any).source_file || (b as any).metadata?.source_file || b.source_type || '').toLowerCase();
  if (srcA !== srcB) return srcA.localeCompare(srcB);

  const [kindA, numA, strA] = extractRecordIndex(a);
  const [kindB, numB, strB] = extractRecordIndex(b);
  if (kindA !== kindB) return kindA - kindB;
  if (numA !== numB) return numA - numB;
  if (strA !== strB) return strA.localeCompare(strB);

  const actA = String(a.action || '').toLowerCase();
  const actB = String(b.action || '').toLowerCase();
  if (actA !== actB) return actA.localeCompare(actB);

  const rawA = String(a.raw || '');
  const rawB = String(b.raw || '');
  return rawA.localeCompare(rawB);
}
