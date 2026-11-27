import type { EvidenceFile } from '../types/evidence.ts';

/**
 * Return true for archive container rows (e.g. uploaded .zip files) whose extracted
 * member artifacts are stored as separate Evidence rows.
 */
export function isEvidenceContainer(
  ev: Pick<EvidenceFile, 'filename' | 'parser_used' | 'event_count' | 'is_container'> | null | undefined,
): boolean {
  if (!ev) return false;
  if (typeof ev.is_container === 'boolean') return ev.is_container;
  if (String(ev.parser_used || '').trim() === 'ZipArchive') return true;
  return (
    String(ev.filename || '').trim().toLowerCase().endsWith('.zip') &&
    Number(ev.event_count || 0) === 0
  );
}

/**
 * Return the derived number of extracted member files for a container row, when known.
 */
export function getContainerExtractedCount(
  ev: Pick<EvidenceFile, 'extracted_count' | 'extracted_results'> | null | undefined,
): number | null {
  if (!ev) return null;
  if (typeof ev.extracted_count === 'number' && Number.isFinite(ev.extracted_count)) {
    return ev.extracted_count;
  }
  if (Array.isArray(ev.extracted_results)) {
    return ev.extracted_results.filter((item) => item && item.status !== 'failed').length;
  }
  return null;
}

/**
 * Format the inventory table status label without misreporting containers as "Parsed" with 0 events.
 */
export function formatEvidenceStatusLabel(
  ev: Pick<
    EvidenceFile,
    'filename' | 'parser_used' | 'event_count' | 'is_container' | 'status' | 'extracted_count' | 'extracted_results'
  >,
): string {
  if (!isEvidenceContainer(ev)) {
    return String(ev.status || 'Parsed');
  }
  if (ev.status === 'Failed') return 'Failed';
  if (ev.status === 'Pending') return 'Extracting...';
  const count = getContainerExtractedCount(ev);
  if (count !== null) {
    return `extracted: ${count} ${count === 1 ? 'file' : 'files'}`;
  }
  return 'container';
}
