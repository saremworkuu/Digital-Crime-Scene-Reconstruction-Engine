/**
 * Format a case display label showing the first 8 characters of case.id next to the case name.
 */
export function formatCaseShortId(caseId?: string | null): string {
  const raw = String(caseId || '').trim();
  return raw ? raw.slice(0, 8) : '';
}

export function formatCaseNameWithId(name?: string | null, caseId?: string | null): string {
  const baseName = String(name || 'No case selected');
  const shortId = formatCaseShortId(caseId);
  return shortId ? `${baseName} (${shortId})` : baseName;
}
