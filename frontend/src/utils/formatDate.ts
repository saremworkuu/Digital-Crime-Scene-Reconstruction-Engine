export function formatDate(isoString: string): string {
  if (!isoString) return '-';
  try {
    const d = new Date(isoString);
    return d.toISOString().replace('T', ' ').replace('Z', ' UTC');
  } catch {
    return isoString;
  }
}

export function formatTimeOnly(isoString: string): string {
  if (!isoString) return '-';
  try {
    const d = new Date(isoString);
    return d.toISOString().substring(11, 19);
  } catch {
    return isoString;
  }
}
