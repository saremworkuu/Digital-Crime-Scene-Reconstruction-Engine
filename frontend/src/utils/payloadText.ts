/**
 * Sanitize untrusted network payload text for safe plain-text React rendering.
 * React JSX text nodes escape HTML metacharacters (<, >, &, ", '); this helper
 * additionally strips ANSI escape sequences, control chars, and bidi overrides.
 */
export function formatSafePayloadText(value: unknown): string {
  const str = String(value ?? '');
  return str
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, '');
}
