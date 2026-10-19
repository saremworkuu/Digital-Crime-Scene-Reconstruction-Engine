/**
 * Cryptographic SHA-256 Hashing service (FR-EVID-2)
 * Computes standard 256-bit hexadecimal digest using Web Crypto API.
 */

export async function computeSHA256(fileOrBuffer: File | Blob | ArrayBuffer | string): Promise<string> {
  let arrayBuffer: ArrayBuffer;

  if (typeof fileOrBuffer === 'string') {
    const encoder = new TextEncoder();
    arrayBuffer = encoder.encode(fileOrBuffer).buffer;
  } else if (fileOrBuffer instanceof ArrayBuffer) {
    arrayBuffer = fileOrBuffer;
  } else {
    arrayBuffer = await fileOrBuffer.arrayBuffer();
  }

  const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
