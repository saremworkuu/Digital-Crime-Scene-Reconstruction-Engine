/**
 * Admin Service Helpers
 * Provides query-string serialization, uniform API response unwrapping,
 * short-TTL in-memory SWR caching + in-flight request deduplication,
 * and legacy localStorage mock key cleanup.
 */

import { ApiResponse } from '../../api';

const LEGACY_KEYS = [
  'users',
  'cases',
  'evidence',
  'rules',
  'messages',
  'audit',
  'system_health',
  'settings'
];

interface CacheEntry<T> {
  data: T;
  updatedAt: number;
}

const memoryCache = new Map<string, CacheEntry<unknown>>();
const inFlightRequests = new Map<string, Promise<unknown>>();
const cacheListeners = new Set<(prefixes: string[]) => void>();
let legacyCleared = false;

export function clearLegacyAdminStorage(): void {
  if (legacyCleared) return;
  legacyCleared = true;
  try {
    for (const key of LEGACY_KEYS) {
      localStorage.removeItem(`dcsre_admin_v3_${key}`);
    }
  } catch {
    // Ignore storage access errors in restricted contexts
  }
}

export function clearAllAdminMemoryCache(): void {
  memoryCache.clear();
  inFlightRequests.clear();
}

export function subscribeAdminCacheInvalidation(listener: (prefixes: string[]) => void): () => void {
  cacheListeners.add(listener);
  return () => {
    cacheListeners.delete(listener);
  };
}

export function invalidateAdminCache(...prefixes: string[]): void {
  if (prefixes.length === 0) {
    memoryCache.clear();
    cacheListeners.forEach((fn) => fn(['*']));
    return;
  }
  for (const key of Array.from(memoryCache.keys())) {
    if (prefixes.some((p) => key.startsWith(p))) {
      memoryCache.delete(key);
    }
  }
  cacheListeners.forEach((fn) => fn(prefixes));
}

export function peekAdminCache<T>(key: string): T | undefined {
  const entry = memoryCache.get(key);
  return entry ? (entry.data as T) : undefined;
}

export async function fetchWithAdminCache<T>(
  key: string,
  fetcher: () => Promise<T>,
  options?: { ttlMs?: number; force?: boolean }
): Promise<T> {
  const ttlMs = options?.ttlMs ?? 30000;
  const force = options?.force ?? false;

  if (!force) {
    const cached = memoryCache.get(key);
    if (cached && Date.now() - cached.updatedAt < ttlMs) {
      return cached.data as T;
    }
  }

  const existing = inFlightRequests.get(key);
  if (existing && !force) {
    return existing as Promise<T>;
  }

  const promise = fetcher()
    .then((data) => {
      memoryCache.set(key, { data, updatedAt: Date.now() });
      return data;
    })
    .finally(() => {
      inFlightRequests.delete(key);
    });

  inFlightRequests.set(key, promise);
  return promise;
}

export function withQuery(
  path: string,
  params?: Record<string, string | number | boolean | undefined | null>
): string {
  if (!params) return path;
  const search = new URLSearchParams();
  for (const [key, val] of Object.entries(params)) {
    if (val === undefined || val === null || val === '') continue;
    search.set(key, String(val));
  }
  const qs = search.toString();
  return qs ? `${path}?${qs}` : path;
}

export function unwrapApi<T>(res: ApiResponse<T>, errorMessage = 'Request failed'): T {
  if (res.error) {
    throw new Error(res.error);
  }
  if (res.data === undefined) {
    throw new Error(errorMessage);
  }
  return res.data;
}
