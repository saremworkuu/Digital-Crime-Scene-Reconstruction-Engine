import test from 'node:test';
import assert from 'node:assert/strict';

import { apiClient } from './client.ts';

test('apiClient.post(/auth/login) waits for /health wake-up and retries after cold-start NetworkError/502', async () => {
  const originalFetch = globalThis.fetch;
  const calls: string[] = [];
  let loginAttempt = 0;
  let healthAttempt = 0;

  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    calls.push(url);
    if (url.endsWith('/health')) {
      healthAttempt += 1;
      if (healthAttempt === 1) {
        return new Response('booting', { status: 502 });
      }
      return new Response(JSON.stringify({ status: 'ok' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    loginAttempt += 1;
    if (loginAttempt === 1) {
      throw new TypeError('NetworkError when attempting to fetch resource.');
    }
    return new Response(JSON.stringify({ access_token: 'tok-123', user: { id: '1', email: 'a@b.com' } }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as typeof fetch;

  try {
    const res = await apiClient.post<{ access_token: string }>('/auth/login', {
      email: 'a@b.com',
      password: 'Password123!',
    });
    assert.equal(res.status, 200);
    assert.equal(res.data?.access_token, 'tok-123');
    assert.equal(loginAttempt, 2);
    assert.ok(healthAttempt >= 2, `expected /health polling, got ${healthAttempt}`);
    assert.ok(calls.some((c) => c.endsWith('/health')));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
