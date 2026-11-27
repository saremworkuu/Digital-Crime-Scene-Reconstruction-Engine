/**
 * Base HTTP API client for አሻራ backend
 */

export interface ApiResponse<T> {
  data?: T;
  error?: string;
  status: number;
}

export const RENDER_BACKEND_URL = 'https://ashara-p3c3.onrender.com';

class ApiClient {
  private token: string | null = null;
  private warmUpPromise: Promise<boolean> | null = null;
  private lastWarmUpAt = 0;
  private baseUrl = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_BASE_URL)
    ? import.meta.env.VITE_API_BASE_URL
    : (typeof import.meta !== 'undefined' && import.meta.env?.PROD)
      ? `${RENDER_BACKEND_URL}/api/v1`
      : '/api/v1';

  constructor() {
    if (typeof window !== 'undefined' && /^https?:\/\//.test(this.baseUrl)) {
      this.warmUp();
    }
  }

  private getHealthUrl(): string {
    if (/^https?:\/\//.test(this.baseUrl)) {
      return this.baseUrl.replace(/\/api\/v1\/?$/, '') + '/health';
    }
    return '/health';
  }

  /**
   * Sends a lightweight CORS-simple GET /health ping (no custom headers/preflight)
   * so cold-started Render instances begin booting before user form submission.
   */
  warmUp(force = false): Promise<boolean> {
    if (typeof fetch !== 'function') return Promise.resolve(false);
    const now = Date.now();
    if (!force && now - this.lastWarmUpAt < 45000 && this.warmUpPromise) {
      return this.warmUpPromise;
    }
    if (this.warmUpPromise && !force) {
      return this.warmUpPromise;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 35000);
    this.warmUpPromise = fetch(this.getHealthUrl(), {
      method: 'GET',
      cache: 'no-store',
      signal: controller.signal,
    })
      .then((res) => {
        if (res.ok) this.lastWarmUpAt = Date.now();
        return res.ok;
      })
      .catch(() => false)
      .finally(() => {
        clearTimeout(timer);
        setTimeout(() => {
          this.warmUpPromise = null;
        }, 5000);
      });
    return this.warmUpPromise;
  }

  /**
   * Poll GET /health (preflight-free) while a cold-started host (e.g. Render)
   * is booting so callers retry only once the server actually responds 200 OK.
   */
  async waitForBackendReady(maxWaitMs = 75000): Promise<boolean> {
    if (typeof fetch !== 'function') return false;
    const deadline = Date.now() + maxWaitMs;
    while (Date.now() < deadline) {
      const ok = await this.warmUp(true);
      if (ok) return true;
      const remaining = deadline - Date.now();
      if (remaining <= 0) break;
      await new Promise((r) => setTimeout(r, Math.min(2500, remaining)));
    }
    return false;
  }

  setToken(token: string | null) {
    this.token = token;
    if (typeof window !== 'undefined') {
      try {
        if (token) {
          localStorage.setItem('dcsre_access_token', token);
        } else {
          localStorage.removeItem('dcsre_access_token');
          localStorage.removeItem('token');
        }
      } catch {
        // ignore
      }
    }
  }

  getToken(): string | null {
    if (this.token) return this.token;
    if (typeof window !== 'undefined') {
      try {
        return localStorage.getItem('dcsre_access_token') || localStorage.getItem('token');
      } catch {
        return null;
      }
    }
    return null;
  }

  private async request<T>(endpoint: string, options: RequestInit & { timeout?: number } = {}): Promise<ApiResponse<T>> {
    const headers = new Headers(options.headers || {});
    if (!(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }

    const token = this.getToken();
    if (token && token !== 'null' && token !== 'undefined' && token.trim() !== '') {
      headers.set('Authorization', `Bearer ${token.trim()}`);
    }

    const method = (options.method || 'GET').toUpperCase();
    const isRetrySafe =
      method === 'GET' ||
      method === 'HEAD' ||
      endpoint.startsWith('/auth/login') ||
      endpoint.startsWith('/auth/register') ||
      endpoint.startsWith('/auth/signup');

    // Hosted backends (such as Render free tier) may drop or time out the first
    // edge connection while booting; use shorter per-attempt timeouts with retries
    // for safe/auth calls when no explicit caller signal was provided.
    const perAttemptTimeoutMs = options.timeout ?? (isRetrySafe ? 40000 : 90000);
    const maxAttempts = isRetrySafe && !options.signal ? 3 : 1;
    const startedAt = Date.now();

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), perAttemptTimeoutMs);

      try {
        const response = await fetch(`${this.baseUrl}${endpoint}`, {
          ...options,
          signal: options.signal || controller.signal,
          headers,
        });
        clearTimeout(timeoutId);

        if (!response.ok) {
          if (attempt < maxAttempts && [502, 503, 504].includes(response.status)) {
            const elapsed = Date.now() - startedAt;
            const remainingBudget = Math.max(5000, 75000 - elapsed);
            await this.waitForBackendReady(remainingBudget);
            continue;
          }
          if (response.status === 401) {
            try {
              this.token = null;
              if (typeof window !== 'undefined') {
                localStorage.removeItem('dcsre_access_token');
                localStorage.removeItem('token');
                if (token) {
                  window.dispatchEvent(new Event('dcsre:session-expired'));
                }
              }
            } catch {}
          }
          const errorData = await response.json().catch(() => ({}));
          return {
            error: errorData.detail || `Request failed with status ${response.status}`,
            status: response.status,
          };
        }

        const data = await response.json();
        this.lastWarmUpAt = Date.now();
        return { data, status: response.status };
      } catch (err: any) {
        clearTimeout(timeoutId);
        const rawMsg = String(err?.message || '');
        const isNetworkBlocked =
          err?.name === 'TypeError' ||
          /networkerror|failed to fetch|load failed/i.test(rawMsg);
        const canRetry = attempt < maxAttempts && (err?.name === 'AbortError' || isNetworkBlocked);
        if (canRetry) {
          const elapsed = Date.now() - startedAt;
          const remainingBudget = Math.max(5000, 75000 - elapsed);
          const ready = await this.waitForBackendReady(remainingBudget);
          if (ready) {
            continue;
          }
        }
        return {
          error: err?.name === 'AbortError'
            ? 'Request timed out (backend may still be waking up; please retry).'
            : isNetworkBlocked
              ? 'Unable to reach backend server (it may be waking up or blocked by CORS/network). Please wait a few seconds and try again.'
              : (rawMsg || 'Network request failed'),
          status: 0,
        };
      }
    }

    return {
      error: 'Unable to reach backend server (it may be waking up or blocked by CORS/network). Please wait a few seconds and try again.',
      status: 0,
    };
  }

  get<T>(endpoint: string) {
    return this.request<T>(endpoint, { method: 'GET' });
  }

  async getText(endpoint: string): Promise<ApiResponse<string>> {
    const headers = new Headers();
    const token = this.getToken();
    if (token && token !== 'null' && token !== 'undefined' && token.trim() !== '') {
      headers.set('Authorization', `Bearer ${token.trim()}`);
    }
    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, { method: 'GET', headers });
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return { error: errorData.detail || `Request failed with status ${response.status}`, status: response.status };
      }
      return { data: await response.text(), status: response.status };
    } catch (err: any) {
      return { error: err.message || 'Request failed', status: 0 };
    }
  }

  async getBlob(endpoint: string): Promise<{ blob?: Blob; error?: string; status: number }> {
    const headers = new Headers();
    const token = this.getToken();
    if (token && token !== 'null' && token !== 'undefined' && token.trim() !== '') {
      headers.set('Authorization', `Bearer ${token.trim()}`);
    }

    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        method: 'GET',
        headers,
      });

      if (!response.ok) {
        return { error: `Request failed with status ${response.status}`, status: response.status };
      }

      const blob = await response.blob();
      return { blob, status: response.status };
    } catch (err: any) {
      return { error: err.message || 'Download failed', status: 0 };
    }
  }

  post<T>(endpoint: string, body?: any) {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  postFormData<T>(endpoint: string, body: FormData, timeout = 120000) {
    return this.request<T>(endpoint, { method: 'POST', body, timeout });
  }

  put<T>(endpoint: string, body?: any) {
    return this.request<T>(endpoint, {
      method: 'PUT',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  patch<T>(endpoint: string, body?: any) {
    return this.request<T>(endpoint, {
      method: 'PATCH',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  delete<T>(endpoint: string) {
    return this.request<T>(endpoint, { method: 'DELETE' });
  }
}

export const apiClient = new ApiClient();
