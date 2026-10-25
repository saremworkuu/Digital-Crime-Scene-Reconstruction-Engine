/**
 * Base HTTP API client for አሻራ backend
 */

export interface ApiResponse<T> {
  data?: T;
  error?: string;
  status: number;
}

export const RENDER_BACKEND_URL = 'https://digital-crime-scene-reconstruction-engine.onrender.com';

class ApiClient {
  private token: string | null = null;
  private baseUrl = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_BASE_URL)
    ? import.meta.env.VITE_API_BASE_URL
    : (typeof import.meta !== 'undefined' && import.meta.env?.PROD)
      ? `${RENDER_BACKEND_URL}/api/v1`
      : '/api/v1';

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

    // Hosted backends may need time to wake, and large evidence requests need
    // considerably longer than the old four-second limit.
    const timeoutMs = options.timeout ?? 60000;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        ...options,
        signal: options.signal || controller.signal,
        headers,
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
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
      return { data, status: response.status };
    } catch (err: any) {
      clearTimeout(timeoutId);
      return {
        error: err.name === 'AbortError' ? 'Request timed out' : (err.message || 'Network request failed'),
        status: 0,
      };
    }
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
