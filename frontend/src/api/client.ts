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

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<ApiResponse<T>> {
    const headers = new Headers(options.headers || {});
    if (!(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }

    const token = this.getToken();
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        ...options,
        headers,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return {
          error: errorData.detail || `Request failed with status ${response.status}`,
          status: response.status,
        };
      }

      const data = await response.json();
      return { data, status: response.status };
    } catch (err: any) {
      return {
        error: err.message || 'Network request failed',
        status: 0,
      };
    }
  }

  get<T>(endpoint: string) {
    return this.request<T>(endpoint, { method: 'GET' });
  }

  post<T>(endpoint: string, body?: any) {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
    });
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
