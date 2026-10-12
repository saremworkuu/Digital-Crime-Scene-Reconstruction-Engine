import { apiClient } from './client';
import { User } from '../types';

export const authApi = {
  register: async (userData: {
    name: string;
    email: string;
    password: string;
    role?: string;
    department?: string;
    badge_id?: string;
    pgp_key?: string;
  }) => {
    return apiClient.post<{ token: string; user: User }>('/auth/register', userData);
  },
  login: async (email: string, password: string) => {
    return apiClient.post<{ token: string; user: User }>('/auth/login', { email, password });
  },
  logout: async () => {
    return apiClient.post('/auth/logout');
  },
  getCurrentUser: async () => {
    return apiClient.get<User>('/auth/me');
  },
  changePassword: async (currentPassword: string, newPassword: string) => {
    return apiClient.post('/auth/change-password', { current_password: currentPassword, new_password: newPassword });
  },
  listUsers: async () => {
    return apiClient.get<User[]>('/auth/users');
  }
};
