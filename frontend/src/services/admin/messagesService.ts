/**
 * Messages Service (Admin-Only & Public Contact Ingress)
 * Direct integration with FastAPI endpoints (/api/v1/admin/messages & /api/v1/contact).
 */

import { AdminContactMessage, MessageStatus, MessagePriority } from '../../admin/types';
import { apiClient } from '../../api';
import {
  fetchWithAdminCache,
  invalidateAdminCache,
  peekAdminCache,
  unwrapApi,
  withQuery
} from './storageHelper';

type MessagesPageResult = {
  messages: AdminContactMessage[];
  total: number;
  unreadCount: number;
  page: number;
  totalPages: number;
};

export const messagesService = {
  getCachedMessages(filters?: {
    status?: string;
    category?: string;
    priority?: string;
    assignee?: string;
    search?: string;
    page?: number;
    limit?: number;
  }): MessagesPageResult | undefined {
    return peekAdminCache<MessagesPageResult>(withQuery('/admin/messages', filters));
  },

  async getMessages(
    filters?: {
      status?: string;
      category?: string;
      priority?: string;
      assignee?: string;
      search?: string;
      page?: number;
      limit?: number;
    },
    force = false
  ): Promise<MessagesPageResult> {
    const url = withQuery('/admin/messages', filters);
    return fetchWithAdminCache(
      url,
      async () => {
        const res = await apiClient.get<MessagesPageResult>(url);
        if (res.error) throw new Error(res.error);
        return {
          messages: Array.isArray(res.data?.messages) ? res.data.messages : [],
          total: res.data?.total ?? 0,
          unreadCount: res.data?.unreadCount ?? 0,
          page: res.data?.page ?? (filters?.page || 1),
          totalPages: res.data?.totalPages ?? 1
        };
      },
      { force }
    );
  },

  async getNewMessagesCount(): Promise<number> {
    return fetchWithAdminCache(
      '/admin/messages/count',
      async () => {
        const res = await apiClient.get<{ count: number }>('/admin/messages/count');
        if (res.error) throw new Error(res.error);
        return res.data?.count ?? 0;
      },
      { ttlMs: 12000 }
    );
  },

  async markAsRead(id: string): Promise<void> {
    const res = await apiClient.patch(`/admin/messages/${id}/read`);
    if (res.error) throw new Error(res.error);
    invalidateAdminCache('/admin/messages', '/admin/system/summary');
  },

  async updateStatus(id: string, status: MessageStatus): Promise<AdminContactMessage> {
    const res = await apiClient.patch<AdminContactMessage>(`/admin/messages/${id}/status`, { status });
    const updated = unwrapApi(res, 'Failed to update message status.');
    invalidateAdminCache('/admin/messages', '/admin/system/summary', '/admin/audit');
    return updated;
  },

  async updatePriority(id: string, priority: MessagePriority): Promise<AdminContactMessage> {
    const res = await apiClient.patch<AdminContactMessage>(`/admin/messages/${id}/priority`, { priority });
    const updated = unwrapApi(res, 'Failed to update message priority.');
    invalidateAdminCache('/admin/messages', '/admin/audit');
    return updated;
  },

  async assignMessage(id: string, assignee: string | null): Promise<AdminContactMessage> {
    const res = await apiClient.patch<AdminContactMessage>(`/admin/messages/${id}/assign`, { assignee });
    const updated = unwrapApi(res, 'Failed to assign message.');
    invalidateAdminCache('/admin/messages', '/admin/audit');
    return updated;
  },

  async addReply(id: string, replyText: string, author?: string): Promise<AdminContactMessage> {
    const res = await apiClient.post<AdminContactMessage>(`/admin/messages/${id}/reply`, {
      message: replyText,
      author
    });
    const updated = unwrapApi(res, 'Failed to send reply.');
    invalidateAdminCache('/admin/messages', '/admin/system/summary', '/admin/audit');
    return updated;
  },

  async markAsSpam(id: string): Promise<void> {
    const res = await apiClient.post(`/admin/messages/${id}/spam`);
    if (res.error) throw new Error(res.error);
    invalidateAdminCache('/admin/messages', '/admin/system/summary', '/admin/audit');
  },

  async softDeleteMessage(id: string): Promise<void> {
    const res = await apiClient.delete(`/admin/messages/${id}`);
    if (res.error) throw new Error(res.error);
    invalidateAdminCache('/admin/messages', '/admin/system/summary', '/admin/audit');
  },

  async submitPublicMessage(data: {
    first_name: string;
    last_name: string;
    email: string;
    phone?: string;
    message: string;
    subject?: string;
    category?: string;
  }): Promise<AdminContactMessage> {
    const res = await apiClient.post<AdminContactMessage>('/contact', {
      first_name: data.first_name,
      last_name: data.last_name,
      email: data.email,
      phone: data.phone || '',
      message: data.message,
      subject: data.subject || 'Forensic Inquiry / Incident Escalation',
      category: data.category || 'Incident Report'
    });
    const created = unwrapApi(res, 'Failed to submit contact message.');
    invalidateAdminCache('/admin/messages', '/admin/system/summary');
    return created;
  }
};
