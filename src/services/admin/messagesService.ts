/**
 * Messages Service (Admin-Only Contact Inbox)
 * Handles inquiries, incident reports, and chain-of-custody verification requests.
 *
 * Fully integrated with live FastAPI endpoints (/api/v1/admin/messages)
 * with graceful fallback to preserved mock seed data.
 */

import {
  AdminContactMessage,
  MessageStatus,
  MessagePriority
} from '../../admin/types';
import { SEED_MESSAGES } from '../../mocks/admin/seedData';
import { delay, getStored, setStored } from './storageHelper';
import { auditService } from './auditService';
import { apiClient } from '../../api';

// ============================================================================
// DATA ACCESS ADAPTER (Real Backend API with Mock Preserving Fallback)
// ============================================================================
const messagesAdapter = {
  async getAll(): Promise<AdminContactMessage[]> {
    try {
      const res = await apiClient.get<{ messages: AdminContactMessage[] }>('/admin/messages?limit=100');
      if (res.data?.messages && Array.isArray(res.data.messages) && res.data.messages.length > 0) {
        setStored('messages', res.data.messages);
        return res.data.messages;
      }
    } catch (err) {
      console.warn('Backend live messages API fallback to local data:', err);
    }
    await delay(150, 300);
    return getStored<AdminContactMessage[]>('messages', SEED_MESSAGES);
  },

  async saveAll(messages: AdminContactMessage[]): Promise<void> {
    setStored('messages', messages);
  }
};

// ============================================================================
// SERVICE INTERFACE
// ============================================================================
export interface MessageFilters {
  status?: string;
  category?: string;
  priority?: string;
  assignee?: string;
  search?: string;
  page?: number;
  limit?: number;
}

export const messagesService = {
  async getMessages(filters?: MessageFilters): Promise<{
    messages: AdminContactMessage[];
    total: number;
    unreadCount: number;
    page: number;
    totalPages: number;
  }> {
    // Try live API first with query params
    try {
      const params = new URLSearchParams();
      if (filters?.status && filters.status !== 'all') params.append('status', filters.status);
      if (filters?.category && filters.category !== 'all') params.append('category', filters.category);
      if (filters?.priority && filters.priority !== 'all') params.append('priority', filters.priority);
      if (filters?.assignee && filters.assignee !== 'all') params.append('assignee', filters.assignee);
      if (filters?.search) params.append('search', filters.search);
      if (filters?.page) params.append('page', String(filters.page));
      if (filters?.limit) params.append('limit', String(filters.limit));

      const res = await apiClient.get<{
        messages: AdminContactMessage[];
        total: number;
        unreadCount: number;
        page: number;
        totalPages: number;
      }>(`/admin/messages?${params.toString()}`);

      if (res.data && Array.isArray(res.data.messages)) {
        return res.data;
      }
    } catch {
      // Proceed to local fallback
    }

    const list = await messagesAdapter.getAll();
    const unreadCount = list.filter((m) => !m.is_read && m.status !== 'archived' && m.status !== 'spam').length;

    const filtered = list.filter((m) => {
      if (filters?.status && filters.status !== 'all' && m.status !== filters.status) {
        return false;
      }
      if (filters?.category && filters.category !== 'all' && m.category !== filters.category) {
        return false;
      }
      if (filters?.priority && filters.priority !== 'all' && m.priority !== filters.priority) {
        return false;
      }
      if (filters?.assignee && filters.assignee !== 'all') {
        if (filters.assignee === 'unassigned' && m.assignee !== null) return false;
        if (filters.assignee !== 'unassigned' && m.assignee !== filters.assignee) return false;
      }
      if (filters?.search) {
        const q = filters.search.toLowerCase();
        return (
          m.reference.toLowerCase().includes(q) ||
          m.sender_name.toLowerCase().includes(q) ||
          m.sender_email.toLowerCase().includes(q) ||
          m.subject.toLowerCase().includes(q) ||
          m.body.toLowerCase().includes(q)
        );
      }
      return true;
    });

    const page = filters?.page || 1;
    const limit = filters?.limit || 10;
    const startIndex = (page - 1) * limit;
    const paginated = filtered.slice(startIndex, startIndex + limit);

    return {
      messages: paginated,
      total: filtered.length,
      unreadCount,
      page,
      totalPages: Math.ceil(filtered.length / limit) || 1
    };
  },

  async getNewMessagesCount(): Promise<number> {
    try {
      const res = await apiClient.get<{ count: number }>('/admin/messages/count');
      if (typeof res.data?.count === 'number') {
        return res.data.count;
      }
    } catch {
      // fallback
    }
    const list = await messagesAdapter.getAll();
    return list.filter((m) => m.status === 'new' || !m.is_read).length;
  },

  async markAsRead(id: string): Promise<void> {
    try {
      await apiClient.patch(`/admin/messages/${id}/read`);
    } catch {
      // fallback
    }
    const list = await messagesAdapter.getAll();
    const item = list.find((m) => m.id === id);
    if (item && !item.is_read) {
      item.is_read = true;
      await messagesAdapter.saveAll(list);
    }
  },

  async updateStatus(id: string, status: MessageStatus): Promise<AdminContactMessage> {
    try {
      const res = await apiClient.patch<AdminContactMessage>(`/admin/messages/${id}/status`, { status });
      if (res.data) {
        const list = await messagesAdapter.getAll();
        const idx = list.findIndex((m) => m.id === id);
        if (idx !== -1) list[idx] = res.data;
        await messagesAdapter.saveAll(list);
        return res.data;
      }
    } catch (err) {
      console.warn('Live API message status update error, proceeding with local fallback:', err);
    }

    const list = await messagesAdapter.getAll();
    const item = list.find((m) => m.id === id);
    if (!item) throw new Error(`Message ${id} not found.`);

    const oldStatus = item.status;
    item.status = status;
    await messagesAdapter.saveAll(list);

    await auditService.log({
      action: 'MESSAGE_STATUS_UPDATE',
      target_type: 'MESSAGE',
      target_id: id,
      details: { reference: item.reference, from: oldStatus, to: status }
    });

    return item;
  },

  async updatePriority(id: string, priority: MessagePriority): Promise<AdminContactMessage> {
    try {
      const res = await apiClient.patch<AdminContactMessage>(`/admin/messages/${id}/priority`, { priority });
      if (res.data) {
        const list = await messagesAdapter.getAll();
        const idx = list.findIndex((m) => m.id === id);
        if (idx !== -1) list[idx] = res.data;
        await messagesAdapter.saveAll(list);
        return res.data;
      }
    } catch (err) {
      console.warn('Live API message priority update error, proceeding with local fallback:', err);
    }

    const list = await messagesAdapter.getAll();
    const item = list.find((m) => m.id === id);
    if (!item) throw new Error(`Message ${id} not found.`);

    item.priority = priority;
    await messagesAdapter.saveAll(list);

    await auditService.log({
      action: 'MESSAGE_PRIORITY_UPDATE',
      target_type: 'MESSAGE',
      target_id: id,
      details: { reference: item.reference, priority }
    });

    return item;
  },

  async assignMessage(id: string, assignee: string | null): Promise<AdminContactMessage> {
    try {
      const res = await apiClient.patch<AdminContactMessage>(`/admin/messages/${id}/assign`, { assignee });
      if (res.data) {
        const list = await messagesAdapter.getAll();
        const idx = list.findIndex((m) => m.id === id);
        if (idx !== -1) list[idx] = res.data;
        await messagesAdapter.saveAll(list);
        return res.data;
      }
    } catch (err) {
      console.warn('Live API message assign error, proceeding with local fallback:', err);
    }

    const list = await messagesAdapter.getAll();
    const item = list.find((m) => m.id === id);
    if (!item) throw new Error(`Message ${id} not found.`);

    item.assignee = assignee;
    await messagesAdapter.saveAll(list);

    await auditService.log({
      action: 'MESSAGE_ASSIGNED',
      target_type: 'MESSAGE',
      target_id: id,
      details: { reference: item.reference, assignee: assignee || 'Unassigned' }
    });

    return item;
  },

  async addReply(id: string, replyText: string, author = 'Sarem Worku (Admin)'): Promise<AdminContactMessage> {
    try {
      const res = await apiClient.post<AdminContactMessage>(`/admin/messages/${id}/reply`, {
        message: replyText,
        author,
      });
      if (res.data) {
        const list = await messagesAdapter.getAll();
        const idx = list.findIndex((m) => m.id === id);
        if (idx !== -1) list[idx] = res.data;
        await messagesAdapter.saveAll(list);
        return res.data;
      }
    } catch (err) {
      console.warn('Live API message reply error, proceeding with local fallback:', err);
    }

    const list = await messagesAdapter.getAll();
    const item = list.find((m) => m.id === id);
    if (!item) throw new Error(`Message ${id} not found.`);

    item.reply_thread.push({
      id: `rep-${Date.now().toString().slice(-6)}`,
      author,
      role: 'Administrator',
      message: replyText,
      timestamp: new Date().toISOString()
    });

    item.status = 'replied';
    item.is_read = true;
    await messagesAdapter.saveAll(list);

    await auditService.log({
      action: 'MESSAGE_REPLY_SENT',
      target_type: 'MESSAGE',
      target_id: id,
      details: { reference: item.reference, author }
    });

    return item;
  },

  async markAsSpam(id: string): Promise<void> {
    try {
      await apiClient.post(`/admin/messages/${id}/spam`);
    } catch {
      // fallback
    }
    const list = await messagesAdapter.getAll();
    const item = list.find((m) => m.id === id);
    if (item) {
      item.status = 'spam';
      item.is_read = true;
      await messagesAdapter.saveAll(list);

      await auditService.log({
        action: 'MESSAGE_MARK_SPAM',
        target_type: 'MESSAGE',
        target_id: id,
        details: { reference: item.reference, sender: item.sender_email }
      });
    }
  },

  async softDeleteMessage(id: string): Promise<void> {
    try {
      await apiClient.delete(`/admin/messages/${id}`);
    } catch {
      // fallback
    }
    const list = await messagesAdapter.getAll();
    const item = list.find((m) => m.id === id);
    if (item) {
      item.status = 'archived';
      await messagesAdapter.saveAll(list);

      await auditService.log({
        action: 'MESSAGE_SOFT_DELETE',
        target_type: 'MESSAGE',
        target_id: id,
        details: { reference: item.reference }
       });
    }
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
    let createdMsg: AdminContactMessage | null = null;
    try {
      const res = await apiClient.post<AdminContactMessage>('/contact', {
        first_name: data.first_name,
        last_name: data.last_name,
        email: data.email,
        phone: data.phone || '',
        message: data.message,
        subject: data.subject || 'Forensic Inquiry / Incident Escalation',
        category: 'Incident Report'
      });
      if (res.data && res.data.id) {
        createdMsg = res.data;
      }
    } catch (err) {
      console.warn('Backend live contact submission error, falling back to local store:', err);
    }

    const list = await messagesAdapter.getAll();
    const finalMsg: AdminContactMessage = createdMsg || {
      id: `msg-${Date.now().toString().slice(-6)}`,
      reference: `አሻራ-${Date.now().toString().slice(-6)}`,
      sender_name: `${data.first_name} ${data.last_name}`.trim(),
      sender_email: data.email,
      sender_phone: data.phone || '',
      subject: data.subject || 'Forensic Inquiry / Incident Escalation',
      category: 'Incident Report',
      status: 'new',
      priority: 'high',
      assignee: null,
      date: new Date().toISOString(),
      is_read: false,
      body: data.message,
      reply_thread: []
    };

    if (!list.some(m => m.id === finalMsg.id || m.reference === finalMsg.reference)) {
      list.unshift(finalMsg);
      await messagesAdapter.saveAll(list);
    }

    try {
      await auditService.log({
        action: 'CONTACT_MESSAGE_RECEIVED',
        target_type: 'MESSAGE',
        target_id: finalMsg.id,
        details: { reference: finalMsg.reference, sender: finalMsg.sender_email }
      });
    } catch {}

    return finalMsg;
  }
};


