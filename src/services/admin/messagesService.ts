/**
 * Messages Service (Admin-Only Contact Inbox)
 * Handles inquiries, incident reports, and chain-of-custody verification requests.
 *
 * NOTE: For now this reads mock data only.
 * [INTEGRATION HOOK]: When connecting the real Contact form submissions later,
 * hook the live PostgreSQL / Render FastAPI endpoint inside `messagesAdapter.getAll()`,
 * or listen to real webhook event emissions without changing any page callers.
 */

import {
  AdminContactMessage,
  MessageStatus,
  MessagePriority
} from '../../admin/types';
import { SEED_MESSAGES } from '../../mocks/admin/seedData';
import { delay, getStored, setStored } from './storageHelper';
import { auditService } from './auditService';

// ============================================================================
// DATA ACCESS ADAPTER (Mock Implementation -> Swappable to Real Backend API)
// ============================================================================
const messagesAdapter = {
  // [REAL CONTACT DATA HOOK]: Replace this fetch logic with `fetch('/api/v1/contact/messages')`
  async getAll(): Promise<AdminContactMessage[]> {
    await delay(300, 500);
    return getStored<AdminContactMessage[]>('messages', SEED_MESSAGES);
  },

  async saveAll(messages: AdminContactMessage[]): Promise<void> {
    await delay(200, 400);
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
    const list = await messagesAdapter.getAll();
    return list.filter((m) => m.status === 'new' || !m.is_read).length;
  },

  async markAsRead(id: string): Promise<void> {
    const list = await messagesAdapter.getAll();
    const item = list.find((m) => m.id === id);
    if (item && !item.is_read) {
      item.is_read = true;
      await messagesAdapter.saveAll(list);
    }
  },

  async updateStatus(id: string, status: MessageStatus): Promise<AdminContactMessage> {
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
  }
};
