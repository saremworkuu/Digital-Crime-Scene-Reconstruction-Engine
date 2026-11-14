/**
 * MessagesPage (Contact Submissions Inbox)
 * Handles customer/investigator inquiries, incident escalations, and chain-of-custody requests.
 *
 * NOTE: For now this reads mock data only.
 * [INTEGRATION HOOK]: Connect the live FastAPI Contact submissions endpoint here
 * or inside `messagesService` when the production database table is deployed.
 */

import React, { useState, useEffect } from 'react';
import {
  Mail,
  MailOpen,
  Send,
  UserCheck,
  ShieldAlert,
  Trash2,
  AlertCircle,
  Clock,
  CheckCircle2,
  Reply,
  Phone,
  MessageSquare,
  ArrowRight,
  X
} from 'lucide-react';
import { DataTable, Column } from '../components/DataTable';
import { FilterBar } from '../components/FilterBar';
import { StatusBadge } from '../components/StatusBadge';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { messagesService, usersService } from '../../services/admin';
import {
  AdminContactMessage,
  MessageStatus,
  MessagePriority,
  MessageCategory,
  AdminUser
} from '../types';
import { toast } from '../../components/Toast';
import { useApp } from '../../store';

export const MessagesPage: React.FC = () => {
  const { theme } = useApp();
  const isLight = theme === 'light';

  const [messages, setMessages] = useState<AdminContactMessage[]>([]);
  const [total, setTotal] = useState(0);
  const [unreadCount, setUnreadCount] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [isLoading, setIsLoading] = useState(true);

  // Filters
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [priorityFilter, setPriorityFilter] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');

  // Detail Drawer
  const [selectedMessage, setSelectedMessage] = useState<AdminContactMessage | null>(null);
  const [replyText, setReplyText] = useState('');
  const [isSendingReply, setIsSendingReply] = useState(false);

  // Examiners list for assignment
  const [examiners, setExaminers] = useState<AdminUser[]>([]);

  // Confirm Dialog
  const [confirmDialog, setConfirmDialog] = useState<{
    isOpen: boolean;
    title: string;
    message: string;
    action: () => Promise<void>;
  }>({
    isOpen: false,
    title: '',
    message: '',
    action: async () => {}
  });

  const loadData = async (targetPage = page) => {
    setIsLoading(true);
    try {
      const [res, userList] = await Promise.all([
        messagesService.getMessages({
          search,
          status: statusFilter,
          priority: priorityFilter,
          category: categoryFilter,
          page: targetPage,
          limit: 10
        }),
        usersService.getUsers()
      ]);

      setMessages(res.messages);
      setTotal(res.total);
      setUnreadCount(res.unreadCount);
      setPage(res.page);
      setTotalPages(res.totalPages);
      setExaminers(userList);

      if (selectedMessage) {
        const refreshed = res.messages.find((m) => m.id === selectedMessage.id);
        if (refreshed) setSelectedMessage(refreshed);
      }
    } catch (err: any) {
      toast.error('Failed to load contact inbox: ' + err.message);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData(1);
  }, [search, statusFilter, priorityFilter, categoryFilter]);

  const handleOpenDetail = async (m: AdminContactMessage) => {
    setSelectedMessage(m);
    setReplyText('');
    if (!m.is_read) {
      await messagesService.markAsRead(m.id);
      loadData(page);
    }
  };

  const handleStatusChange = async (id: string, newStatus: MessageStatus) => {
    try {
      const updated = await messagesService.updateStatus(id, newStatus);
      if (selectedMessage?.id === id) setSelectedMessage(updated);
      toast.success(`Message ticket status updated to ${newStatus}.`);
      loadData(page);
    } catch (err: any) {
      toast.error('Status update failed: ' + err.message);
    }
  };

  const handlePriorityChange = async (id: string, newPriority: MessagePriority) => {
    try {
      const updated = await messagesService.updatePriority(id, newPriority);
      if (selectedMessage?.id === id) setSelectedMessage(updated);
      toast.success(`Priority set to ${newPriority}.`);
      loadData(page);
    } catch (err: any) {
      toast.error('Priority update failed: ' + err.message);
    }
  };

  const handleAssigneeChange = async (id: string, assignee: string) => {
    const nextAssignee = assignee === 'unassigned' ? null : assignee;
    try {
      const updated = await messagesService.assignMessage(id, nextAssignee);
      if (selectedMessage?.id === id) setSelectedMessage(updated);
      toast.success(`Assigned to ${assignee}.`);
      loadData(page);
    } catch (err: any) {
      toast.error('Assignment failed: ' + err.message);
    }
  };

  const handleSendReply = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedMessage || !replyText.trim()) return;

    setIsSendingReply(true);
    try {
      const updated = await messagesService.addReply(selectedMessage.id, replyText);
      setSelectedMessage(updated);
      setReplyText('');
      toast.success(`Reply transmitted to ${selectedMessage.sender_email}.`);
      loadData(page);
    } catch (err: any) {
      toast.error('Reply dispatch failed: ' + err.message);
    } finally {
      setIsSendingReply(false);
    }
  };

  const handleMarkSpam = (m: AdminContactMessage) => {
    setConfirmDialog({
      isOpen: true,
      title: 'Flag as Spam',
      message: `Mark message from ${m.sender_email} (${m.reference}) as unsolicited spam? Future submissions from this domain will be flagged.`,
      action: async () => {
        try {
          await messagesService.markAsSpam(m.id);
          toast.success('Marked as spam.');
          if (selectedMessage?.id === m.id) setSelectedMessage(null);
          loadData(page);
        } catch (err: any) {
          toast.error('Action failed: ' + err.message);
        }
      }
    });
  };

  const handleSoftDelete = (m: AdminContactMessage) => {
    setConfirmDialog({
      isOpen: true,
      title: 'Archive Message',
      message: `Archive contact message ${m.reference}? It can be recovered under archived status filters.`,
      action: async () => {
        try {
          await messagesService.softDeleteMessage(m.id);
          toast.success('Message archived.');
          if (selectedMessage?.id === m.id) setSelectedMessage(null);
          loadData(page);
        } catch (err: any) {
          toast.error('Archive failed: ' + err.message);
        }
      }
    });
  };

  const columns: Column<AdminContactMessage>[] = [
    {
      key: 'reference',
      header: 'Reference & Unread',
      render: (m) => (
        <div className="flex items-center gap-2">
          {!m.is_read ? (
            <span className="w-2 h-2 rounded-full bg-[#f95721] animate-pulse shrink-0" title="Unread Message" />
          ) : (
            <span className={`w-2 h-2 rounded-full shrink-0 ${isLight ? 'bg-slate-300' : 'bg-stone-700'}`} />
          )}
          <span className={`font-mono text-xs ${
            !m.is_read
              ? `font-bold ${isLight ? 'text-slate-900' : 'text-white'}`
              : isLight ? 'text-slate-500' : 'text-stone-400'
          }`}>
            {m.reference}
          </span>
        </div>
      )
    },
    {
      key: 'sender_name',
      header: 'Sender Details',
      render: (m) => (
        <div className="space-y-0.5">
          <div className={`font-sans text-xs ${
            !m.is_read
              ? `font-black ${isLight ? 'text-slate-900' : 'text-white'}`
              : isLight ? 'font-medium text-slate-700' : 'font-medium text-stone-300'
          }`}>
            {m.sender_name}
          </div>
          <div className={`text-[10px] font-mono ${isLight ? 'text-slate-500' : 'text-stone-500'}`}>{m.sender_email}</div>
        </div>
      )
    },
    {
      key: 'subject',
      header: 'Subject & Inquiry',
      render: (m) => (
        <div className="space-y-0.5 max-w-sm">
          <div className={`text-xs font-sans truncate ${
            !m.is_read
              ? `font-extrabold ${isLight ? 'text-slate-900' : 'text-white'}`
              : isLight ? 'text-slate-700' : 'text-stone-300'
          }`}>
            {m.subject}
          </div>
          <p className={`text-[11px] font-sans truncate ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>{m.body}</p>
        </div>
      )
    },
    {
      key: 'category',
      header: 'Category',
      render: (m) => (
        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
          isLight
            ? 'bg-slate-100 border-slate-200 text-slate-700'
            : 'bg-black/40 border-[#2b2523] text-stone-300'
        }`}>
          {m.category}
        </span>
      )
    },
    {
      key: 'priority',
      header: 'Priority',
      render: (m) => <StatusBadge status={m.priority} variant="severity" />
    },
    {
      key: 'status',
      header: 'Status',
      render: (m) => <StatusBadge status={m.status} />
    },
    {
      key: 'assignee',
      header: 'Assignee',
      render: (m) => (
        <span className={`text-xs font-mono ${isLight ? 'text-slate-700' : 'text-stone-300'}`}>
          {m.assignee || <em className={isLight ? 'text-slate-400 not-italic' : 'text-stone-500 not-italic'}>Unassigned</em>}
        </span>
      )
    },
    {
      key: 'date',
      header: 'Received',
      render: (m) => (
        <span className={`text-xs font-mono ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
          {new Date(m.date).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}
        </span>
      )
    },
    {
      key: 'actions',
      header: 'Actions',
      className: 'text-right',
      render: (m) => (
        <div className="flex items-center justify-end gap-1.5">
          <button
            type="button"
            onClick={() => handleOpenDetail(m)}
            className={`px-2.5 py-1 rounded-lg border text-xs font-mono transition-colors cursor-pointer ${
              isLight
                ? 'bg-slate-100 hover:bg-slate-200 text-slate-700 hover:text-slate-900 border-slate-200'
                : 'bg-stone-900 hover:bg-stone-800 text-stone-200 hover:text-[#f95721] border-stone-700 hover:border-[#f95721]/50'
            }`}
          >
            Open
          </button>

          <button
            type="button"
            onClick={() => handleMarkSpam(m)}
            className={`p-1.5 rounded-lg border transition-colors cursor-pointer ${
              isLight
                ? 'bg-slate-100 hover:bg-amber-50 text-slate-500 hover:text-amber-600 border-slate-200'
                : 'bg-stone-900 hover:bg-amber-950/40 text-stone-400 hover:text-amber-400 border-stone-700'
            }`}
            title="Mark as Spam"
          >
            <ShieldAlert className="w-3.5 h-3.5" />
          </button>

          <button
            type="button"
            onClick={() => handleSoftDelete(m)}
            className={`p-1.5 rounded-lg border transition-colors cursor-pointer ${
              isLight
                ? 'bg-slate-100 hover:bg-red-50 text-slate-500 hover:text-red-600 border-slate-200'
                : 'bg-stone-900 hover:bg-red-950/40 text-stone-500 hover:text-red-400 border-stone-700'
            }`}
            title="Archive Message"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      )
    }
  ];

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b ${
        isLight ? 'border-slate-200' : 'border-[#282321]'
      }`}>
        <div>
          <h1 className={`text-xl sm:text-2xl font-black tracking-tight font-sans flex items-center gap-2.5 ${
            isLight ? 'text-slate-900' : 'text-white'
          }`}>
            <Mail className="w-6 h-6 text-[#f95721]" />
            <span>Contact Messages Inbox</span>
            {unreadCount > 0 && (
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-full bg-[#f95721] text-white">
                {unreadCount} New
              </span>
            )}
          </h1>
          <p className={`text-xs sm:text-sm font-sans mt-0.5 ${
            isLight ? 'text-slate-500' : 'text-stone-400'
          }`}>
            Incoming investigator tickets, incident reports, and custody verification inquiries
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <FilterBar
        searchQuery={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search messages by ticket reference, sender, or subject..."
        filters={[
          {
            key: 'status',
            label: 'Status',
            value: statusFilter,
            options: [
              { label: 'All Statuses', value: 'all' },
              { label: 'New', value: 'new' },
              { label: 'In Review', value: 'in_review' },
              { label: 'Replied', value: 'replied' },
              { label: 'Spam', value: 'spam' },
              { label: 'Archived', value: 'archived' }
            ],
            onChange: setStatusFilter
          },
          {
            key: 'priority',
            label: 'Priority',
            value: priorityFilter,
            options: [
              { label: 'All Priorities', value: 'all' },
              { label: 'Critical', value: 'critical' },
              { label: 'High', value: 'high' },
              { label: 'Medium', value: 'medium' },
              { label: 'Low', value: 'low' }
            ],
            onChange: setPriorityFilter
          },
          {
            key: 'category',
            label: 'Category',
            value: categoryFilter,
            options: [
              { label: 'All Categories', value: 'all' },
              { label: 'Incident Report', value: 'Incident Report' },
              { label: 'Telemetry Query', value: 'Telemetry Query' },
              { label: 'Chain of Custody', value: 'Chain of Custody' },
              { label: 'General Inquiry', value: 'General Inquiry' },
              { label: 'Support', value: 'Support' }
            ],
            onChange: setCategoryFilter
          }
        ]}
        onResetFilters={() => {
          setSearch('');
          setStatusFilter('all');
          setPriorityFilter('all');
          setCategoryFilter('all');
        }}
      />

      {/* Main Inbox Table */}
      <DataTable
        columns={columns}
        data={messages}
        keyExtractor={(m) => m.id}
        isLoading={isLoading}
        emptyTitle="Inbox is empty"
        emptyMessage="No contact messages matched your active filter parameters."
        pagination={{
          currentPage: page,
          totalPages: totalPages,
          totalItems: total,
          onPageChange: (p) => {
            setPage(p);
            loadData(p);
          }
        }}
      />

      {/* Slide-over Detail Drawer */}
      {selectedMessage && (
        <div className={`fixed inset-0 z-50 flex justify-end backdrop-blur-sm animate-fadeIn ${
          isLight ? 'bg-slate-900/40' : 'bg-black/70'
        }`}>
          <div className={`w-full max-w-xl h-full shadow-2xl p-6 flex flex-col justify-between overflow-y-auto space-y-5 border-l ${
            isLight
              ? 'bg-white border-slate-200 text-slate-800'
              : 'bg-[#121110] border-[#2e2623] text-white'
          }`}>
            {/* Top Bar of Drawer */}
            <div className="space-y-4">
              <div className={`flex items-center justify-between pb-3 border-b ${
                isLight ? 'border-slate-200' : 'border-[#26201e]'
              }`}>
                <div className="flex items-center gap-2">
                  <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                    isLight
                      ? 'bg-orange-50 border-orange-200 text-[#f95721]'
                      : 'bg-[#f95721]/20 border-[#f95721]/40 text-[#f95721]'
                  }`}>
                    {selectedMessage.reference}
                  </span>
                  <StatusBadge status={selectedMessage.status} />
                  <StatusBadge status={selectedMessage.priority} variant="severity" />
                </div>

                <button
                  type="button"
                  onClick={() => setSelectedMessage(null)}
                  className={`p-1 rounded-lg transition-colors cursor-pointer ${
                    isLight
                      ? 'text-slate-400 hover:text-slate-700 hover:bg-slate-100'
                      : 'text-stone-400 hover:text-white hover:bg-stone-800'
                  }`}
                  aria-label="Close drawer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Subject & Sender Details */}
              <div className="space-y-2">
                <h2 className={`text-lg font-extrabold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>{selectedMessage.subject}</h2>
                <div className={`p-3.5 rounded-xl border space-y-1.5 text-xs font-sans ${
                  isLight
                    ? 'bg-slate-50 border-slate-200 text-slate-700'
                    : 'bg-black/40 border-[#28221f]'
                }`}>
                  <div className="flex items-center justify-between">
                    <span className={isLight ? 'text-slate-500' : 'text-stone-400'}>Sender:</span>
                    <strong className={isLight ? 'text-slate-900' : 'text-white'}>{selectedMessage.sender_name}</strong>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className={isLight ? 'text-slate-500' : 'text-stone-400'}>Email:</span>
                    <a
                      href={`mailto:${selectedMessage.sender_email}`}
                      className="text-[#f95721] font-mono hover:underline"
                    >
                      {selectedMessage.sender_email}
                    </a>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className={isLight ? 'text-slate-500' : 'text-stone-400'}>Phone:</span>
                    <span className={`font-mono ${isLight ? 'text-slate-700' : 'text-stone-300'}`}>{selectedMessage.sender_phone}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className={isLight ? 'text-slate-500' : 'text-stone-400'}>Timestamp:</span>
                    <span className={`font-mono ${isLight ? 'text-slate-700' : 'text-stone-300'}`}>
                      {new Date(selectedMessage.date).toUTCString()}
                    </span>
                  </div>
                </div>
              </div>

              {/* Status / Priority / Assignee Controls */}
              <div className="grid grid-cols-3 gap-2.5 text-xs">
                <div>
                  <label className={`block text-[10px] font-mono mb-1 ${isLight ? 'text-slate-700' : 'text-stone-400'}`}>Status</label>
                  <select
                    value={selectedMessage.status}
                    onChange={(e) => handleStatusChange(selectedMessage.id, e.target.value as MessageStatus)}
                    className={`w-full px-2 py-1.5 rounded-lg border text-xs cursor-pointer ${
                      isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-900'
                        : 'bg-black/50 border-[#2e2623] text-white'
                    }`}
                  >
                    <option value="new" className={isLight ? 'text-slate-900 bg-white' : ''}>New</option>
                    <option value="in_review" className={isLight ? 'text-slate-900 bg-white' : ''}>In Review</option>
                    <option value="replied" className={isLight ? 'text-slate-900 bg-white' : ''}>Replied</option>
                    <option value="spam" className={isLight ? 'text-slate-900 bg-white' : ''}>Spam</option>
                    <option value="archived" className={isLight ? 'text-slate-900 bg-white' : ''}>Archived</option>
                  </select>
                </div>

                <div>
                  <label className={`block text-[10px] font-mono mb-1 ${isLight ? 'text-slate-700' : 'text-stone-400'}`}>Priority</label>
                  <select
                    value={selectedMessage.priority}
                    onChange={(e) => handlePriorityChange(selectedMessage.id, e.target.value as MessagePriority)}
                    className={`w-full px-2 py-1.5 rounded-lg border text-xs cursor-pointer ${
                      isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-900'
                        : 'bg-black/50 border-[#2e2623] text-white'
                    }`}
                  >
                    <option value="critical" className={isLight ? 'text-slate-900 bg-white' : ''}>Critical</option>
                    <option value="high" className={isLight ? 'text-slate-900 bg-white' : ''}>High</option>
                    <option value="medium" className={isLight ? 'text-slate-900 bg-white' : ''}>Medium</option>
                    <option value="low" className={isLight ? 'text-slate-900 bg-white' : ''}>Low</option>
                  </select>
                </div>

                <div>
                  <label className={`block text-[10px] font-mono mb-1 ${isLight ? 'text-slate-700' : 'text-stone-400'}`}>Assignee</label>
                  <select
                    value={selectedMessage.assignee || 'unassigned'}
                    onChange={(e) => handleAssigneeChange(selectedMessage.id, e.target.value)}
                    className={`w-full px-2 py-1.5 rounded-lg border text-xs cursor-pointer ${
                      isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-900'
                        : 'bg-black/50 border-[#2e2623] text-white'
                    }`}
                  >
                    <option value="unassigned" className={isLight ? 'text-slate-900 bg-white' : ''}>Unassigned</option>
                    {examiners.map((ex) => (
                      <option key={ex.id} value={ex.name} className={isLight ? 'text-slate-900 bg-white' : ''}>
                        {ex.name}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Message Body Content */}
              <div className="space-y-1.5">
                <span className={`text-[11px] font-mono uppercase tracking-wider block ${
                  isLight ? 'text-slate-500' : 'text-stone-400'
                }`}>
                  Original Message Content
                </span>
                <div className={`p-4 rounded-xl border text-xs sm:text-sm font-sans leading-relaxed whitespace-pre-wrap ${
                  isLight
                    ? 'bg-slate-50 border-slate-200 text-slate-800'
                    : 'bg-black/50 border-[#2a2320] text-stone-200'
                }`}>
                  {selectedMessage.body}
                </div>
              </div>

              {/* Reply Thread History */}
              <div className="space-y-2.5">
                <span className={`text-[11px] font-mono uppercase tracking-wider block flex items-center gap-1.5 ${
                  isLight ? 'text-slate-500' : 'text-stone-400'
                }`}>
                  <Reply className="w-3.5 h-3.5 text-[#f95721]" />
                  <span>Reply Thread & Case Notes ({selectedMessage.reply_thread.length})</span>
                </span>

                {selectedMessage.reply_thread.length === 0 ? (
                  <p className={`text-xs font-mono py-2 ${isLight ? 'text-slate-400' : 'text-stone-500'}`}>
                    No responses transmitted yet. Author a reply below.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {selectedMessage.reply_thread.map((rep) => (
                      <div
                        key={rep.id}
                        className={`p-3 rounded-xl border space-y-1 text-xs ${
                          isLight
                            ? 'bg-slate-50 border-slate-200 text-slate-800'
                            : 'bg-[#1c1816] border-[#332b27]'
                        }`}
                      >
                        <div className="flex items-center justify-between text-[11px] font-mono">
                          <strong className={isLight ? 'text-[#f95721]' : 'text-[#ff936b]'}>{rep.author}</strong>
                          <span className={isLight ? 'text-slate-400' : 'text-stone-500'}>
                            {new Date(rep.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </span>
                        </div>
                        <p className={`font-sans ${isLight ? 'text-slate-700' : 'text-stone-200'}`}>{rep.message}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Author Reply Form */}
            <form onSubmit={handleSendReply} className={`pt-3 border-t space-y-2.5 ${
              isLight ? 'border-slate-200' : 'border-[#26201e]'
            }`}>
              <label htmlFor="admin-reply-box" className={`block text-xs font-mono font-semibold ${
                isLight ? 'text-slate-800' : 'text-stone-300'
              }`}>
                Compose Dispatch to {selectedMessage.sender_name}
              </label>
              <textarea
                id="admin-reply-box"
                rows={3}
                required
                value={replyText}
                onChange={(e) => setReplyText(e.target.value)}
                placeholder="Type your official response, triage instructions, or evidence validation notes..."
                className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm focus:outline-none focus:border-[#f95721] resize-none font-sans border ${
                  isLight
                    ? 'bg-slate-50 border-slate-300 text-slate-900 placeholder:text-slate-400'
                    : 'bg-black/60 border-[#2e2623] text-white'
                }`}
              />

              <div className="flex items-center justify-between">
                <span className={`text-[10px] font-mono ${isLight ? 'text-slate-400' : 'text-stone-500'}`}>
                  Transmits official signed communication
                </span>
                <button
                  type="submit"
                  disabled={isSendingReply || !replyText.trim()}
                  className="px-4 py-2 rounded-xl text-xs font-bold text-white bg-[#f95721] hover:bg-[#ea580c] transition-all shadow-[0_0_15px_rgba(249,87,33,0.3)] flex items-center gap-1.5 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>{isSendingReply ? 'Transmitting...' : 'Send Reply'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Confirm Action Dialog */}
      <ConfirmDialog
        isOpen={confirmDialog.isOpen}
        title={confirmDialog.title}
        message={confirmDialog.message}
        onConfirm={async () => {
          await confirmDialog.action();
          setConfirmDialog((prev) => ({ ...prev, isOpen: false }));
        }}
        onCancel={() => setConfirmDialog((prev) => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
};
