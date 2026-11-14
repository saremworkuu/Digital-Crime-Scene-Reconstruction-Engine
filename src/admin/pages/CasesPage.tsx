import React, { useState, useEffect } from 'react';
import {
  FolderLock,
  Lock,
  Unlock,
  Archive,
  Users,
  Calendar,
  CheckCircle2,
  FileCheck2,
  AlertTriangle
} from 'lucide-react';
import { DataTable, Column } from '../components/DataTable';
import { FilterBar } from '../components/FilterBar';
import { StatusBadge } from '../components/StatusBadge';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { casesService, usersService } from '../../services/admin';
import { AdminCase, CaseStatus, AdminUser } from '../types';
import { toast } from '../../components/Toast';
import { useApp } from '../../store';

export const CasesPage: React.FC = () => {
  const { theme } = useApp();
  const isLight = theme === 'light';

  const [cases, setCases] = useState<AdminCase[]>([]);
  const [allExaminers, setAllExaminers] = useState<AdminUser[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Filters
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  // Selected Case for Assignment / Details
  const [selectedCase, setSelectedCase] = useState<AdminCase | null>(null);
  const [assignModalOpen, setAssignModalOpen] = useState(false);
  const [selectedInvestigators, setSelectedInvestigators] = useState<string[]>([]);

  // Dialog State
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

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [caseList, userList] = await Promise.all([
        casesService.getCases({ search, status: statusFilter }),
        usersService.getUsers()
      ]);
      setCases(caseList);
      setAllExaminers(userList.filter((u) => u.role === 'investigator' || u.role === 'admin'));
    } catch (err: any) {
      toast.error('Failed to load cases: ' + err.message);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [search, statusFilter]);

  const handleStatusChange = async (c: AdminCase, nextStatus: CaseStatus) => {
    try {
      await casesService.updateStatus(c.id, nextStatus);
      toast.success(`Case status transitioned to ${nextStatus}.`);
      loadData();
    } catch (err: any) {
      toast.error('Status change failed: ' + err.message);
    }
  };

  const handleToggleLegalHold = (c: AdminCase) => {
    const nextHold = !c.legal_hold;
    setConfirmDialog({
      isOpen: true,
      title: nextHold ? 'Apply Statutory Legal Hold' : 'Release Legal Hold',
      message: nextHold
        ? `Applying Legal Hold on "${c.title}" locks all associated forensic evidence files. Evidence deletion will be strictly prohibited across the entire platform.`
        : `Release Legal Hold on "${c.title}"? Examiners will regain authority to manage evidence retention policies.`,
      action: async () => {
        try {
          await casesService.toggleLegalHold(c.id, nextHold);
          toast.success(nextHold ? 'Legal Hold enforced. Evidence locked.' : 'Legal Hold released.');
          loadData();
        } catch (err: any) {
          toast.error('Legal hold update failed: ' + err.message);
        }
      }
    });
  };

  const handleToggleArchive = async (c: AdminCase) => {
    const nextArchived = !c.is_archived;
    try {
      await casesService.toggleArchive(c.id, nextArchived);
      toast.success(nextArchived ? `Case archived.` : `Case unarchived.`);
      loadData();
    } catch (err: any) {
      toast.error('Archive action failed: ' + err.message);
    }
  };

  const handleOpenAssign = (c: AdminCase) => {
    setSelectedCase(c);
    setSelectedInvestigators([...c.assigned_investigators]);
    setAssignModalOpen(true);
  };

  const handleSaveAssignment = async () => {
    if (!selectedCase) return;
    try {
      await casesService.assignInvestigators(selectedCase.id, selectedInvestigators);
      toast.success(`Assigned investigators updated for ${selectedCase.title}.`);
      setAssignModalOpen(false);
      loadData();
    } catch (err: any) {
      toast.error('Assignment failed: ' + err.message);
    }
  };

  const columns: Column<AdminCase>[] = [
    {
      key: 'title',
      header: 'Case Title & Description',
      render: (c) => (
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className={`font-bold font-sans text-sm ${isLight ? 'text-slate-900' : 'text-white'}`}>
              {c.title}
            </span>
            {c.legal_hold && (
              <span
                className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold flex items-center gap-1 shadow-sm border ${
                  isLight
                    ? 'bg-rose-50 border-rose-200 text-rose-700'
                    : 'bg-red-950/80 border-red-700/60 text-red-400'
                }`}
              >
                <Lock className="w-2.5 h-2.5" />
                <span>LEGAL HOLD</span>
              </span>
            )}
            {c.is_archived && (
              <span
                className={`px-2 py-0.5 rounded-full text-[10px] font-mono border ${
                  isLight
                    ? 'bg-slate-100 border-slate-200 text-slate-500'
                    : 'bg-stone-900 border-stone-800 text-stone-500'
                }`}
              >
                ARCHIVED
              </span>
            )}
          </div>
          <p className={`text-xs font-sans line-clamp-1 ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
            {c.description}
          </p>
        </div>
      )
    },
    {
      key: 'status',
      header: 'Status',
      render: (c) => (
        <select
          value={c.status}
          onChange={(e) => handleStatusChange(c, e.target.value as CaseStatus)}
          className={`px-2.5 py-1 rounded-xl text-xs font-sans cursor-pointer focus:outline-none focus:border-[#f95721] border ${
            isLight
              ? 'bg-white border-slate-300 text-slate-800'
              : 'bg-[#191614] border-[#2e2623] text-stone-200'
          }`}
        >
          <option value="open" className={isLight ? 'bg-white text-slate-900' : 'bg-[#141211]'}>Open</option>
          <option value="under_review" className={isLight ? 'bg-white text-slate-900' : 'bg-[#141211]'}>Under Review</option>
          <option value="closed" className={isLight ? 'bg-white text-slate-900' : 'bg-[#141211]'}>Closed</option>
        </select>
      )
    },
    {
      key: 'owner',
      header: 'Docket Lead',
      render: (c) => (
        <span className={`text-xs font-mono ${isLight ? 'text-slate-700' : 'text-stone-300'}`}>
          {c.owner}
        </span>
      )
    },
    {
      key: 'created_date',
      header: 'Date Created',
      render: (c) => (
        <span className={`text-xs font-mono ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
          {new Date(c.created_date).toLocaleDateString([], { dateStyle: 'medium' })}
        </span>
      )
    },
    {
      key: 'assigned_investigators',
      header: 'Assigned Investigators',
      render: (c) => (
        <div className="flex flex-wrap gap-1">
          {c.assigned_investigators.map((inv) => (
            <span
              key={inv}
              className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                isLight
                  ? 'bg-slate-100 border-slate-200 text-slate-700'
                  : 'bg-black/40 border-[#2b2523] text-stone-300'
              }`}
            >
              {inv}
            </span>
          ))}
        </div>
      )
    },
    {
      key: 'actions',
      header: 'Actions',
      className: 'text-right',
      render: (c) => (
        <div className="flex items-center justify-end gap-1.5">
          <button
            type="button"
            onClick={() => handleOpenAssign(c)}
            className={`p-1.5 rounded-lg border transition-colors flex items-center gap-1 text-xs font-mono cursor-pointer ${
              isLight
                ? 'bg-slate-100 hover:bg-slate-200 text-slate-700 border-slate-200'
                : 'bg-stone-900 hover:bg-stone-800 text-stone-300 hover:text-white border-stone-700'
            }`}
            title="Assign Investigators"
          >
            <Users className="w-3.5 h-3.5 text-[#f95721]" />
            <span>Assign</span>
          </button>

          <button
            type="button"
            onClick={() => handleToggleLegalHold(c)}
            className={`p-1.5 rounded-lg border transition-colors flex items-center gap-1 text-xs font-mono cursor-pointer ${
              c.legal_hold
                ? isLight
                  ? 'bg-rose-50 hover:bg-rose-100 text-rose-700 border-rose-200'
                  : 'bg-red-950/60 hover:bg-red-900/60 text-red-300 border-red-700/60'
                : isLight
                ? 'bg-slate-100 hover:bg-slate-200 text-slate-600 border-slate-200'
                : 'bg-stone-900 hover:bg-stone-800 text-stone-400 border-stone-700'
            }`}
            title={c.legal_hold ? 'Release Legal Hold' : 'Enforce Legal Hold'}
          >
            {c.legal_hold ? <Lock className="w-3.5 h-3.5 text-red-500" /> : <Unlock className="w-3.5 h-3.5" />}
            <span>{c.legal_hold ? 'Hold Active' : 'Set Hold'}</span>
          </button>

          <button
            type="button"
            onClick={() => handleToggleArchive(c)}
            className={`p-1.5 rounded-lg border transition-colors cursor-pointer ${
              isLight
                ? 'bg-slate-100 hover:bg-slate-200 text-slate-600 border-slate-200'
                : 'bg-stone-900 hover:bg-stone-800 text-stone-400 hover:text-white border-stone-700'
            }`}
            title={c.is_archived ? 'Restore Case' : 'Archive Case'}
          >
            <Archive className="w-3.5 h-3.5" />
          </button>
        </div>
      )
    }
  ];

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div
        className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b ${
          isLight ? 'border-slate-200' : 'border-[#282321]'
        }`}
      >
        <div>
          <h1
            className={`text-xl sm:text-2xl font-black tracking-tight font-sans flex items-center gap-2.5 ${
              isLight ? 'text-slate-900' : 'text-white'
            }`}
          >
            <FolderLock className="w-6 h-6 text-[#f95721]" />
            <span>Case Management & Legal Holds</span>
          </h1>
          <p className={`text-xs sm:text-sm font-sans mt-0.5 ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
            Manage investigation lifecycle, assign forensic examiners, and lock evidence under statutory legal hold
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <FilterBar
        searchQuery={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search cases by title, owner, or assigned examiners..."
        filters={[
          {
            key: 'status',
            label: 'Status',
            value: statusFilter,
            options: [
              { label: 'All Statuses', value: 'all' },
              { label: 'Open', value: 'open' },
              { label: 'Under Review', value: 'under_review' },
              { label: 'Closed', value: 'closed' }
            ],
            onChange: setStatusFilter
          }
        ]}
        onResetFilters={() => {
          setSearch('');
          setStatusFilter('all');
        }}
      />

      {/* Main Cases Table */}
      <DataTable
        columns={columns}
        data={cases}
        keyExtractor={(c) => c.id}
        isLoading={isLoading}
        emptyTitle="No cases found"
        emptyMessage="No cases matched the search filter."
      />

      {/* Modal: Assign Investigators */}
      {assignModalOpen && selectedCase && (
        <div
          className={`fixed inset-0 z-50 flex items-center justify-center p-4 backdrop-blur-sm animate-fadeIn ${
            isLight ? 'bg-slate-900/40' : 'bg-black/80'
          }`}
        >
          <div
            className={`w-full max-w-md rounded-2xl border p-6 shadow-2xl space-y-4 ${
              isLight ? 'bg-white border-slate-200 text-slate-800' : 'bg-[#141211] border-[#2e2623] text-white'
            }`}
          >
            <div className={`flex items-center justify-between pb-3 border-b ${isLight ? 'border-slate-100' : 'border-[#26201e]'}`}>
              <h3 className={`text-base font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
                Assign Examiners: {selectedCase.title}
              </h3>
              <button
                type="button"
                onClick={() => setAssignModalOpen(false)}
                className={`text-xs font-mono cursor-pointer ${
                  isLight ? 'text-slate-400 hover:text-slate-700' : 'text-stone-400 hover:text-white'
                }`}
              >
                Close
              </button>
            </div>

            <p className={`text-xs font-sans ${isLight ? 'text-slate-600' : 'text-stone-300'}`}>
              Select verified forensic investigators authorized to access raw evidence and generate attack paths for this docket:
            </p>

            <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
              {allExaminers.map((examiner) => {
                const isSelected = selectedInvestigators.includes(examiner.name);
                return (
                  <div
                    key={examiner.id}
                    onClick={() => {
                      if (isSelected) {
                        setSelectedInvestigators((prev) => prev.filter((name) => name !== examiner.name));
                      } else {
                        setSelectedInvestigators((prev) => [...prev, examiner.name]);
                      }
                    }}
                    className={`p-3 rounded-xl border flex items-center justify-between cursor-pointer transition-all ${
                      isSelected
                        ? isLight
                          ? 'bg-orange-50 border-orange-300 text-orange-950 font-semibold'
                          : 'bg-[#29160e] border-[#f95721]/60 text-white'
                        : isLight
                        ? 'bg-slate-50 border-slate-200 text-slate-700 hover:border-slate-300'
                        : 'bg-black/30 border-[#28221f] text-stone-300 hover:border-stone-600'
                    }`}
                  >
                    <div className="space-y-0.5">
                      <div className="text-xs font-bold font-sans">{examiner.name}</div>
                      <div className={`text-[10px] font-mono ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
                        {examiner.department}
                      </div>
                    </div>
                    {isSelected && <CheckCircle2 className="w-4 h-4 text-[#f95721]" />}
                  </div>
                );
              })}
            </div>

            <div className={`flex items-center justify-end gap-2.5 pt-3 border-t ${isLight ? 'border-slate-100' : 'border-[#26201e]'}`}>
              <button
                type="button"
                onClick={() => setAssignModalOpen(false)}
                className={`px-4 py-2 rounded-xl text-xs font-semibold border cursor-pointer ${
                  isLight
                    ? 'text-slate-700 bg-slate-100 border-slate-300 hover:bg-slate-200'
                    : 'text-stone-300 bg-stone-900 border-stone-700 hover:bg-stone-800'
                }`}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSaveAssignment}
                className="px-4 py-2 rounded-xl text-xs font-bold text-white bg-[#f95721] hover:bg-[#ea580c] cursor-pointer shadow-md"
              >
                Save Assignment
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirm Dialog */}
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
