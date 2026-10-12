import React, { useState } from 'react';
import { useApp } from '../store';
import { Case, CaseStatus } from '../types';
import {
  FolderLock,
  Plus,
  Search,
  ArrowRight,
  Trash2,
  Edit2,
  X,
  ChevronDown,
  ArrowUpDown
} from 'lucide-react';

export const Cases: React.FC = () => {
  const {
    cases,
    activeCaseId,
    setActiveCaseId,
    createCase,
    updateCaseStatus,
    updateCaseDetails,
    deleteCase,
    setCurrentPage,
    currentUser
  } = useApp();

  const [statusFilter, setStatusFilter] = useState<'All' | CaseStatus>('All');
  const [sortBy, setSortBy] = useState<'newest' | 'oldest' | 'name' | 'detections' | 'events'>('newest');
  const [searchQuery, setSearchQuery] = useState('');
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [newCaseName, setNewCaseName] = useState('');
  const [newCaseDesc, setNewCaseDesc] = useState('');
  const [newCaseTags, setNewCaseTags] = useState('');

  // Editing state
  const [editingCase, setEditingCase] = useState<Case | null>(null);
  const [editName, setEditName] = useState('');
  const [editDesc, setEditDesc] = useState('');

  const filteredCases = cases
    .filter(c => {
      const matchesStatus = statusFilter === 'All' || c.status === statusFilter;
      const matchesSearch =
        c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.tags?.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()));
      return matchesStatus && matchesSearch;
    })
    .sort((a, b) => {
      if (sortBy === 'newest') {
        return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      }
      if (sortBy === 'oldest') {
        return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
      }
      if (sortBy === 'name') {
        return a.name.localeCompare(b.name);
      }
      if (sortBy === 'detections') {
        return (b.detection_count || 0) - (a.detection_count || 0);
      }
      if (sortBy === 'events') {
        return (b.event_count || 0) - (a.event_count || 0);
      }
      return 0;
    });

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCaseName.trim()) return;

    const tags = newCaseTags
      .split(',')
      .map(t => t.trim())
      .filter(t => t.length > 0);

    const newId = createCase(newCaseName.trim(), newCaseDesc.trim(), tags);
    setIsCreateModalOpen(false);
    setNewCaseName('');
    setNewCaseDesc('');
    setNewCaseTags('');
    setActiveCaseId(newId);
  };

  const handleEditSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingCase) return;
    updateCaseDetails(editingCase.id, editName.trim(), editDesc.trim());
    setEditingCase(null);
  };

  const isAdmin = currentUser?.role === 'admin';

  return (
    <div className="space-y-6">
      
      {/* Header & New Case Button (FR-CASE-1) */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[#282321]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#fafaf9] flex items-center gap-2.5">
            <FolderLock className="w-5 h-5 text-[#f95721]" />
            <span>Forensic Case Management</span>
          </h1>
          <p className="text-xs text-[#a8a29e] mt-1">
            Manage active incident reconstructions, chain-of-custody associations, and investigator assignments.
          </p>
        </div>

        <button
          onClick={() => setIsCreateModalOpen(true)}
          className="px-3.5 py-2 rounded-lg bg-[#f95721] hover:bg-[#ea580c] text-white font-semibold text-xs transition-all flex items-center gap-2 shadow-[0_0_15px_rgba(249,87,33,0.3)] hover:shadow-[0_0_20px_rgba(249,87,33,0.5)] cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          <span>New Investigation Case</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-[#161413]/90 border border-[#2b2523] rounded-xl backdrop-blur-xl">
        
        {/* Search */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-[#78716c] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search cases by name, description, or tag..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg pl-9 pr-3 py-1.5 text-xs text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]/50 transition-colors"
          />
        </div>

        {/* Dropdowns: Status filter & Sort By */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Status Filter Dropdown */}
          <div className="relative flex items-center bg-[#0d0c0c] border border-[#2b2523] rounded-lg px-2.5 py-1.5 text-xs font-mono">
            <span className="text-[#78716c] text-[11px] mr-1.5">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as 'All' | CaseStatus)}
              className="bg-transparent text-[#fafaf9] focus:outline-none cursor-pointer pr-5 font-semibold text-xs appearance-none"
            >
              <option value="All" className="bg-[#161413] text-[#e7e5e4]">All Statuses</option>
              <option value="Open" className="bg-[#161413] text-[#86efac]">Open</option>
              <option value="In Progress" className="bg-[#161413] text-[#f95721]">In Progress</option>
              <option value="Closed" className="bg-[#161413] text-[#a8a29e]">Closed</option>
            </select>
            <ChevronDown className="w-3.5 h-3.5 text-[#78716c] absolute right-2 pointer-events-none" />
          </div>

          {/* Sort By Dropdown */}
          <div className="relative flex items-center bg-[#0d0c0c] border border-[#2b2523] rounded-lg px-2.5 py-1.5 text-xs font-mono">
            <ArrowUpDown className="w-3 h-3 text-[#f95721] mr-1.5" />
            <span className="text-[#78716c] text-[11px] mr-1.5">Sort:</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="bg-transparent text-[#fafaf9] focus:outline-none cursor-pointer pr-5 font-semibold text-xs appearance-none"
            >
              <option value="newest" className="bg-[#161413] text-[#e7e5e4]">Newest First</option>
              <option value="oldest" className="bg-[#161413] text-[#e7e5e4]">Oldest First</option>
              <option value="name" className="bg-[#161413] text-[#e7e5e4]">Name (A-Z)</option>
              <option value="detections" className="bg-[#161413] text-[#e7e5e4]">Most Findings</option>
              <option value="events" className="bg-[#161413] text-[#e7e5e4]">Most Events</option>
            </select>
            <ChevronDown className="w-3.5 h-3.5 text-[#78716c] absolute right-2 pointer-events-none" />
          </div>

          <div className="text-xs text-[#a8a29e] font-mono tabular-nums px-2">
            {filteredCases.length} cases
          </div>
        </div>

      </div>

      {/* Case Grid (FR-CASE-2, FR-CASE-4) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredCases.map((c) => {
          const isActive = c.id === activeCaseId;

          return (
            <div
              key={c.id}
              className={`p-5 rounded-2xl border transition-all flex flex-col justify-between space-y-4 backdrop-blur-xl ${
                isActive
                  ? 'bg-[#1e1917] border-[#ea580c] shadow-[0_0_20px_rgba(249,87,33,0.15)] ring-1 ring-[#f95721]/30'
                  : 'bg-[#161413]/90 border-[#2b2523] hover:border-[#3a322e]'
              }`}
            >
              <div className="space-y-3">
                {/* Title & Status */}
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <h3
                        onClick={() => {
                          setActiveCaseId(c.id);
                          setCurrentPage('case_detail');
                        }}
                        className="text-base font-semibold text-[#fafaf9] hover:text-[#f95721] cursor-pointer transition-colors"
                      >
                        {c.name}
                      </h3>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-[#a8a29e] mt-1 font-mono">
                      <span>Owner: <strong className="text-[#fafaf9] font-normal">{c.owner_name}</strong></span>
                      <span>·</span>
                      <span>Created {c.created_at.slice(0, 10)}</span>
                    </div>
                  </div>

                  {/* Status Dropdown / Badge (FR-CASE-3) */}
                  <select
                    value={c.status}
                    onChange={(e) => updateCaseStatus(c.id, e.target.value as CaseStatus)}
                    className={`text-xs font-mono font-semibold px-2.5 py-1 rounded-lg border focus:outline-none cursor-pointer ${
                      c.status === 'Open'
                        ? 'bg-[#102a18] text-[#86efac] border-[#22c55e]/40'
                        : c.status === 'In Progress'
                        ? 'bg-[#2a140d] text-[#f95721] border-[#ea580c]/50'
                        : 'bg-[#1f1b19] text-[#a8a29e] border-[#38312d]'
                    }`}
                  >
                    <option value="Open">Open</option>
                    <option value="In Progress">In Progress</option>
                    <option value="Closed">Closed</option>
                  </select>
                </div>

                {/* Description */}
                <p className="text-xs text-[#a8a29e] line-clamp-2 leading-relaxed">
                  {c.description}
                </p>

                {/* Tags */}
                {c.tags && c.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {c.tags.map((t) => (
                      <span
                        key={t}
                        className="text-[11px] font-mono text-[#f95721] bg-[#2a140d] border border-[#ea580c]/30 px-2 py-0.5 rounded font-medium"
                      >
                        #{t}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Stats & Actions Footer */}
              <div className="pt-3 border-t border-[#282321] flex flex-wrap items-center justify-between gap-3 text-xs">
                
                {/* Micro Counters */}
                <div className="flex items-center gap-3 font-mono text-[#a8a29e] text-[11px]">
                  <span>{c.evidence_count} evidence files</span>
                  <span>·</span>
                  <span>{c.event_count} events</span>
                  <span>·</span>
                  <span className="text-[#f95721] font-semibold">{c.detection_count} detections</span>
                </div>

                {/* Buttons */}
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      setEditingCase(c);
                      setEditName(c.name);
                      setEditDesc(c.description);
                    }}
                    className="p-1.5 text-[#a8a29e] hover:text-[#fafaf9] hover:bg-[#25201e] rounded-lg transition-colors cursor-pointer"
                    title="Edit Case Details"
                  >
                    <Edit2 className="w-3.5 h-3.5" />
                  </button>

                  {isAdmin && (
                    <button
                      onClick={() => {
                        if (confirm(`Are you sure you want to delete case "${c.name}"?`)) {
                          deleteCase(c.id);
                        }
                      }}
                      className="p-1.5 text-[#a8a29e] hover:text-[#ef4444] hover:bg-[#25201e] rounded-lg transition-colors cursor-pointer"
                      title="Delete Case"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}

                  <button
                    onClick={() => {
                      setActiveCaseId(c.id);
                      setCurrentPage('case_detail');
                    }}
                    className={`px-3 py-1 rounded-lg font-medium text-xs transition-all flex items-center gap-1 cursor-pointer ${
                      isActive
                        ? 'bg-[#f95721] text-white font-semibold shadow-sm'
                        : 'bg-[#25201e] hover:bg-[#2f2926] text-[#e7e5e4]'
                    }`}
                  >
                    <span>{isActive ? 'Current Active' : 'Select Case'}</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>

              </div>

            </div>
          );
        })}
      </div>

      {/* Create Case Modal (FR-CASE-1) */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="w-full max-w-lg bg-[#161413] border border-[#2b2523] rounded-2xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#282321]">
              <h3 className="text-sm font-semibold text-[#fafaf9] flex items-center gap-2">
                <FolderLock className="w-4 h-4 text-[#f95721]" />
                <span>Create New Investigation Case</span>
              </h3>
              <button
                onClick={() => setIsCreateModalOpen(false)}
                className="text-[#a8a29e] hover:text-[#fafaf9] cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateSubmit} className="space-y-4 text-xs">
              <div className="space-y-1">
                <label className="text-[#d6d3d1] font-medium">Case Title / Incident Identifier *</label>
                <input
                  type="text"
                  required
                  value={newCaseName}
                  onChange={(e) => setNewCaseName(e.target.value)}
                  placeholder="e.g., Incident 2026-09A: Core Database Breach"
                  className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg px-3 py-2 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]/50"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[#d6d3d1] font-medium">Case Description & Scope</label>
                <textarea
                  rows={4}
                  value={newCaseDesc}
                  onChange={(e) => setNewCaseDesc(e.target.value)}
                  placeholder="Provide brief background on indicators, affected systems, and initial responder findings..."
                  className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg px-3 py-2 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]/50"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[#d6d3d1] font-medium">Investigation Tags (comma-separated)</label>
                <input
                  type="text"
                  value={newCaseTags}
                  onChange={(e) => setNewCaseTags(e.target.value)}
                  placeholder="e.g. APT, Ransomware, DMZ, ActiveDirectory"
                  className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg px-3 py-2 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] font-mono text-xs"
                />
              </div>

              <div className="pt-2 flex justify-end gap-2 border-t border-[#282321]">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-[#25201e] hover:bg-[#2f2926] text-[#d6d3d1] cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-[#f95721] hover:bg-[#ea580c] text-white font-semibold shadow-sm cursor-pointer"
                >
                  Create Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Case Modal (FR-CASE-5) */}
      {editingCase && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="w-full max-w-lg bg-[#161413] border border-[#2b2523] rounded-2xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#282321]">
              <h3 className="text-sm font-semibold text-[#fafaf9]">
                Edit Case Information
              </h3>
              <button onClick={() => setEditingCase(null)} className="text-[#a8a29e] hover:text-[#fafaf9] cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleEditSubmit} className="space-y-4 text-xs">
              <div className="space-y-1">
                <label className="text-[#d6d3d1] font-medium">Case Name</label>
                <input
                  type="text"
                  required
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg px-3 py-2 text-[#fafaf9] focus:outline-none focus:border-[#f95721]"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[#d6d3d1] font-medium">Description</label>
                <textarea
                  rows={4}
                  value={editDesc}
                  onChange={(e) => setEditDesc(e.target.value)}
                  className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg px-3 py-2 text-[#fafaf9] focus:outline-none focus:border-[#f95721]"
                />
              </div>

              <div className="pt-2 flex justify-end gap-2 border-t border-[#282321]">
                <button
                  type="button"
                  onClick={() => setEditingCase(null)}
                  className="px-4 py-2 rounded-lg bg-[#25201e] hover:bg-[#2f2926] text-[#d6d3d1] cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-[#f95721] hover:bg-[#ea580c] text-white font-semibold cursor-pointer"
                >
                  Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
};
