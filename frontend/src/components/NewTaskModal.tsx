import React, { useState } from 'react';
import { useApp } from '../store';
import { X, Plus, ShieldAlert, Sparkles, FolderPlus } from 'lucide-react';

interface NewTaskModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const NewTaskModal: React.FC<NewTaskModalProps> = ({ isOpen, onClose }) => {
  const { createCase, setActiveCaseId, setCurrentPage } = useApp();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [tagInput, setTagInput] = useState('APT, Perimeter, Zero-Day');

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    const tags = tagInput.split(',').map(t => t.trim()).filter(Boolean);
    const newCaseId = createCase(name.trim(), description.trim() || 'New incident reconstruction workspace', tags);
    setActiveCaseId(newCaseId);
    setCurrentPage('findings');
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
      <div className="w-full max-w-lg rounded-2xl bg-[#101014] border border-neutral-800 shadow-[0_25px_70px_rgba(0,0,0,0.9)] p-6 space-y-5">
        
        <div className="flex items-center justify-between pb-3 border-b border-neutral-800/80">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-[#ff461e]/20 border border-[#ff461e]/40 flex items-center justify-center text-[#ff461e]">
              <FolderPlus className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">Create New Forensic Task</h3>
              <p className="text-[11px] text-neutral-400">Initialize an incident reconstruction workspace</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded-lg text-neutral-400 hover:text-white hover:bg-neutral-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div className="space-y-1.5">
            <label className="text-[11px] font-semibold text-neutral-300">Case / Task Name</label>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Operation Chimera - DC01 Breach"
              className="w-full bg-neutral-950/80 border border-neutral-800 rounded-xl px-3.5 py-2.5 text-neutral-100 placeholder-neutral-600 focus:outline-none focus:border-[#ff461e]"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-[11px] font-semibold text-neutral-300">Investigation Scope & Description</label>
            <textarea
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Describe suspected threat actor, compromised network segments, or telemetry sources..."
              className="w-full bg-neutral-950/80 border border-neutral-800 rounded-xl p-3 text-neutral-100 placeholder-neutral-600 focus:outline-none focus:border-[#ff461e]"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-[11px] font-semibold text-neutral-300">Tags (Comma-separated)</label>
            <input
              type="text"
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              placeholder="APT29, Lateral Movement, WebShell"
              className="w-full bg-neutral-950/80 border border-neutral-800 rounded-xl px-3.5 py-2 text-neutral-100 placeholder-neutral-600 focus:outline-none focus:border-[#ff461e]"
            />
          </div>

          <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-neutral-800/80">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl text-neutral-300 hover:bg-neutral-850 text-xs font-semibold transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-5 py-2 rounded-xl bg-gradient-to-r from-[#ff461e] to-[#ff5722] hover:from-[#ff5722] hover:to-[#ff6a3d] text-white font-semibold text-xs tracking-wide transition-all shadow-[0_0_20px_rgba(255,70,30,0.35)] flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Initialize Task</span>
            </button>
          </div>
        </form>

      </div>
    </div>
  );
};
