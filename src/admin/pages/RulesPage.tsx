import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldAlert,
  Play,
  Download,
  Upload,
  Plus,
  Trash2,
  Edit,
  CheckCircle2,
  AlertCircle,
  FileCode,
  Sliders
} from 'lucide-react';
import { DataTable, Column } from '../components/DataTable';
import { FilterBar } from '../components/FilterBar';
import { StatusBadge } from '../components/StatusBadge';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { rulesService } from '../../services/admin';
import { AdminSigmaRule, RuleSeverity } from '../types';
import { toast } from '../../components/Toast';

export const RulesPage: React.FC = () => {
  const [rules, setRules] = useState<AdminSigmaRule[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Filters
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');

  // Modals & Drawers
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [testModalOpen, setTestModalOpen] = useState(false);
  const [testResults, setTestResults] = useState<{
    ruleId: string;
    matchCount: number;
    sampleMatches: Array<{ timestamp: string; host: string; log_snippet: string }>;
  } | null>(null);

  // Form Fields
  const [editingRule, setEditingRule] = useState<AdminSigmaRule | null>(null);
  const [formName, setFormName] = useState('');
  const [formSeverity, setFormSeverity] = useState<RuleSeverity>('high');
  const [formMitre, setFormMitre] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formQuery, setFormQuery] = useState('');

  // File input ref for JSON import
  const fileInputRef = useRef<HTMLInputElement>(null);

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

  const loadData = async () => {
    setIsLoading(true);
    try {
      const list = await rulesService.getRules({ search, severity: severityFilter });
      setRules(list);
    } catch (err: any) {
      toast.error('Failed to load detection rules: ' + err.message);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [search, severityFilter]);

  const handleToggle = async (rule: AdminSigmaRule) => {
    const nextState = !rule.enabled;
    try {
      await rulesService.toggleRule(rule.id, nextState);
      toast.success(`Rule "${rule.name}" is now ${nextState ? 'Enabled' : 'Disabled'}.`);
      loadData();
    } catch (err: any) {
      toast.error('Failed to toggle rule: ' + err.message);
    }
  };

  const handleOpenCreate = () => {
    setFormName('');
    setFormSeverity('high');
    setFormMitre('T1059.001');
    setFormDescription('');
    setFormQuery('process_name = "powershell.exe" and command_line contains "-enc"');
    setCreateModalOpen(true);
  };

  const handleOpenEdit = (rule: AdminSigmaRule) => {
    setEditingRule(rule);
    setFormName(rule.name);
    setFormSeverity(rule.severity);
    setFormMitre(rule.mitre_id);
    setFormDescription(rule.description);
    setFormQuery(rule.query);
    setEditModalOpen(true);
  };

  const handleSaveCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await rulesService.createRule({
        name: formName,
        severity: formSeverity,
        mitre_id: formMitre,
        description: formDescription,
        query: formQuery
      });
      toast.success(`Sigma rule "${formName}" created.`);
      setCreateModalOpen(false);
      loadData();
    } catch (err: any) {
      toast.error(err.message || 'Creation failed');
    }
  };

  const handleSaveEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingRule) return;
    try {
      await rulesService.updateRule(editingRule.id, {
        name: formName,
        severity: formSeverity,
        mitre_id: formMitre,
        description: formDescription,
        query: formQuery
      });
      toast.success(`Updated rule "${formName}".`);
      setEditModalOpen(false);
      loadData();
    } catch (err: any) {
      toast.error(err.message || 'Update failed');
    }
  };

  const handleDelete = (rule: AdminSigmaRule) => {
    setConfirmDialog({
      isOpen: true,
      title: `Delete Rule: ${rule.name}`,
      message: `Permanently delete Sigma rule [${rule.name}] (${rule.mitre_id})? Active telemetry correlation triggers will be revoked.`,
      action: async () => {
        try {
          await rulesService.deleteRule(rule.id);
          toast.success(`Rule deleted.`);
          loadData();
        } catch (err: any) {
          toast.error(err.message || 'Delete failed');
        }
      }
    });
  };

  const handleTestRule = async (rule: AdminSigmaRule) => {
    try {
      toast.info(`Evaluating [${rule.name}] against telemetry stream...`);
      const results = await rulesService.testRule(rule.id);
      setTestResults(results);
      setTestModalOpen(true);
    } catch (err: any) {
      toast.error('Test execution failed: ' + err.message);
    }
  };

  const handleExportJson = () => {
    try {
      const json = rulesService.exportRulesToJson(rules);
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `dcsre_sigma_rules_${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success('Sigma rules exported as JSON.');
    } catch (err: any) {
      toast.error('Export failed');
    }
  };

  const handleImportJson = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (evt) => {
      try {
        const text = evt.target?.result as string;
        const count = await rulesService.importRulesFromJson(text);
        toast.success(`Imported ${count} Sigma detection rules.`);
        loadData();
      } catch (err: any) {
        toast.error('Import failed: ' + err.message);
      } finally {
        if (fileInputRef.current) fileInputRef.current.value = '';
      }
    };
    reader.readAsText(file);
  };

  const columns: Column<AdminSigmaRule>[] = [
    {
      key: 'name',
      header: 'Rule Title & Query Spec',
      render: (r) => (
        <div className="space-y-1">
          <div className="font-bold text-white font-sans text-xs sm:text-sm">{r.name}</div>
          <p className="text-xs text-stone-400 font-sans line-clamp-1">{r.description}</p>
          <code className="text-[10px] font-mono text-[#ff936b] bg-black/50 px-2 py-0.5 rounded border border-[#2b2523] block truncate max-w-md">
            {r.query}
          </code>
        </div>
      )
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (r) => <StatusBadge status={r.severity} variant="severity" />
    },
    {
      key: 'mitre_id',
      header: 'MITRE ATT&CK',
      render: (r) => (
        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-black/60 border border-[#3b322e] text-[#f95721] font-bold">
          {r.mitre_id}
        </span>
      )
    },
    {
      key: 'times_triggered',
      header: 'Times Triggered',
      render: (r) => (
        <span className="text-xs font-mono font-bold text-stone-300">
          {r.times_triggered} incidents
        </span>
      )
    },
    {
      key: 'enabled',
      header: 'Status & State',
      render: (r) => (
        <button
          type="button"
          onClick={() => handleToggle(r)}
          className={`px-3 py-1 rounded-full text-xs font-mono font-semibold transition-all border cursor-pointer ${
            r.enabled
              ? 'bg-emerald-950/70 border-emerald-600/60 text-emerald-300 hover:bg-emerald-900/60'
              : 'bg-stone-900 border-stone-800 text-stone-500 hover:bg-stone-800'
          }`}
        >
          {r.enabled ? 'Enabled' : 'Disabled'}
        </button>
      )
    },
    {
      key: 'actions',
      header: 'Actions',
      className: 'text-right',
      render: (r) => (
        <div className="flex items-center justify-end gap-1.5">
          <button
            type="button"
            onClick={() => handleTestRule(r)}
            className="px-2 py-1 rounded-lg bg-stone-900 hover:bg-orange-950/50 text-[#f95721] border border-stone-700 hover:border-[#f95721]/50 text-xs font-mono flex items-center gap-1 cursor-pointer transition-colors"
            title="Execute Rule Against Telemetry"
          >
            <Play className="w-3 h-3" />
            <span>Test</span>
          </button>

          <button
            type="button"
            onClick={() => handleOpenEdit(r)}
            className="p-1.5 rounded-lg bg-stone-900 hover:bg-stone-800 text-stone-300 hover:text-white border border-stone-700 cursor-pointer transition-colors"
            title="Edit Rule"
          >
            <Edit className="w-3.5 h-3.5" />
          </button>

          <button
            type="button"
            onClick={() => handleDelete(ruleItem(r))}
            className="p-1.5 rounded-lg bg-stone-900 hover:bg-red-950/50 text-stone-500 hover:text-red-400 border border-stone-700 hover:border-red-600/50 cursor-pointer transition-colors"
            title="Delete Rule"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      )
    }
  ];

  // Helper for typing
  const ruleItem = (r: AdminSigmaRule) => r;

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#282321]">
        <div>
          <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight font-sans flex items-center gap-2.5">
            <ShieldAlert className="w-6 h-6 text-[#f95721]" />
            <span>Sigma Detection Rules Engine</span>
          </h1>
          <p className="text-xs sm:text-sm text-stone-400 font-sans mt-0.5">
            Real-time telemetry tripwires, MITRE ATT&CK correlation, and rule validation
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleImportJson}
            accept=".json"
            className="hidden"
          />

          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-mono font-semibold text-stone-300 bg-stone-900 hover:bg-stone-800 border border-stone-700 cursor-pointer"
            title="Import Rules from JSON"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Import</span>
          </button>

          <button
            type="button"
            onClick={handleExportJson}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-mono font-semibold text-stone-300 bg-stone-900 hover:bg-stone-800 border border-stone-700 cursor-pointer"
            title="Export Rules as JSON"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export</span>
          </button>

          <button
            type="button"
            onClick={handleOpenCreate}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs sm:text-sm font-bold text-white bg-[#f95721] hover:bg-[#ea580c] transition-all shadow-[0_0_15px_rgba(249,87,33,0.3)] cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Add Rule</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <FilterBar
        searchQuery={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search Sigma rules by name, MITRE technique, or description..."
        filters={[
          {
            key: 'severity',
            label: 'Severity',
            value: severityFilter,
            options: [
              { label: 'All Severities', value: 'all' },
              { label: 'Critical', value: 'critical' },
              { label: 'High', value: 'high' },
              { label: 'Medium', value: 'medium' },
              { label: 'Low', value: 'low' }
            ],
            onChange: setSeverityFilter
          }
        ]}
        onResetFilters={() => {
          setSearch('');
          setSeverityFilter('all');
        }}
      />

      {/* Main Rules Table */}
      <DataTable
        columns={columns}
        data={rules}
        keyExtractor={(r) => r.id}
        isLoading={isLoading}
        emptyTitle="No Sigma rules matched"
        emptyMessage="Try adjusting search terms or add a new Sigma detection rule."
      />

      {/* Test Results Modal */}
      {testModalOpen && testResults && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-lg rounded-2xl bg-[#141211] border border-[#2e2623] p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#26201e]">
              <div className="flex items-center gap-2 text-white font-bold font-sans">
                <Play className="w-4 h-4 text-[#f95721]" />
                <span>Sigma Rule Simulation Output</span>
              </div>
              <button
                type="button"
                onClick={() => setTestModalOpen(false)}
                className="text-xs font-mono text-stone-400 hover:text-white cursor-pointer"
              >
                Close
              </button>
            </div>

            <div className="flex items-center justify-between p-3 rounded-xl bg-black/40 border border-[#28221f]">
              <span className="text-xs font-mono text-stone-400">Total Telemetry Matches</span>
              <span className="text-base font-mono font-bold text-emerald-400">
                {testResults.matchCount} Event Hits
              </span>
            </div>

            <div className="space-y-2">
              <span className="text-[11px] font-mono text-stone-400 uppercase tracking-wider block">
                Sample Correlated Log Snippets
              </span>
              {testResults.sampleMatches.map((m, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-xl bg-black/50 border border-[#2b2523] space-y-1 font-mono text-xs"
                >
                  <div className="flex items-center justify-between text-stone-500 text-[10px]">
                    <span>Host: {m.host}</span>
                    <span>{m.timestamp}</span>
                  </div>
                  <div className="text-stone-200">{m.log_snippet}</div>
                </div>
              ))}
            </div>

            <div className="pt-2 text-right">
              <button
                type="button"
                onClick={() => setTestModalOpen(false)}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-stone-300 bg-stone-900 hover:bg-stone-800 border border-stone-700 cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Create Rule */}
      {createModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-lg rounded-2xl bg-[#141211] border border-[#2e2724] p-6 shadow-2xl space-y-4">
            <h3 className="text-lg font-bold text-white font-sans">Author Sigma Detection Rule</h3>
            <form onSubmit={handleSaveCreate} className="space-y-3.5">
              <div>
                <label className="block text-xs font-mono text-stone-400 mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  placeholder="e.g. Cobalt Strike Beaconing via Rundll32"
                  className="w-full px-3 py-2 rounded-xl bg-black/40 border border-[#2e2724] text-white text-xs sm:text-sm focus:outline-none focus:border-[#f95721]"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono text-stone-400 mb-1">Severity</label>
                  <select
                    value={formSeverity}
                    onChange={(e) => setFormSeverity(e.target.value as RuleSeverity)}
                    className="w-full px-3 py-2 rounded-xl bg-black/40 border border-[#2e2724] text-white text-xs sm:text-sm focus:outline-none focus:border-[#f95721] cursor-pointer"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono text-stone-400 mb-1">MITRE ATT&CK ID</label>
                  <input
                    type="text"
                    required
                    value={formMitre}
                    onChange={(e) => setFormMitre(e.target.value)}
                    placeholder="e.g. T1059.001"
                    className="w-full px-3 py-2 rounded-xl bg-black/40 border border-[#2e2724] text-white text-xs sm:text-sm focus:outline-none focus:border-[#f95721]"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-mono text-stone-400 mb-1">Description</label>
                <input
                  type="text"
                  required
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  placeholder="Brief description of adversary activity detected"
                  className="w-full px-3 py-2 rounded-xl bg-black/40 border border-[#2e2724] text-white text-xs sm:text-sm focus:outline-none focus:border-[#f95721]"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-stone-400 mb-1">Detection Query</label>
                <textarea
                  rows={3}
                  required
                  value={formQuery}
                  onChange={(e) => setFormQuery(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-black/40 border border-[#2e2724] text-white font-mono text-xs focus:outline-none focus:border-[#f95721] resize-none"
                />
              </div>

              <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-[#26201e]">
                <button
                  type="button"
                  onClick={() => setCreateModalOpen(false)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-stone-300 bg-stone-900 border border-stone-700 hover:bg-stone-800 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl text-xs font-bold text-white bg-[#f95721] hover:bg-[#ea580c] cursor-pointer shadow-md"
                >
                  Create Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Edit Rule */}
      {editModalOpen && editingRule && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-lg rounded-2xl bg-[#141211] border border-[#2e2724] p-6 shadow-2xl space-y-4">
            <h3 className="text-lg font-bold text-white font-sans">Edit Sigma Rule: {editingRule.name}</h3>
            <form onSubmit={handleSaveEdit} className="space-y-3.5">
              <div>
                <label className="block text-xs font-mono text-stone-400 mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-black/40 border border-[#2e2724] text-white text-xs sm:text-sm focus:outline-none focus:border-[#f95721]"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono text-stone-400 mb-1">Severity</label>
                  <select
                    value={formSeverity}
                    onChange={(e) => setFormSeverity(e.target.value as RuleSeverity)}
                    className="w-full px-3 py-2 rounded-xl bg-black/40 border border-[#2e2724] text-white text-xs sm:text-sm focus:outline-none focus:border-[#f95721] cursor-pointer"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono text-stone-400 mb-1">MITRE ATT&CK ID</label>
                  <input
                    type="text"
                    required
                    value={formMitre}
                    onChange={(e) => setFormMitre(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-black/40 border border-[#2e2724] text-white text-xs sm:text-sm focus:outline-none focus:border-[#f95721]"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-mono text-stone-400 mb-1">Description</label>
                <input
                  type="text"
                  required
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-black/40 border border-[#2e2724] text-white text-xs sm:text-sm focus:outline-none focus:border-[#f95721]"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-stone-400 mb-1">Detection Query</label>
                <textarea
                  rows={3}
                  required
                  value={formQuery}
                  onChange={(e) => setFormQuery(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-black/40 border border-[#2e2724] text-white font-mono text-xs focus:outline-none focus:border-[#f95721] resize-none"
                />
              </div>

              <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-[#26201e]">
                <button
                  type="button"
                  onClick={() => setEditModalOpen(false)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-stone-300 bg-stone-900 border border-stone-700 hover:bg-stone-800 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl text-xs font-bold text-white bg-[#f95721] hover:bg-[#ea580c] cursor-pointer shadow-md"
                >
                  Save Changes
                </button>
              </div>
            </form>
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
