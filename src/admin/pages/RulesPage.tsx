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
import { useApp } from '../../store';

export const RulesPage: React.FC = () => {
  const { theme } = useApp();
  const isLight = theme === 'light';

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
          <div className={`font-bold font-sans text-xs sm:text-sm ${isLight ? 'text-slate-900' : 'text-white'}`}>{r.name}</div>
          <p className={`text-xs font-sans line-clamp-1 ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>{r.description}</p>
          <code className={`text-[10px] font-mono px-2 py-0.5 rounded border block truncate max-w-md ${
            isLight
              ? 'text-[#f95721] bg-orange-50/80 border-orange-200'
              : 'text-[#ff936b] bg-black/50 border-[#2b2523]'
          }`}>
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
        <span className={`text-[11px] font-mono px-2 py-0.5 rounded border font-bold ${
          isLight
            ? 'bg-orange-50 border-orange-200 text-[#f95721]'
            : 'bg-black/60 border-[#3b322e] text-[#f95721]'
        }`}>
          {r.mitre_id}
        </span>
      )
    },
    {
      key: 'times_triggered',
      header: 'Times Triggered',
      render: (r) => (
        <span className={`text-xs font-mono font-bold ${isLight ? 'text-slate-700' : 'text-stone-300'}`}>
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
              ? isLight
                ? 'bg-emerald-50 border-emerald-200 text-emerald-700 hover:bg-emerald-100'
                : 'bg-emerald-950/70 border-emerald-600/60 text-emerald-300 hover:bg-emerald-900/60'
              : isLight
                ? 'bg-slate-100 border-slate-200 text-slate-500 hover:bg-slate-200'
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
            className={`px-2 py-1 rounded-lg border text-xs font-mono flex items-center gap-1 cursor-pointer transition-colors ${
              isLight
                ? 'bg-slate-100 hover:bg-orange-50 text-[#f95721] border-slate-200 hover:border-orange-300'
                : 'bg-stone-900 hover:bg-orange-950/50 text-[#f95721] border-stone-700 hover:border-[#f95721]/50'
            }`}
            title="Execute Rule Against Telemetry"
          >
            <Play className="w-3 h-3" />
            <span>Test</span>
          </button>

          <button
            type="button"
            onClick={() => handleOpenEdit(r)}
            className={`p-1.5 rounded-lg border cursor-pointer transition-colors ${
              isLight
                ? 'bg-slate-100 hover:bg-slate-200 text-slate-700 hover:text-slate-900 border-slate-200'
                : 'bg-stone-900 hover:bg-stone-800 text-stone-300 hover:text-white border-stone-700'
            }`}
            title="Edit Rule"
          >
            <Edit className="w-3.5 h-3.5" />
          </button>

          <button
            type="button"
            onClick={() => handleDelete(ruleItem(r))}
            className={`p-1.5 rounded-lg border cursor-pointer transition-colors ${
              isLight
                ? 'bg-slate-100 hover:bg-red-50 text-slate-500 hover:text-red-600 border-slate-200 hover:border-red-200'
                : 'bg-stone-900 hover:bg-red-950/50 text-stone-500 hover:text-red-400 border-stone-700 hover:border-red-600/50'
            }`}
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
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b ${
        isLight ? 'border-slate-200' : 'border-[#282321]'
      }`}>
        <div>
          <h1 className={`text-xl sm:text-2xl font-black tracking-tight font-sans flex items-center gap-2.5 ${
            isLight ? 'text-slate-900' : 'text-white'
          }`}>
            <ShieldAlert className="w-6 h-6 text-[#f95721]" />
            <span>Sigma Detection Rules Engine</span>
          </h1>
          <p className={`text-xs sm:text-sm font-sans mt-0.5 ${
            isLight ? 'text-slate-500' : 'text-stone-400'
          }`}>
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
            className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-mono font-semibold cursor-pointer border transition-colors ${
              isLight
                ? 'text-slate-700 bg-white hover:bg-slate-50 border-slate-300'
                : 'text-stone-300 bg-stone-900 hover:bg-stone-800 border-stone-700'
            }`}
            title="Import Rules from JSON"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Import</span>
          </button>

          <button
            type="button"
            onClick={handleExportJson}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-mono font-semibold cursor-pointer border transition-colors ${
              isLight
                ? 'text-slate-700 bg-white hover:bg-slate-50 border-slate-300'
                : 'text-stone-300 bg-stone-900 hover:bg-stone-800 border-stone-700'
            }`}
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
        <div className={`fixed inset-0 z-50 flex items-center justify-center p-4 backdrop-blur-sm animate-fadeIn ${
          isLight ? 'bg-slate-900/40' : 'bg-black/80'
        }`}>
          <div className={`w-full max-w-lg rounded-2xl p-6 space-y-4 border ${
            isLight
              ? 'bg-white border-slate-200 shadow-xl text-slate-800'
              : 'bg-[#141211] border-[#2e2623] shadow-2xl text-white'
          }`}>
            <div className={`flex items-center justify-between pb-3 border-b ${
              isLight ? 'border-slate-200' : 'border-[#26201e]'
            }`}>
              <div className={`flex items-center gap-2 font-bold font-sans ${
                isLight ? 'text-slate-900' : 'text-white'
              }`}>
                <Play className="w-4 h-4 text-[#f95721]" />
                <span>Sigma Rule Simulation Output</span>
              </div>
              <button
                type="button"
                onClick={() => setTestModalOpen(false)}
                className={`text-xs font-mono cursor-pointer ${
                  isLight ? 'text-slate-400 hover:text-slate-700' : 'text-stone-400 hover:text-white'
                }`}
              >
                Close
              </button>
            </div>

            <div className={`flex items-center justify-between p-3 rounded-xl border ${
              isLight ? 'bg-slate-50 border-slate-200' : 'bg-black/40 border-[#28221f]'
            }`}>
              <span className={`text-xs font-mono ${isLight ? 'text-slate-600' : 'text-stone-400'}`}>Total Telemetry Matches</span>
              <span className="text-base font-mono font-bold text-emerald-600 dark:text-emerald-400">
                {testResults.matchCount} Event Hits
              </span>
            </div>

            <div className="space-y-2">
              <span className={`text-[11px] font-mono uppercase tracking-wider block ${
                isLight ? 'text-slate-500' : 'text-stone-400'
              }`}>
                Sample Correlated Log Snippets
              </span>
              {testResults.sampleMatches.map((m, idx) => (
                <div
                  key={idx}
                  className={`p-3 rounded-xl border space-y-1 font-mono text-xs ${
                    isLight ? 'bg-slate-50 border-slate-200' : 'bg-black/50 border-[#2b2523]'
                  }`}
                >
                  <div className={`flex items-center justify-between text-[10px] ${
                    isLight ? 'text-slate-400' : 'text-stone-500'
                  }`}>
                    <span>Host: {m.host}</span>
                    <span>{m.timestamp}</span>
                  </div>
                  <div className={isLight ? 'text-slate-800' : 'text-stone-200'}>{m.log_snippet}</div>
                </div>
              ))}
            </div>

            <div className="pt-2 text-right">
              <button
                type="button"
                onClick={() => setTestModalOpen(false)}
                className={`px-4 py-2 rounded-xl text-xs font-semibold border cursor-pointer ${
                  isLight
                    ? 'text-slate-700 bg-slate-100 hover:bg-slate-200 border-slate-300'
                    : 'text-stone-300 bg-stone-900 hover:bg-stone-800 border-stone-700'
                }`}
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Create Rule */}
      {createModalOpen && (
        <div className={`fixed inset-0 z-50 flex items-center justify-center p-4 backdrop-blur-sm animate-fadeIn ${
          isLight ? 'bg-slate-900/40' : 'bg-black/80'
        }`}>
          <div className={`w-full max-w-lg rounded-2xl p-6 space-y-4 border ${
            isLight
              ? 'bg-white border-slate-200 shadow-xl'
              : 'bg-[#141211] border-[#2e2724] shadow-2xl'
          }`}>
            <h3 className={`text-lg font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>Author Sigma Detection Rule</h3>
            <form onSubmit={handleSaveCreate} className="space-y-3.5">
              <div>
                <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-700' : 'text-stone-400'}`}>Rule Name</label>
                <input
                  type="text"
                  required
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  placeholder="e.g. Cobalt Strike Beaconing via Rundll32"
                  className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm focus:outline-none focus:border-[#f95721] border ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900 placeholder:text-slate-400'
                      : 'bg-black/40 border-[#2e2724] text-white'
                  }`}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-700' : 'text-stone-400'}`}>Severity</label>
                  <select
                    value={formSeverity}
                    onChange={(e) => setFormSeverity(e.target.value as RuleSeverity)}
                    className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm focus:outline-none focus:border-[#f95721] cursor-pointer border ${
                      isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-900'
                        : 'bg-black/40 border-[#2e2724] text-white'
                    }`}
                  >
                    <option value="critical" className={isLight ? 'text-slate-900 bg-white' : ''}>Critical</option>
                    <option value="high" className={isLight ? 'text-slate-900 bg-white' : ''}>High</option>
                    <option value="medium" className={isLight ? 'text-slate-900 bg-white' : ''}>Medium</option>
                    <option value="low" className={isLight ? 'text-slate-900 bg-white' : ''}>Low</option>
                  </select>
                </div>

                <div>
                  <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-700' : 'text-stone-400'}`}>MITRE ATT&CK ID</label>
                  <input
                    type="text"
                    required
                    value={formMitre}
                    onChange={(e) => setFormMitre(e.target.value)}
                    placeholder="e.g. T1059.001"
                    className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm focus:outline-none focus:border-[#f95721] border ${
                      isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-900 placeholder:text-slate-400'
                        : 'bg-black/40 border-[#2e2724] text-white'
                    }`}
                  />
                </div>
              </div>

              <div>
                <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-700' : 'text-stone-400'}`}>Description</label>
                <input
                  type="text"
                  required
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  placeholder="Brief description of adversary activity detected"
                  className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm focus:outline-none focus:border-[#f95721] border ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900 placeholder:text-slate-400'
                      : 'bg-black/40 border-[#2e2724] text-white'
                  }`}
                />
              </div>

              <div>
                <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-700' : 'text-stone-400'}`}>Detection Query</label>
                <textarea
                  rows={3}
                  required
                  value={formQuery}
                  onChange={(e) => setFormQuery(e.target.value)}
                  className={`w-full px-3 py-2 rounded-xl font-mono text-xs focus:outline-none focus:border-[#f95721] resize-none border ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900'
                      : 'bg-black/40 border-[#2e2724] text-white'
                  }`}
                />
              </div>

              <div className={`flex items-center justify-end gap-2.5 pt-3 border-t ${
                isLight ? 'border-slate-200' : 'border-[#26201e]'
              }`}>
                <button
                  type="button"
                  onClick={() => setCreateModalOpen(false)}
                  className={`px-4 py-2 rounded-xl text-xs font-semibold cursor-pointer border ${
                    isLight
                      ? 'text-slate-700 bg-slate-100 hover:bg-slate-200 border-slate-300'
                      : 'text-stone-300 bg-stone-900 border-stone-700 hover:bg-stone-800'
                  }`}
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
        <div className={`fixed inset-0 z-50 flex items-center justify-center p-4 backdrop-blur-sm animate-fadeIn ${
          isLight ? 'bg-slate-900/40' : 'bg-black/80'
        }`}>
          <div className={`w-full max-w-lg rounded-2xl p-6 space-y-4 border ${
            isLight
              ? 'bg-white border-slate-200 shadow-xl'
              : 'bg-[#141211] border-[#2e2724] shadow-2xl'
          }`}>
            <h3 className={`text-lg font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>Edit Sigma Rule: {editingRule.name}</h3>
            <form onSubmit={handleSaveEdit} className="space-y-3.5">
              <div>
                <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-700' : 'text-stone-400'}`}>Rule Name</label>
                <input
                  type="text"
                  required
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm focus:outline-none focus:border-[#f95721] border ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900'
                      : 'bg-black/40 border-[#2e2724] text-white'
                  }`}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-700' : 'text-stone-400'}`}>Severity</label>
                  <select
                    value={formSeverity}
                    onChange={(e) => setFormSeverity(e.target.value as RuleSeverity)}
                    className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm focus:outline-none focus:border-[#f95721] cursor-pointer border ${
                      isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-900'
                        : 'bg-black/40 border-[#2e2724] text-white'
                    }`}
                  >
                    <option value="critical" className={isLight ? 'text-slate-900 bg-white' : ''}>Critical</option>
                    <option value="high" className={isLight ? 'text-slate-900 bg-white' : ''}>High</option>
                    <option value="medium" className={isLight ? 'text-slate-900 bg-white' : ''}>Medium</option>
                    <option value="low" className={isLight ? 'text-slate-900 bg-white' : ''}>Low</option>
                  </select>
                </div>

                <div>
                  <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-700' : 'text-stone-400'}`}>MITRE ATT&CK ID</label>
                  <input
                    type="text"
                    required
                    value={formMitre}
                    onChange={(e) => setFormMitre(e.target.value)}
                    className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm focus:outline-none focus:border-[#f95721] border ${
                      isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-900'
                        : 'bg-black/40 border-[#2e2724] text-white'
                    }`}
                  />
                </div>
              </div>

              <div>
                <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-700' : 'text-stone-400'}`}>Description</label>
                <input
                  type="text"
                  required
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  className={`w-full px-3 py-2 rounded-xl text-xs sm:text-sm focus:outline-none focus:border-[#f95721] border ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900'
                      : 'bg-black/40 border-[#2e2724] text-white'
                  }`}
                />
              </div>

              <div>
                <label className={`block text-xs font-mono mb-1 ${isLight ? 'text-slate-700' : 'text-stone-400'}`}>Detection Query</label>
                <textarea
                  rows={3}
                  required
                  value={formQuery}
                  onChange={(e) => setFormQuery(e.target.value)}
                  className={`w-full px-3 py-2 rounded-xl font-mono text-xs focus:outline-none focus:border-[#f95721] resize-none border ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900'
                      : 'bg-black/40 border-[#2e2724] text-white'
                  }`}
                />
              </div>

              <div className={`flex items-center justify-end gap-2.5 pt-3 border-t ${
                isLight ? 'border-slate-200' : 'border-[#26201e]'
              }`}>
                <button
                  type="button"
                  onClick={() => setEditModalOpen(false)}
                  className={`px-4 py-2 rounded-xl text-xs font-semibold cursor-pointer border ${
                    isLight
                      ? 'text-slate-700 bg-slate-100 hover:bg-slate-200 border-slate-300'
                      : 'text-stone-300 bg-stone-900 border-stone-700 hover:bg-stone-800'
                  }`}
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
