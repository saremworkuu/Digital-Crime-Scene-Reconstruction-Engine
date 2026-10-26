import React, { useState, useEffect } from 'react';
import {
  Settings,
  Globe,
  Building,
  Calendar,
  Lock,
  Shield,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Save,
  HelpCircle
} from 'lucide-react';
import { systemService } from '../../services/admin';
import { AdminSettings } from '../types';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { toast } from '../../components/Toast';
import { useApp } from '../../store';

export const SettingsPage: React.FC = () => {
  const { theme } = useApp();
  const isLight = theme === 'light';

  const [settings, setSettings] = useState<AdminSettings | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);

  // Form State
  const [orgName, setOrgName] = useState('');
  const [timeZone, setTimeZone] = useState('UTC');
  const [retentionDays, setRetentionDays] = useState(365);
  const [minPasswordLength, setMinPasswordLength] = useState(12);
  const [twoFactorEnforced, setTwoFactorEnforced] = useState(false);
  const [lockoutLimit, setLockoutLimit] = useState(5);

  // Reset Demo Data Confirm Dialog
  const [resetDialogOpen, setResetDialogOpen] = useState(false);
  const [isResetting, setIsResetting] = useState(false);

  const loadSettings = async () => {
    setIsLoading(true);
    try {
      const data = await systemService.getSettings();
      setSettings(data);
      setOrgName(data.org_name);
      setTimeZone(data.time_zone);
      setRetentionDays(data.retention_days);
      setMinPasswordLength(data.min_password_length);
      setTwoFactorEnforced(data.two_factor_enforced);
      setLockoutLimit(data.failed_login_lockout_limit);
    } catch (err: any) {
      toast.error('Failed to load settings: ' + err.message);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    try {
      const updated = await systemService.updateSettings({
        org_name: orgName,
        time_zone: timeZone,
        retention_days: Number(retentionDays),
        min_password_length: Number(minPasswordLength),
        two_factor_enforced: twoFactorEnforced,
        failed_login_lockout_limit: Number(lockoutLimit)
      });
      setSettings(updated);
      toast.success('System settings saved successfully');
    } catch (err: any) {
      toast.error('Failed to update settings: ' + err.message);
    } finally {
      setIsSaving(false);
    }
  };

  const handleResetDemoData = async () => {
    setIsResetting(true);
    try {
      await systemService.resetDemoData();
      toast.success('Admin mock environment reset to factory seed values');
      setTimeout(() => {
        window.location.reload();
      }, 1000);
    } catch (err: any) {
      toast.error('Failed to reset demo data: ' + err.message);
    } finally {
      setIsResetting(false);
      setResetDialogOpen(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Page Header */}
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b ${
        isLight ? 'border-slate-200' : 'border-[#2e2926]'
      }`}>
        <div>
          <h1 className={`text-xl font-bold tracking-tight flex items-center gap-2.5 ${
            isLight ? 'text-slate-900' : 'text-[#e7e5e4]'
          }`}>
            <Settings className="w-5 h-5 text-[#f95721]" />
            Global Platform Settings
          </h1>
          <p className={`text-xs mt-1 ${isLight ? 'text-slate-500' : 'text-[#a8a29e]'}`}>
            Configure report branding, evidence retention horizons, default investigation timezones, and forensic security baselines.
          </p>
        </div>
      </div>

      {/* Main Settings Form */}
      <form onSubmit={handleSave} className="space-y-6">
        {/* Section 1: Organization & Forensic Branding */}
        <div className={`rounded-xl p-5 space-y-4 border ${
          isLight
            ? 'bg-white border-slate-200 text-slate-800 shadow-sm'
            : 'bg-[#121110] border-[#24201e]'
        }`}>
          <div className={`flex items-center gap-2 pb-2 border-b ${
            isLight ? 'border-slate-200' : 'border-[#24201e]'
          }`}>
            <Building className="w-4 h-4 text-[#f95721]" />
            <h2 className={`text-sm font-semibold ${isLight ? 'text-slate-900' : 'text-[#e7e5e4]'}`}>Report Branding & Department Identity</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div>
              <label htmlFor="orgNameInput" className={`block font-medium mb-1.5 ${isLight ? 'text-slate-700' : 'text-[#a8a29e]'}`}>
                Organization / Lab Name
              </label>
              <input
                id="orgNameInput"
                type="text"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                required
                className={`w-full px-3 py-2 rounded-lg focus:outline-none focus:border-[#f95721] font-sans border ${
                  isLight
                    ? 'bg-slate-50 border-slate-300 text-slate-900'
                    : 'bg-[#181615] border-[#292422] text-[#e7e5e4]'
                }`}
              />
              <p className={`text-[11px] mt-1 ${isLight ? 'text-slate-500' : 'text-[#78716c]'}`}>
                Appears on generated forensic PDFs, chain-of-custody headers, and court export packages.
              </p>
            </div>

            <div>
              <label htmlFor="timeZoneSelect" className={`block font-medium mb-1.5 flex items-center gap-1.5 ${isLight ? 'text-slate-700' : 'text-[#a8a29e]'}`}>
                <Globe className="w-3.5 h-3.5 text-[#f95721]" />
                Investigation Reference Timezone
              </label>
              <select
                id="timeZoneSelect"
                value={timeZone}
                onChange={(e) => setTimeZone(e.target.value)}
                className={`w-full px-3 py-2 rounded-lg focus:outline-none focus:border-[#f95721] font-mono text-xs cursor-pointer border ${
                  isLight
                    ? 'bg-slate-50 border-slate-300 text-slate-900'
                    : 'bg-[#181615] border-[#292422] text-[#e7e5e4]'
                }`}
              >
                <option value="UTC" className={isLight ? 'bg-white text-slate-900' : ''}>UTC (Coordinated Universal Time) [Recommended for Forensic Timelines]</option>
                <option value="America/New_York" className={isLight ? 'bg-white text-slate-900' : ''}>America/New_York (EST/EDT)</option>
                <option value="America/Los_Angeles" className={isLight ? 'bg-white text-slate-900' : ''}>America/Los_Angeles (PST/PDT)</option>
                <option value="Europe/London" className={isLight ? 'bg-white text-slate-900' : ''}>Europe/London (GMT/BST)</option>
                <option value="Europe/Berlin" className={isLight ? 'bg-white text-slate-900' : ''}>Europe/Berlin (CET/CEST)</option>
                <option value="Asia/Tokyo" className={isLight ? 'bg-white text-slate-900' : ''}>Asia/Tokyo (JST)</option>
                <option value="Africa/Addis_Ababa" className={isLight ? 'bg-white text-slate-900' : ''}>Africa/Addis_Ababa (EAT +03:00)</option>
              </select>
              <p className={`text-[11px] mt-1 ${isLight ? 'text-slate-500' : 'text-[#78716c]'}`}>
                Timestamps normalized from EVTX, PCAP, and syslog are displayed relative to this baseline.
              </p>
            </div>
          </div>
        </div>

        {/* Section 2: Data Retention & Compliance */}
        <div className={`rounded-xl p-5 space-y-4 border ${
          isLight
            ? 'bg-white border-slate-200 text-slate-800 shadow-sm'
            : 'bg-[#121110] border-[#24201e]'
        }`}>
          <div className={`flex items-center gap-2 pb-2 border-b ${
            isLight ? 'border-slate-200' : 'border-[#24201e]'
          }`}>
            <Calendar className="w-4 h-4 text-[#f95721]" />
            <h2 className={`text-sm font-semibold ${isLight ? 'text-slate-900' : 'text-[#e7e5e4]'}`}>Evidence & Audit Retention Policy</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div>
              <label htmlFor="retentionDaysInput" className={`block font-medium mb-1.5 ${isLight ? 'text-slate-700' : 'text-[#a8a29e]'}`}>
                Retention Horizon (Days)
              </label>
              <input
                id="retentionDaysInput"
                type="number"
                min="30"
                max="3650"
                value={retentionDays}
                onChange={(e) => setRetentionDays(Number(e.target.value))}
                required
                className={`w-full px-3 py-2 rounded-lg focus:outline-none focus:border-[#f95721] font-mono border ${
                  isLight
                    ? 'bg-slate-50 border-slate-300 text-slate-900'
                    : 'bg-[#181615] border-[#292422] text-[#e7e5e4]'
                }`}
              />
              <p className={`text-[11px] mt-1 ${isLight ? 'text-slate-500' : 'text-[#78716c]'}`}>
                Cases older than this retention threshold will be queued for automated archive unless under Legal Hold.
              </p>
            </div>

            <div className={`p-3 rounded-lg flex items-start gap-2.5 border ${
              isLight
                ? 'bg-emerald-50/70 border-emerald-200 text-slate-700'
                : 'bg-[#181615] border-[#292422]'
            }`}>
              <Shield className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
              <div className={`text-[11px] ${isLight ? 'text-slate-600' : 'text-[#a8a29e]'}`}>
                <strong className={isLight ? 'text-emerald-800' : 'text-[#e7e5e4]'}>Legal Hold Overrule:</strong> Any active case flagged with a Legal Hold
                strictly prevents automated deletion, immutable evidence wiping, or audit log truncation regardless of retention limits.
              </div>
            </div>
          </div>
        </div>

        {/* Section 3: Forensic Security & Auth Controls */}
        <div className={`rounded-xl p-5 space-y-4 border ${
          isLight
            ? 'bg-white border-slate-200 text-slate-800 shadow-sm'
            : 'bg-[#121110] border-[#24201e]'
        }`}>
          <div className={`flex items-center gap-2 pb-2 border-b ${
            isLight ? 'border-slate-200' : 'border-[#24201e]'
          }`}>
            <Lock className="w-4 h-4 text-[#f95721]" />
            <h2 className={`text-sm font-semibold ${isLight ? 'text-slate-900' : 'text-[#e7e5e4]'}`}>Authentication & Password Baselines</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div>
              <label htmlFor="minPasswordLengthInput" className={`block font-medium mb-1.5 ${isLight ? 'text-slate-700' : 'text-[#a8a29e]'}`}>
                Min Password Length
              </label>
              <input
                id="minPasswordLengthInput"
                type="number"
                min="8"
                max="32"
                value={minPasswordLength}
                onChange={(e) => setMinPasswordLength(Number(e.target.value))}
                className={`w-full px-3 py-2 rounded-lg focus:outline-none focus:border-[#f95721] font-mono border ${
                  isLight
                    ? 'bg-slate-50 border-slate-300 text-slate-900'
                    : 'bg-[#181615] border-[#292422] text-[#e7e5e4]'
                }`}
              />
              <p className={`text-[11px] mt-1 ${isLight ? 'text-slate-500' : 'text-[#78716c]'}`}>NIST SP 800-63B recommends 12+ chars.</p>
            </div>

            <div>
              <label htmlFor="lockoutLimitInput" className={`block font-medium mb-1.5 ${isLight ? 'text-slate-700' : 'text-[#a8a29e]'}`}>
                Lockout Failed Attempt Threshold
              </label>
              <input
                id="lockoutLimitInput"
                type="number"
                min="3"
                max="10"
                value={lockoutLimit}
                onChange={(e) => setLockoutLimit(Number(e.target.value))}
                className={`w-full px-3 py-2 rounded-lg focus:outline-none focus:border-[#f95721] font-mono border ${
                  isLight
                    ? 'bg-slate-50 border-slate-300 text-slate-900'
                    : 'bg-[#181615] border-[#292422] text-[#e7e5e4]'
                }`}
              />
              <p className={`text-[11px] mt-1 ${isLight ? 'text-slate-500' : 'text-[#78716c]'}`}>Locks account for 30m after failures.</p>
            </div>

            <div className="flex flex-col justify-center pt-2">
              <label className="flex items-center gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={twoFactorEnforced}
                  onChange={(e) => setTwoFactorEnforced(e.target.checked)}
                  className={`rounded text-[#f95721] focus:ring-[#f95721] w-4 h-4 ${
                    isLight
                      ? 'border-slate-300 bg-white'
                      : 'border-[#3d3632] bg-[#181615]'
                  }`}
                />
                <span className={`text-xs font-semibold ${isLight ? 'text-slate-900' : 'text-[#e7e5e4]'}`}>Mandate 2FA (TOTP)</span>
              </label>
              <p className={`text-[11px] mt-1 ${isLight ? 'text-slate-500' : 'text-[#78716c]'}`}>
                Forces all investigators and auditors to bind an authenticator app upon next sign-in.
              </p>
            </div>
          </div>
        </div>

        {/* Action Button */}
        <div className="flex justify-end pt-2">
          <button
            type="submit"
            disabled={isSaving}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-semibold bg-[#f95721] hover:bg-[#ea580c] text-white shadow-lg shadow-[#f95721]/20 transition-all cursor-pointer disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            {isSaving ? 'Saving Changes...' : 'Save Configuration'}
          </button>
        </div>
      </form>

      {/* Danger Zone: Reset Demo Data */}
      <div className={`rounded-xl p-5 space-y-4 border ${
        isLight
          ? 'border-red-200 bg-red-50/70 text-slate-800'
          : 'border-red-500/30 bg-red-950/20'
      }`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className={`w-5 h-5 ${isLight ? 'text-red-500' : 'text-red-400'}`} />
            <div>
              <h2 className={`text-sm font-semibold ${isLight ? 'text-red-700' : 'text-red-300'}`}>Administrative Demo Environment Reset</h2>
              <p className={`text-xs mt-0.5 ${isLight ? 'text-slate-600' : 'text-[#a8a29e]'}`}>
                Purge all custom cases, newly registered examiners, mock messages, and modifications. Restores original factory seed state.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setResetDialogOpen(true)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors cursor-pointer shrink-0 ${
              isLight
                ? 'bg-red-600 hover:bg-red-700 text-white'
                : 'bg-red-900/60 hover:bg-red-800 text-red-200 border border-red-500/50'
            }`}
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset Demo Data
          </button>
        </div>
      </div>

      {/* Confirm Reset Dialog */}
      <ConfirmDialog
        isOpen={resetDialogOpen}
        title="Reset All Admin Mock Data to Factory Defaults?"
        message="This action will clear all localStorage keys prefixed with 'dcsre_admin_' and re-seed 1 administrator, 2 investigators, 1 auditor, 2 cases, 8 evidence files, 6 Sigma rules, and 8 contact messages. The page will refresh immediately."
        confirmLabel="Confirm Factory Reset"
        variant="danger"
        isLoading={isResetting}
        onConfirm={handleResetDemoData}
        onCancel={() => setResetDialogOpen(false)}
      />
    </div>
  );
};
