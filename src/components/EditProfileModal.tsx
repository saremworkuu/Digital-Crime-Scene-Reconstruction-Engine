import React, { useState, useEffect } from 'react';
import { useApp } from '../store';
import {
  X,
  User as UserIcon,
  Mail,
  Building2,
  BadgeCheck,
  Lock,
  KeyRound,
  Shield,
  ShieldCheck,
  Check,
  AlertCircle,
  Eye,
  EyeOff,
  Save,
  Loader2,
  Sparkles
} from 'lucide-react';
import { toast } from './Toast';

interface EditProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
}

type TabType = 'details' | 'security';

export const EditProfileModal: React.FC<EditProfileModalProps> = ({ isOpen, onClose }) => {
  const { currentUser, updateCurrentUserProfile, theme } = useApp();
  const isLight = theme === 'light';

  const [activeTab, setActiveTab] = useState<TabType>('details');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Profile details state
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [department, setDepartment] = useState('');
  const [badgeId, setBadgeId] = useState('');

  // Security / Password state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);

  // Populate when opened or currentUser changes
  useEffect(() => {
    if (isOpen && currentUser) {
      setName(currentUser.name || '');
      setEmail(currentUser.email || '');
      setDepartment(currentUser.department || '');
      setBadgeId(currentUser.badgeId || currentUser.badge_id || '');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setErrorMsg(null);
      setSuccessMsg(null);
      setActiveTab('details');
    }
  }, [isOpen, currentUser]);

  if (!isOpen || !currentUser) return null;

  const isAdmin = currentUser.role === 'admin';

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);

    if (!name.trim()) {
      setErrorMsg('Full name cannot be blank.');
      return;
    }

    if (!email.trim() || !email.includes('@')) {
      setErrorMsg('Please enter a valid official email address.');
      return;
    }

    if (activeTab === 'security') {
      if (!currentPassword) {
        setErrorMsg('Please enter your current password to authorize security modifications.');
        return;
      }
      if (newPassword.length < 8) {
        setErrorMsg('New password must be at least 8 characters long.');
        return;
      }
      if (newPassword !== confirmPassword) {
        setErrorMsg('New password and confirmation do not match.');
        return;
      }
    }

    setIsSubmitting(true);
    try {
      const payload: {
        name: string;
        email: string;
        department: string;
        badgeId: string;
        badge_id: string;
        currentPassword?: string;
        newPassword?: string;
      } = {
        name: name.trim(),
        email: email.trim().toLowerCase(),
        department: department.trim(),
        badgeId: badgeId.trim(),
        badge_id: badgeId.trim()
      };

      if (activeTab === 'security' && newPassword) {
        payload.currentPassword = currentPassword;
        payload.newPassword = newPassword;
      }

      const res = await updateCurrentUserProfile(payload);
      if (res.success) {
        setSuccessMsg(res.message || 'Profile updated successfully.');
        if (activeTab === 'security') {
          setCurrentPassword('');
          setNewPassword('');
          setConfirmPassword('');
        }
        setTimeout(() => {
          onClose();
        }, 1200);
      } else {
        setErrorMsg(res.message || 'Failed to update profile. Please check your credentials.');
      }
    } catch (err: any) {
      setErrorMsg(err?.message || 'An unexpected error occurred while saving profile changes.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/75 backdrop-blur-md animate-fadeIn">
      <div
        className={`w-full max-w-xl max-h-[90vh] flex flex-col rounded-2xl border shadow-[0_25px_80px_rgba(0,0,0,0.85)] overflow-hidden transition-all duration-200 ${
          isLight
            ? 'bg-white border-slate-200 text-slate-800'
            : 'bg-[#141211] border-[#2e2926] text-[#e7e5e4]'
        }`}
      >
        {/* Header with Operator Badge */}
        <div
          className={`px-6 py-4.5 border-b flex items-center justify-between ${
            isLight
              ? 'bg-slate-50 border-slate-200'
              : 'bg-[#1a1716] border-[#2e2926]'
          }`}
        >
          <div className="flex items-center gap-3">
            <div
              className={`w-10 h-10 rounded-xl flex items-center justify-center font-bold text-base shadow-sm border ${
                isAdmin
                  ? isLight
                    ? 'bg-red-50 text-red-600 border-red-200'
                    : 'bg-[#3b1219] text-[#fca5a5] border-[#ef4444]/40'
                  : isLight
                  ? 'bg-orange-50 text-[#ea580c] border-orange-200'
                  : 'bg-[#24130d] text-[#f95721] border-[#ea580c]/50'
              }`}
            >
              {name.charAt(0) || 'U'}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3
                  className={`text-base font-bold tracking-tight ${
                    isLight ? 'text-slate-900' : 'text-[#fafaf9]'
                  }`}
                >
                  Edit Forensic Profile
                </h3>
                <span
                  className={`text-[10px] font-mono uppercase font-bold px-2 py-0.5 rounded border ${
                    isAdmin
                      ? isLight
                        ? 'bg-red-100 text-red-800 border-red-200'
                        : 'bg-[#3b1219] text-[#fca5a5] border-[#ef4444]/50'
                      : isLight
                      ? 'bg-orange-100 text-orange-800 border-orange-200'
                      : 'bg-[#24130d] text-[#f95721] border-[#ea580c]/40'
                  }`}
                >
                  {isAdmin ? 'System Administrator' : 'Forensic Investigator'}
                </span>
              </div>
              <p
                className={`text-xs ${
                  isLight ? 'text-slate-500' : 'text-[#a8a29e]'
                }`}
              >
                Update examiner identity, department, and authentication credentials
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className={`p-1.5 rounded-lg transition-colors cursor-pointer ${
              isLight
                ? 'text-slate-400 hover:text-slate-700 hover:bg-slate-200'
                : 'text-[#78716c] hover:text-[#fafaf9] hover:bg-[#25211e]'
            }`}
            aria-label="Close Profile Dialog"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Selection */}
        <div
          className={`flex border-b px-6 pt-2 gap-4 ${
            isLight ? 'border-slate-200 bg-slate-50/50' : 'border-[#2e2926] bg-[#121110]'
          }`}
        >
          <button
            type="button"
            onClick={() => {
              setActiveTab('details');
              setErrorMsg(null);
            }}
            className={`flex items-center gap-2 py-2.5 text-xs font-semibold border-b-2 transition-colors cursor-pointer ${
              activeTab === 'details'
                ? isLight
                  ? 'border-[#ea580c] text-[#ea580c]'
                  : 'border-[#f95721] text-[#f95721]'
                : isLight
                ? 'border-transparent text-slate-500 hover:text-slate-900'
                : 'border-transparent text-[#78716c] hover:text-[#e7e5e4]'
            }`}
          >
            <UserIcon className="w-3.5 h-3.5" />
            <span>Examiner Details</span>
          </button>

          <button
            type="button"
            onClick={() => {
              setActiveTab('security');
              setErrorMsg(null);
            }}
            className={`flex items-center gap-2 py-2.5 text-xs font-semibold border-b-2 transition-colors cursor-pointer ${
              activeTab === 'security'
                ? isLight
                  ? 'border-[#ea580c] text-[#ea580c]'
                  : 'border-[#f95721] text-[#f95721]'
                : isLight
                ? 'border-transparent text-slate-500 hover:text-slate-900'
                : 'border-transparent text-[#78716c] hover:text-[#e7e5e4]'
            }`}
          >
            <KeyRound className="w-3.5 h-3.5" />
            <span>Security & Password</span>
          </button>
        </div>

        {/* Feedback Alerts */}
        {errorMsg && (
          <div className="mx-6 mt-4 p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-500 text-xs flex items-center gap-2.5">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {successMsg && (
          <div className="mx-6 mt-4 p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-500 text-xs flex items-center gap-2.5">
            <Check className="w-4 h-4 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* Form Body */}
        <form onSubmit={handleSaveProfile} className="p-4 sm:p-6 space-y-4 flex-1 overflow-y-auto">
          {activeTab === 'details' ? (
            <div className="space-y-4 text-xs">
              {/* Full Name */}
              <div className="space-y-1.5">
                <label
                  className={`flex items-center gap-1.5 font-semibold text-xs ${
                    isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                  }`}
                >
                  <UserIcon className="w-3.5 h-3.5 text-[#f95721]" />
                  <span>Full Legal Name / Call-Sign</span>
                </label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Sarem Worku or Chen Wei"
                  className={`w-full rounded-xl px-3.5 py-2.5 border text-xs focus:outline-none transition-colors ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900 focus:border-[#ea580c] focus:bg-white'
                      : 'bg-[#181615] border-[#2e2926] text-[#fafaf9] placeholder-[#78716c] focus:border-[#f95721] focus:bg-[#1e1b19]'
                  }`}
                />
              </div>

              {/* Email */}
              <div className="space-y-1.5">
                <label
                  className={`flex items-center gap-1.5 font-semibold text-xs ${
                    isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                  }`}
                >
                  <Mail className="w-3.5 h-3.5 text-[#f95721]" />
                  <span>Official Examiner Email</span>
                </label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="e.g. examiner@ashara.gov"
                  className={`w-full rounded-xl px-3.5 py-2.5 border text-xs font-mono focus:outline-none transition-colors ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900 focus:border-[#ea580c] focus:bg-white'
                      : 'bg-[#181615] border-[#2e2926] text-[#fafaf9] placeholder-[#78716c] focus:border-[#f95721] focus:bg-[#1e1b19]'
                  }`}
                />
              </div>

              {/* Department & Badge ID Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                <div className="space-y-1.5">
                  <label
                    className={`flex items-center gap-1.5 font-semibold text-xs ${
                      isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                    }`}
                  >
                    <Building2 className="w-3.5 h-3.5 text-[#f95721]" />
                    <span>Department / Forensic Unit</span>
                  </label>
                  <input
                    type="text"
                    value={department}
                    onChange={(e) => setDepartment(e.target.value)}
                    placeholder="e.g. Cyber Attribution Command"
                    className={`w-full rounded-xl px-3.5 py-2.5 border text-xs focus:outline-none transition-colors ${
                      isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-900 focus:border-[#ea580c] focus:bg-white'
                        : 'bg-[#181615] border-[#2e2926] text-[#fafaf9] placeholder-[#78716c] focus:border-[#f95721] focus:bg-[#1e1b19]'
                    }`}
                  />
                </div>

                <div className="space-y-1.5">
                  <label
                    className={`flex items-center gap-1.5 font-semibold text-xs ${
                      isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                    }`}
                  >
                    <BadgeCheck className="w-3.5 h-3.5 text-[#f95721]" />
                    <span>Forensic Badge / Serial ID</span>
                  </label>
                  <input
                    type="text"
                    value={badgeId}
                    onChange={(e) => setBadgeId(e.target.value)}
                    placeholder="e.g. DFIR-4821 or SEC-001"
                    className={`w-full rounded-xl px-3.5 py-2.5 border text-xs font-mono focus:outline-none transition-colors ${
                      isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-900 focus:border-[#ea580c] focus:bg-white'
                        : 'bg-[#181615] border-[#2e2926] text-[#fafaf9] placeholder-[#78716c] focus:border-[#f95721] focus:bg-[#1e1b19]'
                    }`}
                  />
                </div>
              </div>

              {/* Role Read-Only Assurance Notice */}
              <div
                className={`p-3 rounded-xl border flex items-center justify-between text-[11px] ${
                  isLight
                    ? 'bg-slate-100 border-slate-200 text-slate-600'
                    : 'bg-[#191716] border-[#262220] text-[#a8a29e]'
                }`}
              >
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0" />
                  <span>
                    Cryptographic Role: <strong>{isAdmin ? 'System Administrator' : 'Forensic Investigator'}</strong>
                  </span>
                </div>
                <span className="text-[10px] font-mono text-[#78716c]">Role Locked (RBAC)</span>
              </div>
            </div>
          ) : (
            <div className="space-y-4 text-xs">
              <div
                className={`p-3 rounded-xl border text-xs flex items-start gap-2.5 ${
                  isLight
                    ? 'bg-orange-50 border-orange-200 text-orange-900'
                    : 'bg-[#24130d]/50 border-[#ea580c]/30 text-[#fdba74]'
                }`}
              >
                <Shield className="w-4 h-4 text-[#f95721] shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <span className="font-semibold">NIST Authenticator Standards</span>
                  <p className="text-[11px] opacity-90">
                    Use at least 8 characters. Passwords are salted and hashed with SHA-256 / bcrypt and verified on every forensic chain of custody event.
                  </p>
                </div>
              </div>

              {/* Current Password */}
              <div className="space-y-1.5">
                <label
                  className={`flex items-center gap-1.5 font-semibold text-xs ${
                    isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                  }`}
                >
                  <Lock className="w-3.5 h-3.5 text-[#f95721]" />
                  <span>Current Master Password</span>
                </label>
                <div className="relative">
                  <input
                    type={showCurrentPassword ? 'text' : 'password'}
                    required={activeTab === 'security'}
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    placeholder="Enter current password to authorize changes"
                    className={`w-full rounded-xl pl-3.5 pr-10 py-2.5 border text-xs font-mono focus:outline-none transition-colors ${
                      isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-900 focus:border-[#ea580c] focus:bg-white'
                        : 'bg-[#181615] border-[#2e2926] text-[#fafaf9] placeholder-[#78716c] focus:border-[#f95721] focus:bg-[#1e1b19]'
                    }`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-[#78716c] hover:text-[#fafaf9]"
                  >
                    {showCurrentPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* New Password */}
              <div className="space-y-1.5">
                <label
                  className={`flex items-center gap-1.5 font-semibold text-xs ${
                    isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                  }`}
                >
                  <KeyRound className="w-3.5 h-3.5 text-[#f95721]" />
                  <span>New Passphrase (Min. 8 chars)</span>
                </label>
                <div className="relative">
                  <input
                    type={showNewPassword ? 'text' : 'password'}
                    required={activeTab === 'security'}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Enter robust new passphrase"
                    className={`w-full rounded-xl pl-3.5 pr-10 py-2.5 border text-xs font-mono focus:outline-none transition-colors ${
                      isLight
                        ? 'bg-slate-50 border-slate-300 text-slate-900 focus:border-[#ea580c] focus:bg-white'
                        : 'bg-[#181615] border-[#2e2926] text-[#fafaf9] placeholder-[#78716c] focus:border-[#f95721] focus:bg-[#1e1b19]'
                    }`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-[#78716c] hover:text-[#fafaf9]"
                  >
                    {showNewPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Confirm New Password */}
              <div className="space-y-1.5">
                <label
                  className={`flex items-center gap-1.5 font-semibold text-xs ${
                    isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                  }`}
                >
                  <Check className="w-3.5 h-3.5 text-[#f95721]" />
                  <span>Confirm New Passphrase</span>
                </label>
                <input
                  type={showNewPassword ? 'text' : 'password'}
                  required={activeTab === 'security'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Re-type new passphrase exactly"
                  className={`w-full rounded-xl px-3.5 py-2.5 border text-xs font-mono focus:outline-none transition-colors ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900 focus:border-[#ea580c] focus:bg-white'
                      : 'bg-[#181615] border-[#2e2926] text-[#fafaf9] placeholder-[#78716c] focus:border-[#f95721] focus:bg-[#1e1b19]'
                  }`}
                />
              </div>
            </div>
          )}

          {/* Action Buttons */}
          <div
            className={`pt-4 border-t flex items-center justify-end gap-3 ${
              isLight ? 'border-slate-200' : 'border-[#2e2926]'
            }`}
          >
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className={`px-4 py-2 rounded-xl text-xs font-medium transition-colors cursor-pointer ${
                isLight
                  ? 'bg-slate-100 hover:bg-slate-200 text-slate-700'
                  : 'bg-[#1a1716] hover:bg-[#25211e] text-[#a8a29e]'
              }`}
            >
              Cancel
            </button>

            <button
              type="submit"
              disabled={isSubmitting}
              className="px-5 py-2 rounded-xl bg-gradient-to-r from-[#ea580c] to-[#f95721] hover:from-[#d94806] hover:to-[#ea580c] text-white text-xs font-bold shadow-lg shadow-[#ea580c]/20 transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Saving Changes...</span>
                </>
              ) : (
                <>
                  <Save className="w-4 h-4" />
                  <span>Save Profile</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
