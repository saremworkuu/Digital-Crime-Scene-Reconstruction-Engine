import React, { useState } from 'react';
import { useApp } from '../store';
import { UserRole } from '../types';
import {
  Shield,
  Lock,
  Mail,
  User as UserIcon,
  BadgeCheck,
  Building,
  KeyRound,
  CheckCircle2,
  AlertCircle,
  Eye,
  EyeOff,
  Sparkles,
  ArrowRight,
  Fingerprint,
  FileCheck2,
  ChevronRight,
  Sun,
  Moon
} from 'lucide-react';
import { Forensic3DCore } from '../components/Forensic3DCore';

export const Register: React.FC = () => {
  const { registerUser, setCurrentPage, theme, toggleTheme } = useApp();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [role, setRole] = useState<UserRole>('investigator');
  const [department, setDepartment] = useState('Digital Forensics & Incident Response (DFIR)');
  const [badgeId, setBadgeId] = useState(`DFIR-${Math.floor(1000 + Math.random() * 9000)}`);
  const [pgpKey, setPgpKey] = useState('');
  const [agreedToProtocols, setAgreedToProtocols] = useState(true);

  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Live password strength calculation (NIST 800-63B guidelines)
  const calculateStrength = (pass: string) => {
    let score = 0;
    if (pass.length >= 8) score += 25;
    if (pass.length >= 12) score += 15;
    if (/[A-Z]/.test(pass)) score += 20;
    if (/[0-9]/.test(pass)) score += 20;
    if (/[^A-Za-z0-9]/.test(pass)) score += 20;
    return Math.min(100, score);
  };

  const strength = calculateStrength(password);
  const getStrengthLabel = (s: number) => {
    if (s <= 25) return { label: 'Weak', color: 'bg-red-500', text: 'text-red-400' };
    if (s <= 60) return { label: 'Moderate', color: 'bg-amber-500', text: 'text-amber-400' };
    if (s <= 85) return { label: 'Strong', color: 'bg-[#ea580c]', text: 'text-[#fb923c]' };
    return { label: 'Cryptographically Hardened', color: 'bg-[#f95721]', text: 'text-[#f95721]' };
  };

  const strengthInfo = getStrengthLabel(strength);

  const generateBadgeId = () => {
    const prefixes = ['DFIR', 'CIRT', 'CCU', 'SOC', 'INV'];
    const p = prefixes[Math.floor(Math.random() * prefixes.length)];
    const num = Math.floor(1000 + Math.random() * 9000);
    setBadgeId(`${p}-${num}`);
  };

  const handlePreloadDemo = () => {
    setName('Special Agent Alex Vance');
    setEmail(`alex.vance@dcsre.corp`);
    setPassword('ForensicSecure#2026!');
    setConfirmPassword('ForensicSecure#2026!');
    setRole('investigator');
    setDepartment('Cyber Incident Response Team (CIRT)');
    generateBadgeId();
    setPgpKey('4A29 B901 88EC DF91 2026');
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);

    if (!name.trim()) {
      setErrorMsg('Full examiner name is required.');
      return;
    }

    if (!email.trim() || !email.includes('@')) {
      setErrorMsg('A valid official email address is required.');
      return;
    }

    if (password.length < 8) {
      setErrorMsg('Password must be at least 8 characters in length per NIST 800-63B.');
      return;
    }

    if (password !== confirmPassword) {
      setErrorMsg('Master authentication passwords do not match.');
      return;
    }

    if (!agreedToProtocols) {
      setErrorMsg('You must attest to the evidentiary chain-of-custody protocols.');
      return;
    }

    setIsSubmitting(true);

    try {
      const result = registerUser({
        name,
        email,
        role,
        department,
        badgeId,
        password,
        pgpKey
      });

      if (result.success) {
        setSuccessMsg(result.message);
      } else {
        setErrorMsg(result.message);
        setIsSubmitting(false);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Registration failed unexpectedly.');
      setIsSubmitting(false);
    }
  };

  return (
    <div className="py-6 max-w-4xl mx-auto px-4">
      {/* Back button & Quick Action */}
      <div className="flex items-center justify-between mb-6">
        <button
          type="button"
          onClick={() => setCurrentPage('login')}
          className="text-xs text-[#a8a29e] hover:text-[#f95721] flex items-center gap-1.5 transition-colors font-mono cursor-pointer"
        >
          <ChevronRight className="w-3.5 h-3.5 rotate-180 text-[#f95721]" />
          <span>Back to Terminal Login</span>
        </button>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={toggleTheme}
            className="text-xs px-2.5 py-1.5 rounded-lg bg-[#191716] text-[#e7e5e4] border border-[#2e2926] hover:bg-[#221f1d] transition-colors flex items-center gap-1.5 font-mono cursor-pointer"
            title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          >
            {theme === 'dark' ? (
              <>
                <Sun className="w-3.5 h-3.5 text-amber-400" />
                <span className="hidden sm:inline text-[11px]">Light Mode</span>
              </>
            ) : (
              <>
                <Moon className="w-3.5 h-3.5 text-indigo-400" />
                <span className="hidden sm:inline text-[11px]">Dark Mode</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={handlePreloadDemo}
            className="text-xs px-3 py-1.5 rounded-lg bg-[#24130d] text-[#f95721] border border-[#ea580c]/40 hover:bg-[#341a12] transition-colors flex items-center gap-1.5 font-mono cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5 text-[#fb923c]" />
            <span>Pre-fill Sample Profile</span>
          </button>
        </div>
      </div>

      <div className="bg-[#161413]/95 border border-[#2b2523] rounded-2xl shadow-2xl backdrop-blur-xl overflow-hidden">
        {/* Header Banner with Subtle Interactive 3D Cryptographic Core */}
        <div className="bg-[#12100f]/90 border-b border-[#282321] px-6 sm:px-8 py-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="flex items-center justify-center shrink-0">
                <Forensic3DCore size={46} interactive={true} />
              </div>
              <div>
                <h1 className="text-xl font-bold text-[#fafaf9] flex items-center gap-2">
                  <span>Examiner Clearance Registration</span>
                  <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-[#2a140d] text-[#f95721] border border-[#ea580c]/40 font-semibold">
                    NIST SP 800-86
                  </span>
                </h1>
                <p className="text-xs text-[#a8a29e] mt-0.5">
                  Enroll credentialed forensic personnel into DCSRE role-based access & chain of custody index.
                </p>
              </div>
            </div>
            
            <div className="text-right sm:block hidden font-mono text-[11px] text-[#78716c]">
              <div>PROTOCOL: ISO/IEC 27037</div>
              <div className="text-[#f95721] font-semibold">ACCESS LEVEL: ENROLLEE</div>
            </div>
          </div>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 sm:p-8 space-y-6">
          {errorMsg && (
            <div className="p-3.5 bg-red-950/60 border border-red-800/80 rounded-lg flex items-start gap-2.5 text-red-300 text-xs">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div>
                <div className="font-semibold text-red-200">Registration Check Failed</div>
                <div>{errorMsg}</div>
              </div>
            </div>
          )}

          {successMsg && (
            <div className="p-3.5 bg-emerald-950/60 border border-emerald-800/80 rounded-lg flex items-start gap-2.5 text-emerald-300 text-xs">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <div className="font-semibold text-emerald-200">Registration Accepted</div>
                <div>{successMsg} Redirecting to workspace...</div>
              </div>
            </div>
          )}

          {/* Section 1: Identity & Credentials */}
          <div className="space-y-4">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-[#a8a29e] font-mono flex items-center gap-2 border-b border-[#282321] pb-2">
              <UserIcon className="w-3.5 h-3.5 text-[#f95721]" />
              <span>1. Examiner Identity & Access Credentials</span>
            </h2>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5 text-xs">
                <label className="text-[#d6d3d1] font-medium">Full Legal / Examiner Name *</label>
                <div className="relative">
                  <UserIcon className="w-4 h-4 text-[#78716c] absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. Inspector Marcus Vance"
                    className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg pl-9 pr-3 py-2 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]/50 text-xs transition-colors"
                  />
                </div>
              </div>

              <div className="space-y-1.5 text-xs">
                <label className="text-[#d6d3d1] font-medium">Email *</label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-[#78716c] absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="marcus.vance@dcsre.corp"
                    className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg pl-9 pr-3 py-2 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]/50 font-mono text-xs transition-colors"
                  />
                </div>
              </div>

              <div className="space-y-1.5 text-xs">
                <label className="text-[#d6d3d1] font-medium">Master Password / Security Key *</label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-[#78716c] absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg pl-9 pr-10 py-2 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]/50 font-mono text-xs transition-colors"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-[#78716c] hover:text-[#d6d3d1] transition-colors"
                    title={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {/* Strength meter */}
                {password.length > 0 && (
                  <div className="space-y-1 pt-1">
                    <div className="h-1.5 w-full bg-[#1c1917] rounded-full overflow-hidden border border-[#2b2523]">
                      <div
                        className={`h-full transition-all duration-300 ${strengthInfo.color}`}
                        style={{ width: `${strength}%` }}
                      />
                    </div>
                    <div className="flex justify-between items-center text-[10px] font-mono text-[#a8a29e]">
                      <span>NIST Complexity: <span className={strengthInfo.text}>{strengthInfo.label}</span></span>
                      <span>{strength}%</span>
                    </div>
                  </div>
                )}
              </div>

              <div className="space-y-1.5 text-xs">
                <label className="text-[#d6d3d1] font-medium">Confirm Master Password *</label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-[#78716c] absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg pl-9 pr-3 py-2 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]/50 font-mono text-xs transition-colors"
                  />
                </div>
                {confirmPassword && password !== confirmPassword && (
                  <span className="text-[10px] text-red-400 font-mono block">
                    Passwords do not match
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Section 2: Clearance Level & Unit */}
          <div className="space-y-4">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-[#a8a29e] font-mono flex items-center gap-2 border-b border-[#282321] pb-2">
              <BadgeCheck className="w-3.5 h-3.5 text-[#f95721]" />
              <span>2. Role & Department</span>
            </h2>

            {/* Role Card */}
            <div className="p-3.5 rounded-xl border bg-[#24130d]/80 border-[#ea580c]/50 text-[#fafaf9] flex items-center justify-between">
              <span className="text-xs font-semibold text-[#f95721] flex items-center gap-2">
                <KeyRound className="w-4 h-4" />
                <span className="text-sm font-bold">Forensic Investigator</span>
              </span>
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[#f95721] text-white font-bold">
                Clearance
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
              <div className="space-y-1.5 text-xs">
                <label className="text-[#d6d3d1] font-medium">Department / Forensic Unit</label>
                <div className="relative">
                  <Building className="w-4 h-4 text-[#78716c] absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    required
                    value={department}
                    onChange={(e) => setDepartment(e.target.value)}
                    placeholder="Incident Response CIRT"
                    className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg pl-9 pr-3 py-2 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]/50 text-xs transition-colors"
                  />
                </div>
              </div>

              <div className="space-y-1.5 text-xs">
                <div className="flex justify-between items-center">
                  <label className="text-[#d6d3d1] font-medium">Badge ID</label>
                  <button
                    type="button"
                    onClick={generateBadgeId}
                    className="text-[10px] text-[#f95721] hover:text-[#fb923c] font-mono cursor-pointer"
                  >
                    Regenerate
                  </button>
                </div>
                <div className="relative">
                  <BadgeCheck className="w-4 h-4 text-[#78716c] absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    required
                    value={badgeId}
                    onChange={(e) => setBadgeId(e.target.value)}
                    placeholder="DFIR-8841"
                    className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg pl-9 pr-3 py-2 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]/50 font-mono text-xs uppercase transition-colors"
                  />
                </div>
              </div>
            </div>

            <div className="space-y-1.5 text-xs">
              <label className="text-[#d6d3d1] font-medium block">
                PGP Fingerprint (Optional)
              </label>
              <div className="relative">
                <Fingerprint className="w-4 h-4 text-[#78716c] absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={pgpKey}
                  onChange={(e) => setPgpKey(e.target.value)}
                  placeholder="7A14 9F20 C183 E099 2026"
                  className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg pl-9 pr-3 py-2 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]/50 font-mono text-xs uppercase transition-colors"
                />
              </div>
            </div>
          </div>

          {/* Section 3: Agreement */}
          <div className="p-3 bg-[#0d0c0c] border border-[#2b2523] rounded-xl">
            <label className="flex items-center gap-2.5 text-xs text-[#d6d3d1] cursor-pointer select-none">
              <input
                type="checkbox"
                checked={agreedToProtocols}
                onChange={(e) => setAgreedToProtocols(e.target.checked)}
                className="accent-[#f95721] rounded cursor-pointer"
              />
              <span>I agree to forensic integrity protocols and logging standards.</span>
            </label>
          </div>

          {/* Action Row */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-4 border-t border-[#282321]">
            <div className="text-xs text-[#a8a29e]">
              Already credentialed?{' '}
              <button
                type="button"
                onClick={() => setCurrentPage('login')}
                className="text-[#f95721] hover:text-[#fb923c] font-semibold cursor-pointer"
              >
                Sign In
              </button>
            </div>

            <div className="flex items-center gap-3 w-full sm:w-auto">
              <button
                type="button"
                onClick={() => setCurrentPage('login')}
                className="w-full sm:w-auto px-4 py-2.5 rounded-lg border border-[#2b2523] hover:bg-[#1f1b19] text-[#d6d3d1] text-xs font-semibold transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full sm:w-auto px-6 py-2.5 rounded-lg bg-[#f95721] hover:bg-[#ea580c] disabled:opacity-50 text-white font-semibold text-xs flex items-center justify-center gap-2 shadow-md transition-all cursor-pointer"
              >
                <span>Register</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};
