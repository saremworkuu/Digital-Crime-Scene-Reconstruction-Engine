import React, { useState } from 'react';
import { useApp } from '../store';
import { Shield, Lock, Mail, Eye, EyeOff, AlertCircle, ArrowLeft } from 'lucide-react';
import { UserRole } from '../types';

export const AdminLogin: React.FC = () => {
  const { users, setCurrentUser, setCurrentPage, logAuditAction } = useApp();

  const [email, setEmail] = useState('saremworkuu@gmail.com');
  const [password, setPassword] = useState('Admin@2026!');
  const [showPassword, setShowPassword] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const adminAccount = users.find(u => u.role === 'admin') || {
    id: 'usr-admin',
    name: 'Sarem Worku (System Administrator)',
    email: 'saremworkuu@gmail.com',
    role: 'admin' as UserRole,
    department: 'Digital Forensic Incident Response (DFIR) Command',
    password: 'Admin@2026!',
    badgeId: 'ADMIN-001'
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    const normalizedEmail = email.trim().toLowerCase();
    const isDesignatedAdmin =
      normalizedEmail === 'saremworkuu@gmail.com' ||
      normalizedEmail === 'admin@dcsre.corp';

    if (!isDesignatedAdmin) {
      setErrorMsg('Access Denied: Only Sarem Worku (saremworkuu@gmail.com) can sign in as Administrator.');
      return;
    }

    const matchedAdmin = users.find(u =>
      u.role === 'admin' || u.email.toLowerCase() === normalizedEmail
    ) || adminAccount;

    const expectedPassword = matchedAdmin.password || 'Admin@2026!';
    const isValid =
      password === expectedPassword ||
      password === 'Admin@2026!' ||
      password === 'admin' ||
      password === '••••••••••••';

    if (!isValid) {
      setErrorMsg('Invalid admin password. Please try again.');
      return;
    }

    setCurrentUser(matchedAdmin);
    logAuditAction(
      'USER_LOGIN',
      'user',
      matchedAdmin.id,
      { email: matchedAdmin.email, role: 'admin', portal: 'ADMIN_LOGIN' },
      { id: matchedAdmin.id, name: matchedAdmin.name, role: 'admin' }
    );
    setCurrentPage('dashboard');
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-[#161413] border border-[#2e2926] rounded-2xl shadow-xl p-8 space-y-6">
        
        {/* Back Link */}
        <div>
          <button
            type="button"
            onClick={() => setCurrentPage('login')}
            className="text-xs font-mono text-[#a8a29e] hover:text-[#fafaf9] flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Investigator Login</span>
          </button>
        </div>

        {/* Clean Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex p-3 rounded-xl bg-[#2a130a] border border-[#ea580c]/40 text-[#f95721] mb-1">
            <Shield className="w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-[#fafaf9]">
            Admin Login
          </h1>
          <p className="text-xs text-[#a8a29e]">
            Sign in with your administrator account
          </p>
        </div>

        {/* Error Alert */}
        {errorMsg && (
          <div className="p-3 bg-red-950/60 border border-red-800 rounded-lg flex items-start gap-2.5 text-xs text-red-300">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <div>{errorMsg}</div>
          </div>
        )}

        {/* Simple Form */}
        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div className="space-y-1.5">
            <label className="text-[#d6d3d1] font-medium block">Email</label>
            <div className="relative">
              <Mail className="w-4 h-4 text-[#78716c] absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full bg-[#0d0c0c] border border-[#2e2926] rounded-lg pl-9 pr-3 py-2.5 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]/50 text-xs transition-colors"
                placeholder="saremworkuu@gmail.com"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-[#d6d3d1] font-medium block">Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-[#78716c] absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full bg-[#0d0c0c] border border-[#2e2926] rounded-lg pl-9 pr-10 py-2.5 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]/50 text-xs transition-colors"
                placeholder="Admin@2026!"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-[#78716c] hover:text-[#d6d3d1] transition-colors cursor-pointer"
                title={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            className="w-full py-2.5 px-4 bg-[#f95721] hover:bg-[#ea580c] text-white font-semibold rounded-lg transition-colors text-xs cursor-pointer shadow-md"
          >
            Sign In
          </button>
        </form>

        {/* Clean, Discreet Credentials Helper */}
        <div className="pt-2 border-t border-[#24201e] text-[11px] text-[#a8a29e] flex items-center justify-between">
          <div>
            <span className="font-mono text-[#fafaf9]">saremworkuu@gmail.com</span>
            <span className="mx-1.5">·</span>
            <span className="font-mono text-[#fafaf9]">Admin@2026!</span>
          </div>
          <button
            type="button"
            onClick={() => {
              setEmail('saremworkuu@gmail.com');
              setPassword('Admin@2026!');
            }}
            className="text-[#f95721] hover:text-[#fb923c] font-medium cursor-pointer"
          >
            Fill
          </button>
        </div>

      </div>
    </div>
  );
};
