import React, { useState } from 'react';
import { useApp } from '../store';
import { authApi, apiClient } from '../api';
import {
  Eye,
  EyeOff,
  AlertCircle,
  CheckCircle2,
  Shield,
  ArrowRight
} from 'lucide-react';
import { toast } from '../components/Toast';

export const Login: React.FC = () => {
  const { loginUser, setCurrentPage, theme } = useApp();
  const isLight = theme === 'light';

  // Form Fields - clean inputs for security
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);

  // States
  const [emailError, setEmailError] = useState<string | null>(null);
  const [generalError, setGeneralError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const validateEmail = (val: string) => {
    setEmail(val);
    if (!val) {
      setEmailError(null);
      return;
    }
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val);
    const isUsername = /^[a-zA-Z0-9_.-]{3,}$/.test(val);
    if (!isEmail && !isUsername) {
      setEmailError('Enter a valid email or username');
    } else {
      setEmailError(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setGeneralError(null);
    setSuccessMsg(null);

    const trimmedInput = email.trim();

    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedInput);
    const isUsername = /^[a-zA-Z0-9_.-]{3,}$/.test(trimmedInput);

    if (!trimmedInput || (!isEmail && !isUsername)) {
      const err = 'Please enter a valid credential email or username.';
      setEmailError('Enter a valid email or username');
      setGeneralError(err);
      toast.error(err);
      return;
    }

    if (!password) {
      const err = 'Please enter your password.';
      setGeneralError(err);
      toast.error(err);
      return;
    }

    setIsSubmitting(true);

    try {
      // 1. Attempt backend JWT login to obtain live bearer token
      try {
        const res = await authApi.login(trimmedInput.toLowerCase(), password);
        const tokenString = res?.data?.token || (res?.data as any)?.access_token;
        if (tokenString) {
          apiClient.setToken(tokenString);
        }
      } catch (backendErr) {
        console.warn('Backend live auth fallback to local authenticated session:', backendErr);
      }

      // 2. Perform application store authentication
      const result = loginUser(trimmedInput, password);

      if (result.success) {
        setSuccessMsg(result.message);
        const welcome = result.user?.role === 'admin'
          ? `Welcome back, Administrator ${result.user.name.split(' ')[0]}!`
          : `Signed in as ${result.user?.name || 'Examiner'}!`;
        toast.success(welcome);
        setTimeout(() => {
          setCurrentPage('dashboard');
        }, 600);
      } else {
        setGeneralError(result.message);
        toast.error(result.message || 'Authentication failed. Please check credentials.');
      }
    } catch (err: any) {
      const msg = err.message || 'An unexpected authentication error occurred.';
      setGeneralError(msg);
      toast.error(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      className={`min-h-[calc(100vh-4rem)] w-full flex flex-col lg:flex-row transition-colors ${
        isLight ? 'bg-slate-50' : 'bg-[#090807]'
      }`}
    >
      {/* =================================================================== */}
      {/* LEFT HALF OF PAGE: PURE IMAGE (No boxes, no frames, full half bleed) */}
      {/* =================================================================== */}
      <div className="w-full lg:w-1/2 min-h-[340px] sm:min-h-[420px] lg:min-h-[calc(100vh-4rem)] relative overflow-hidden bg-[#070606] flex items-center justify-center">
        <img
          src="/assets/auth_art.png"
          alt="Puppet on strings artwork"
          className="w-full h-full object-cover object-center"
          loading="eager"
          decoding="sync"
        />
      </div>

      {/* =================================================================== */}
      {/* RIGHT HALF OF PAGE: LOGIN FORM (Clean, centered, no outer box)      */}
      {/* =================================================================== */}
      <div className="w-full lg:w-1/2 flex items-center justify-center px-6 sm:px-12 lg:px-14 xl:px-20 py-8 lg:py-12">
        <div className="w-full max-w-md">

          {/* Header */}
          <div className="space-y-1.5 mb-6">
            <h1
              className={`text-2xl sm:text-3xl font-extrabold tracking-tight font-sans ${
                isLight ? 'text-slate-900' : 'text-white'
              }`}
            >
              Sign In Account
            </h1>
          </div>

          {/* Success Banner */}
          {successMsg && (
            <div className="mb-5 p-3.5 rounded-xl bg-emerald-950/70 border border-emerald-600/70 text-emerald-300 text-xs flex items-center gap-2 animate-fadeIn">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* General Error Notification */}
          {generalError && (
            <div className="mb-5 p-3.5 rounded-xl bg-red-950/70 border border-red-800/80 text-red-300 text-xs flex items-center gap-2 animate-fadeIn">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{generalError}</span>
            </div>
          )}

          {/* Sign In Form */}
          <form onSubmit={handleSubmit} className="space-y-4">

            {/* Email Field */}
            <div className="space-y-1.5">
              <label
                htmlFor="login-email"
                className={`block text-xs font-medium font-sans ${
                  isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                }`}
              >
                Email or Username
              </label>
              <div className="relative">
                <input
                  id="login-email"
                  type="text"
                  required
                  value={email}
                  onChange={(e) => validateEmail(e.target.value)}
                  placeholder="saremworkuu@gmail.com or admin"
                  className={`w-full px-3.5 py-2.5 sm:py-3 pr-10 rounded-xl text-sm transition-all outline-none font-sans ${
                    emailError
                      ? isLight
                        ? 'bg-red-50/50 border border-red-500 text-red-600 focus:ring-1 focus:ring-red-500'
                        : 'bg-[#1f0d0a] border border-red-600/90 text-red-400 placeholder:text-red-400/50 focus:ring-1 focus:ring-red-500'
                      : isLight
                      ? 'bg-white border border-slate-300 text-slate-900 placeholder:text-slate-400 focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]'
                      : 'bg-[#141211] border border-[#2b2523] text-white placeholder:text-[#655f5c] focus:border-[#f95721] focus:bg-[#1a1715] focus:ring-1 focus:ring-[#f95721]'
                  }`}
                />

                {emailError && (
                  <div className="absolute right-3 top-1/2 -translate-y-1/2 text-red-500 pointer-events-none">
                    <AlertCircle className="w-4 h-4" />
                  </div>
                )}
              </div>

              {emailError && (
                <p className="text-[11px] text-red-500 font-sans mt-1">
                  {emailError}
                </p>
              )}
            </div>

            {/* Password Field */}
            <div className="space-y-1.5">
              <label
                htmlFor="login-pass"
                className={`block text-xs font-medium font-sans ${
                  isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                }`}
              >
                Password
              </label>
              <div className="relative">
                <input
                  id="login-pass"
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Your password"
                  className={`w-full px-3.5 py-2.5 sm:py-3 pr-10 rounded-xl text-sm transition-all outline-none font-sans ${
                    isLight
                      ? 'bg-white border border-slate-300 text-slate-900 placeholder:text-slate-400 focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]'
                      : 'bg-[#141211] border border-[#2b2523] text-white placeholder:text-[#655f5c] focus:border-[#f95721] focus:bg-[#1a1715] focus:ring-1 focus:ring-[#f95721]'
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#78716c] hover:text-[#d6d3d1] transition-colors p-1 cursor-pointer"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Submit Button */}
            <div className="pt-2">
              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-3.5 px-6 rounded-xl font-bold text-sm text-white bg-[#f95721] hover:bg-[#ea580c] active:scale-[0.99] transition-all shadow-lg hover:shadow-[0_0_20px_rgba(249,87,33,0.4)] cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed text-center flex items-center justify-center gap-2"
              >
                {isSubmitting ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Signing in...</span>
                  </>
                ) : (
                  <>
                    <span>Sign In to Workspace</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>

            {/* Footer link to Register */}
            <div className="text-center pt-2">
              <span
                className={`text-xs font-sans ${isLight ? 'text-slate-500' : 'text-[#a8a29e]'}`}
              >
                Don't have an enrolled account?{' '}
              </span>
              <button
                type="button"
                onClick={() => setCurrentPage('register')}
                className="text-xs font-bold text-white hover:text-[#f95721] transition-colors cursor-pointer"
              >
                Sign Up Account
              </button>
            </div>

          </form>
        </div>
      </div>

    </div>
  );
};