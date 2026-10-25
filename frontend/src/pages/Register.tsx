import React, { useState } from 'react';
import { useApp } from '../store';
import {
  Eye,
  EyeOff,
  AlertCircle,
  CheckCircle2
} from 'lucide-react';
import { validateRealEmail } from '../utils/emailValidator';
import { toast } from '../components/Toast';
import { authApi, apiClient } from '../api';

export const Register: React.FC = () => {
  const { registerUser, setCurrentPage, theme } = useApp();
  const isLight = theme === 'light';

  // Form Fields
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [department, setDepartment] = useState('Digital Forensics & Incident Response (DFIR)');
  const [showPassword, setShowPassword] = useState(false);

  // Validation & Submission States
  const [emailError, setEmailError] = useState<string | null>(null);
  const [isEmailVerified, setIsEmailVerified] = useState(false);
  const [generalError, setGeneralError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Strict real email validation
  const validateEmail = (val: string) => {
    setEmail(val);
    if (!val.trim()) {
      setEmailError(null);
      setIsEmailVerified(false);
      return;
    }
    const check = validateRealEmail(val);
    if (!check.isValid) {
      setEmailError(check.error || 'Please enter a valid, real email.');
      setIsEmailVerified(false);
    } else {
      setEmailError(null);
      setIsEmailVerified(true);
    }
  };


  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setGeneralError(null);
    setSuccessMsg(null);

    const fullName = `${firstName.trim()} ${lastName.trim()}`.trim();
    if (!firstName.trim() || !lastName.trim()) {
      const err = 'Please enter both your First Name and Last Name.';
      setGeneralError(err);
      toast.error(err);
      return;
    }

    const emailCheck = validateRealEmail(email);
    if (!emailCheck.isValid) {
      const err = emailCheck.error || 'A valid real email address is required.';
      setEmailError(err);
      setGeneralError(err);
      toast.error(err);
      setIsEmailVerified(false);
      return;
    }

    if (password.length < 8) {
      const err = 'Password must be at least 8 characters long.';
      setGeneralError(err);
      toast.error(err);
      return;
    }

    setIsSubmitting(true);

    const badgeIdentifier = `DFIR-${Math.floor(1000 + Math.random() * 9000)}`;
    try {
      const normalizedEmail = email.trim().toLowerCase();
      const response = await authApi.register({
        name: fullName,
        email: normalizedEmail,
        password,
        role: 'investigator',
        department: department.trim() || 'Digital Forensics Unit',
        badge_id: badgeIdentifier
      });
      const token = response.data?.token || response.data?.access_token;
      if (response.error || !token) {
        throw new Error(response.error || 'The backend did not create a secure session.');
      }

      // Establish the backend session before the store changes currentUser;
      // case and evidence loading starts as soon as that state changes.
      apiClient.setToken(token);
      const result = registerUser({
        name: fullName,
        email: normalizedEmail,
        role: 'investigator',
        department: department.trim() || 'Digital Forensics Unit',
        badgeId: badgeIdentifier,
        password
      });

      if (!result.success) throw new Error(result.message || 'Registration failed.');
      setSuccessMsg(result.message);
      toast.success(result.message || 'Examiner account registered successfully!');
      setTimeout(() => setCurrentPage('dashboard'), 1200);
    } catch (err: any) {
      apiClient.setToken(null);
      setGeneralError(err.message || 'Registration failed. Please check your details.');
      toast.error(err.message || 'Registration failed. Please check your details.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      className={`min-h-[calc(100vh-4rem)] w-full flex flex-col lg:flex-row transition-colors ${isLight ? 'bg-slate-50' : 'bg-[#090807]'
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
      {/* RIGHT HALF OF PAGE: SIGN UP FORM (Clean, centered, no outer box)    */}
      {/* =================================================================== */}
      <div className="w-full lg:w-1/2 flex items-center justify-center px-6 sm:px-12 lg:px-14 xl:px-20 py-8 lg:py-12">
        <div className="w-full max-w-md">

          {/* Header */}
          <div className="space-y-1.5 mb-6">
            <h1
              className={`text-2xl sm:text-3xl font-extrabold tracking-tight font-sans ${isLight ? 'text-slate-900' : 'text-white'
                }`}
            >
              Sign Up Account
            </h1>
          </div>

          {/* Success Banner */}
          {successMsg && (
            <div className="mb-5 p-3.5 rounded-xl bg-emerald-950/70 border border-emerald-600/70 text-emerald-300 text-xs flex items-center gap-2 animate-fadeIn">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{successMsg} Redirecting to investigation workspace...</span>
            </div>
          )}

          {/* General Error Notification */}
          {generalError && (
            <div className="mb-5 p-3.5 rounded-xl bg-red-950/70 border border-red-800/80 text-red-300 text-xs flex items-center gap-2 animate-fadeIn">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{generalError}</span>
            </div>
          )}

          {/* Form matching Picture 1 fields & layout */}
          <form onSubmit={handleSubmit} className="space-y-4">

            {/* Row 1: First Name & Last Name (Side by Side) */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              <div className="space-y-1.5">
                <label
                  htmlFor="reg-firstName"
                  className={`block text-xs font-medium font-sans ${isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                    }`}
                >
                  First Name
                </label>
                <input
                  id="reg-firstName"
                  type="text"
                  required
                  value={firstName}
                  onChange={(e) => setFirstName(e.target.value)}
                  placeholder="Felix"
                  className={`w-full px-3.5 py-2.5 sm:py-3 rounded-xl text-sm transition-all outline-none font-sans ${isLight
                    ? 'bg-white border border-slate-300 text-slate-900 placeholder:text-slate-400 focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]'
                    : 'bg-[#141211] border border-[#2b2523] text-white placeholder:text-[#655f5c] focus:border-[#f95721] focus:bg-[#1a1715] focus:ring-1 focus:ring-[#f95721]'
                    }`}
                />
              </div>

              <div className="space-y-1.5">
                <label
                  htmlFor="reg-lastName"
                  className={`block text-xs font-medium font-sans ${isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                    }`}
                >
                  Last Name
                </label>
                <input
                  id="reg-lastName"
                  type="text"
                  required
                  value={lastName}
                  onChange={(e) => setLastName(e.target.value)}
                  placeholder="Brown"
                  className={`w-full px-3.5 py-2.5 sm:py-3 rounded-xl text-sm transition-all outline-none font-sans ${isLight
                    ? 'bg-white border border-slate-300 text-slate-900 placeholder:text-slate-400 focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]'
                    : 'bg-[#141211] border border-[#2b2523] text-white placeholder:text-[#655f5c] focus:border-[#f95721] focus:bg-[#1a1715] focus:ring-1 focus:ring-[#f95721]'
                    }`}
                />
              </div>
            </div>

            {/* Row 2: Email (With Real Email Verification & Error State) */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label
                  htmlFor="reg-email"
                  className={`block text-xs font-medium font-sans ${isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                    }`}
                >
                  Email Address
                </label>
                {isEmailVerified && !emailError && (
                  <span className="flex items-center gap-1 text-[11px] font-sans font-medium text-emerald-400">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    Verified Real Email
                  </span>
                )}
              </div>
              <div className="relative">
                <input
                  id="reg-email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => validateEmail(e.target.value)}
                  placeholder="felixbrown27@gmail.com"
                  className={`w-full px-3.5 py-2.5 sm:py-3 pr-10 rounded-xl text-sm transition-all outline-none font-sans ${emailError
                    ? isLight
                      ? 'bg-red-50/50 border border-red-500 text-red-600 focus:ring-1 focus:ring-red-500'
                      : 'bg-[#1f0d0a] border border-red-600/90 text-red-400 placeholder:text-red-400/50 focus:ring-1 focus:ring-red-500'
                    : isEmailVerified
                      ? isLight
                        ? 'bg-emerald-50/30 border border-emerald-500/70 text-slate-900 focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500'
                        : 'bg-[#0e1d15] border border-emerald-500/50 text-white focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500'
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
                {!emailError && isEmailVerified && (
                  <div className="absolute right-3 top-1/2 -translate-y-1/2 text-emerald-400 pointer-events-none">
                    <CheckCircle2 className="w-4 h-4" />
                  </div>
                )}
              </div>

              {emailError && (
                <p className="text-[11px] text-red-500 font-sans mt-1 flex items-center gap-1.5">
                  <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                  <span>{emailError}</span>
                </p>
              )}
            </div>


            {/* Row 4: Password Field */}
            <div className="space-y-1.5">
              <label
                htmlFor="reg-pass"
                className={`block text-xs font-medium font-sans ${isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                  }`}
              >
                Password
              </label>
              <div className="relative">
                <input
                  id="reg-pass"
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Your password"
                  className={`w-full px-3.5 py-2.5 sm:py-3 pr-10 rounded-xl text-sm transition-all outline-none font-sans ${isLight
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
              <p
                className={`text-[11px] font-sans ${isLight ? 'text-slate-500' : 'text-[#78716c]'
                  }`}
              >
                Must be at least 8 characters
              </p>
            </div>

            {/* Submit Button */}
            <div className="pt-2">
              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-3.5 px-6 rounded-xl font-bold text-sm text-white bg-[#f95721] hover:bg-[#ea580c] active:scale-[0.99] transition-all shadow-lg hover:shadow-[0_0_20px_rgba(249,87,33,0.4)] cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed text-center"
              >
                {isSubmitting ? 'Creating Examiner Account...' : 'Create Account'}
              </button>
            </div>

            {/* Footer link to Log In */}
            <div className="text-center pt-2">
              <span
                className={`text-xs font-sans ${isLight ? 'text-slate-500' : 'text-[#a8a29e]'
                  }`}
              >
                Already have an account?{' '}
              </span>
              <button
                type="button"
                onClick={() => setCurrentPage('login')}
                className={`text-xs font-bold transition-colors cursor-pointer ${
                  isLight ? 'text-[#f95721] hover:text-[#ea580c] hover:underline' : 'text-[#f95721] hover:text-white'
                }`}
              >
                Log In
              </button>
            </div>

          </form>
        </div>
      </div>

    </div>
  );
};
