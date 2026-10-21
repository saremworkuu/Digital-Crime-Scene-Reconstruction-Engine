import React, { useState } from 'react';
import { useApp } from '../store';
import {
  Eye,
  EyeOff,
  AlertCircle,
  CheckCircle2,
  Sparkles
} from 'lucide-react';

export const Register: React.FC = () => {
  const { registerUser, setCurrentPage, theme } = useApp();
  const isLight = theme === 'light';

  // Form Fields
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [password, setPassword] = useState('');
  const [department, setDepartment] = useState('Digital Forensics & Incident Response (DFIR)');
  const [showPassword, setShowPassword] = useState(false);

  // Validation & Submission States
  const [emailError, setEmailError] = useState<string | null>(null);
  const [generalError, setGeneralError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Email format validation matching Picture 1 alert design
  const validateEmail = (val: string) => {
    setEmail(val);
    if (!val) {
      setEmailError(null);
      return;
    }
    const isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val);
    if (!isValid) {
      setEmailError('Enter a valid Email');
    } else {
      setEmailError(null);
    }
  };

  const handlePreloadDemo = () => {
    setFirstName('Felix');
    setLastName('Brown');
    setEmail('felixbrown27@gmail.com');
    setEmailError(null);
    setPhoneNumber('271 250 0701');
    setPassword('ForensicAuth#2026');
    setDepartment('Host Forensics & Malware Analysis');
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setGeneralError(null);
    setSuccessMsg(null);

    const fullName = `${firstName.trim()} ${lastName.trim()}`.trim();
    if (!firstName.trim() || !lastName.trim()) {
      setGeneralError('Please enter both your First Name and Last Name.');
      return;
    }

    if (!email.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setEmailError('Enter a valid Email');
      setGeneralError('A valid email address is required.');
      return;
    }

    if (password.length < 8) {
      setGeneralError('Password must be at least 8 characters long.');
      return;
    }

    setIsSubmitting(true);

    const badgeIdentifier = `DFIR-${Math.floor(1000 + Math.random() * 9000)}`;
    const result = registerUser({
      name: fullName,
      email: email.trim().toLowerCase(),
      role: 'investigator',
      department: department.trim() || 'Digital Forensics Unit',
      badgeId: badgeIdentifier,
      password: password
    });

    setIsSubmitting(false);

    if (result.success) {
      setSuccessMsg(result.message);
      setTimeout(() => {
        setCurrentPage('dashboard');
      }, 1200);
    } else {
      setGeneralError(result.message);
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
          referrerPolicy="no-referrer"
          className="w-full h-full object-cover object-center"
        />
      </div>

      {/* =================================================================== */}
      {/* RIGHT HALF OF PAGE: SIGN UP FORM (Clean, centered, no outer box)    */}
      {/* =================================================================== */}
      <div className="w-full lg:w-1/2 flex items-center justify-center px-6 sm:px-12 lg:px-14 xl:px-20 py-8 lg:py-12">
        <div className="w-full max-w-md">

          {/* Header */}
          <div className="space-y-1.5 mb-6">
            <div className="flex items-center justify-between">
              <h1
                className={`text-2xl sm:text-3xl font-extrabold tracking-tight font-sans ${isLight ? 'text-slate-900' : 'text-white'
                  }`}
              >
                Sign Up Account
              </h1>

              {/* Demo Quick Fill Button */}
              <button
                type="button"
                onClick={handlePreloadDemo}
                className={`text-xs font-mono px-2.5 py-1 rounded-lg border transition-colors flex items-center gap-1.5 cursor-pointer ${isLight
                  ? 'border-orange-200 bg-orange-50 text-orange-600 hover:bg-orange-100'
                  : 'border-[#ea580c]/40 bg-[#24130d] text-[#ff936b] hover:bg-[#34170f]'
                  }`}
                title="Prefill sample examiner details"
              >
                <Sparkles className="w-3 h-3 text-[#f95721]" />
                <span>Sample Data</span>
              </button>
            </div>
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

            {/* Row 2: Email (With Red Error State matching Picture 1) */}
            <div className="space-y-1.5">
              <label
                htmlFor="reg-email"
                className={`block text-xs font-medium font-sans ${isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                  }`}
              >
                Email
              </label>
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

            {/* Row 3: Phone Number matching Picture 1 */}
            <div className="space-y-1.5">
              <label
                htmlFor="reg-phone"
                className={`block text-xs font-medium font-sans ${isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                  }`}
              >
                Phone Number
              </label>
              <div className="flex gap-2">
                <div
                  className={`flex items-center gap-1.5 px-3 py-2.5 sm:py-3 rounded-xl border shrink-0 transition-colors ${isLight
                    ? 'bg-white border-slate-300 text-slate-700'
                    : 'bg-[#141211] border-[#2b2523] text-[#d6d3d1]'
                    }`}
                >
                  <span className="text-base leading-none">🇺🇸</span>
                  <span className="text-xs font-mono font-medium">+1</span>
                </div>
                <input
                  id="reg-phone"
                  type="tel"
                  value={phoneNumber}
                  onChange={(e) => setPhoneNumber(e.target.value)}
                  placeholder="271 250 0701"
                  className={`w-full px-3.5 py-2.5 sm:py-3 rounded-xl text-sm transition-all outline-none font-sans ${isLight
                    ? 'bg-white border border-slate-300 text-slate-900 placeholder:text-slate-400 focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]'
                    : 'bg-[#141211] border border-[#2b2523] text-white placeholder:text-[#655f5c] focus:border-[#f95721] focus:bg-[#1a1715] focus:ring-1 focus:ring-[#f95721]'
                    }`}
                />
              </div>
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
                className="text-xs font-bold text-white hover:text-[#f95721] transition-colors cursor-pointer"
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
