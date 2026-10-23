import React, { useState } from 'react';
import { useApp } from '../store';
import {
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { toast } from '../components/Toast';

export const Contact: React.FC = () => {
  const { theme } = useApp();
  const isLight = theme === 'light';

  // Form Fields
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [organization, setOrganization] = useState('');
  const [message, setMessage] = useState('');

  // States
  const [emailError, setEmailError] = useState<string | null>(null);
  const [generalError, setGeneralError] = useState<string | null>(null);
  const [ticketId, setTicketId] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

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


  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setGeneralError(null);

    if (!firstName.trim() || !lastName.trim()) {
      const err = 'Please enter both your First Name and Last Name.';
      setGeneralError(err);
      toast.error(err);
      return;
    }

    if (!email.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      const err = 'A valid official email is required.';
      setEmailError('Enter a valid Email');
      setGeneralError(err);
      toast.error(err);
      return;
    }

    setIsSubmitting(true);

    // Simulate sending message
    setTimeout(() => {
      const generatedTicket = `አሻራ-${Date.now().toString().slice(-6)}`;
      setTicketId(generatedTicket);
      setIsSubmitting(false);
      toast.success(`Message received! Reference ticket #${generatedTicket}`);
    }, 500);
  };

  return (
    <div className="min-h-[calc(100vh-4.5rem)] py-4 sm:py-6 flex items-center justify-center px-3 sm:px-6">
      {/* Outer Card Shell Container matching Picture 1 */}
      <div
        className={`w-full max-w-5xl rounded-[28px] border transition-colors shadow-2xl p-4 sm:p-5 lg:p-6 ${isLight
            ? 'bg-white border-slate-200 shadow-slate-200/50'
            : 'bg-[#090807] border-[#24201e] shadow-[0_25px_60px_-15px_rgba(0,0,0,0.8)]'
          }`}
      >
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 lg:gap-8 items-center">

          {/* =================================================================== */}
          {/* LEFT PANEL: Widened Proportional Image Box (Picture 1: Eagle art)   */}
          {/* Sized proportionally so you don't have to scroll down               */}
          {/* =================================================================== */}
          <div className="lg:col-span-6 flex flex-col justify-center">
            <div className="relative w-full h-[400px] sm:h-[460px] lg:h-[500px] rounded-2xl overflow-hidden bg-[#0d0c0c] border border-[#2b2523] flex items-center justify-center shadow-2xl">
              <img
                src="/assets/contact_art.png"
                alt="Hooded figure running along forest pathway"
                className="w-full h-full object-cover object-center transition-transform duration-700 hover:scale-105"
                loading="eager"
                decoding="sync"
              />
            </div>
          </div>

          {/* =================================================================== */}
          {/* RIGHT PANEL: Clean Modern Form (matching Picture 1 layout)          */}
          {/* =================================================================== */}
          <div className="lg:col-span-6 flex flex-col justify-center px-2 sm:px-4 lg:px-6 py-2">

            {/* Header */}
            <div className="space-y-1 mb-5">
              <h1
                className={`text-2xl sm:text-3xl font-extrabold tracking-tight font-sans ${isLight ? 'text-slate-900' : 'text-white'
                  }`}
              >
                Contact Us
              </h1>
              <p
                className={`text-xs sm:text-sm font-sans ${isLight ? 'text-slate-500' : 'text-[#a8a29e]'
                  }`}
              >
                Send us a message and our team will get back to you shortly
              </p>
            </div>

            {/* Confirmation Banner */}
            {ticketId && (
              <div className="mb-4 p-3.5 rounded-2xl bg-emerald-950/70 border border-emerald-600/70 text-emerald-200 space-y-1.5 animate-fadeIn">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span className="text-sm font-bold text-white font-sans">
                    Message Received — Ref: <span className="font-mono text-emerald-300">{ticketId}</span>
                  </span>
                </div>
                <p className="text-xs text-emerald-200/90 leading-relaxed font-sans">
                  Thank you! We will reach out to <strong className="text-white">{email}</strong> shortly.
                </p>
              </div>
            )}

            {/* General Error Notification */}
            {generalError && (
              <div className="mb-4 p-3 rounded-xl bg-red-950/70 border border-red-800/80 text-red-300 text-xs flex items-center gap-2 animate-fadeIn">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{generalError}</span>
              </div>
            )}

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-3.5">

              {/* Row 1: First Name & Last Name (Side by Side matching Picture 1) */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label
                    htmlFor="contact-firstName"
                    className={`block text-xs font-medium font-sans ${isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                      }`}
                  >
                    First Name
                  </label>
                  <input
                    id="contact-firstName"
                    type="text"
                    required
                    value={firstName}
                    onChange={(e) => setFirstName(e.target.value)}
                    placeholder="Felix"
                    className={`w-full px-3.5 py-2 sm:py-2.5 rounded-xl text-sm transition-all outline-none font-sans ${isLight
                        ? 'bg-slate-50 border border-slate-300 text-slate-900 placeholder:text-slate-400 focus:border-[#f95721] focus:bg-white focus:ring-1 focus:ring-[#f95721]'
                        : 'bg-[#141211] border border-[#2b2523] text-white placeholder:text-[#655f5c] focus:border-[#f95721] focus:bg-[#1a1715] focus:ring-1 focus:ring-[#f95721]'
                      }`}
                  />
                </div>

                <div className="space-y-1">
                  <label
                    htmlFor="contact-lastName"
                    className={`block text-xs font-medium font-sans ${isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                      }`}
                  >
                    Last Name
                  </label>
                  <input
                    id="contact-lastName"
                    type="text"
                    required
                    value={lastName}
                    onChange={(e) => setLastName(e.target.value)}
                    placeholder="Brown"
                    className={`w-full px-3.5 py-2 sm:py-2.5 rounded-xl text-sm transition-all outline-none font-sans ${isLight
                        ? 'bg-slate-50 border border-slate-300 text-slate-900 placeholder:text-slate-400 focus:border-[#f95721] focus:bg-white focus:ring-1 focus:ring-[#f95721]'
                        : 'bg-[#141211] border border-[#2b2523] text-white placeholder:text-[#655f5c] focus:border-[#f95721] focus:bg-[#1a1715] focus:ring-1 focus:ring-[#f95721]'
                      }`}
                  />
                </div>
              </div>

              {/* Row 2: Email (With Red Error State matching Picture 1) */}
              <div className="space-y-1">
                <label
                  htmlFor="contact-email"
                  className={`block text-xs font-medium font-sans ${isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                    }`}
                >
                  Email
                </label>
                <div className="relative">
                  <input
                    id="contact-email"
                    type="email"
                    required
                    value={email}
                    onChange={(e) => validateEmail(e.target.value)}
                    placeholder="felixbrown27@gmail.com"
                    className={`w-full px-3.5 py-2 sm:py-2.5 pr-10 rounded-xl text-sm transition-all outline-none font-sans ${emailError
                        ? isLight
                          ? 'bg-red-50/50 border border-red-500 text-red-600 focus:ring-1 focus:ring-red-500'
                          : 'bg-[#1f0d0a] border border-red-600/90 text-red-400 placeholder:text-red-400/50 focus:ring-1 focus:ring-red-500'
                        : isLight
                          ? 'bg-slate-50 border border-slate-300 text-slate-900 placeholder:text-slate-400 focus:border-[#f95721] focus:bg-white focus:ring-1 focus:ring-[#f95721]'
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
                  <p className="text-[11px] text-red-500 font-sans mt-0.5">
                    {emailError}
                  </p>
                )}
              </div>


              {/* Row 4: Clean, Compact Message Field */}
              <div className="space-y-1">
                <label
                  htmlFor="contact-msg"
                  className={`block text-xs font-medium font-sans ${isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                    }`}
                >
                  Message
                </label>
                <textarea
                  id="contact-msg"
                  rows={2}
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  placeholder="How can we assist you?"
                  className={`w-full px-3.5 py-2 sm:py-2.5 rounded-xl text-sm transition-all outline-none font-sans resize-none ${isLight
                      ? 'bg-slate-50 border border-slate-300 text-slate-900 placeholder:text-slate-400 focus:border-[#f95721] focus:bg-white focus:ring-1 focus:ring-[#f95721]'
                      : 'bg-[#141211] border border-[#2b2523] text-white placeholder:text-[#655f5c] focus:border-[#f95721] focus:bg-[#1a1715] focus:ring-1 focus:ring-[#f95721]'
                    }`}
                />
              </div>

              {/* Submit Button (matching Picture 1) */}
              <div className="pt-1.5">
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full py-3 px-6 rounded-xl font-bold text-sm text-white bg-[#f95721] hover:bg-[#ea580c] active:scale-[0.99] transition-all shadow-lg hover:shadow-[0_0_20px_rgba(249,87,33,0.4)] cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed text-center"
                >
                  {isSubmitting ? 'Sending Message...' : 'Send Message'}
                </button>
              </div>

            </form>
          </div>

        </div>
      </div>
    </div>
  );
};
