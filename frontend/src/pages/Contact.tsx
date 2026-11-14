import React, { useState } from 'react';
import { useApp } from '../store';
import {
  CheckCircle2,
  AlertCircle,
  Send,
  Loader2
} from 'lucide-react';
import { toast } from '../components/Toast';
import { messagesService } from '../services/admin/messagesService';

export const Contact: React.FC = () => {
  const { theme } = useApp();
  const isLight = theme === 'light';

  // Form Fields
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [message, setMessage] = useState('');

  // Field-specific validation errors
  const [firstNameError, setFirstNameError] = useState<string | null>(null);
  const [lastNameError, setLastNameError] = useState<string | null>(null);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [phoneError, setPhoneError] = useState<string | null>(null);
  const [messageError, setMessageError] = useState<string | null>(null);

  // General state
  const [generalError, setGeneralError] = useState<string | null>(null);
  const [ticketId, setTicketId] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Field validation helpers
  const validateFirstName = (val: string) => {
    setFirstName(val);
    if (!val.trim()) {
      setFirstNameError('First name is required');
    } else {
      setFirstNameError(null);
    }
  };

  const validateLastName = (val: string) => {
    setLastName(val);
    if (!val.trim()) {
      setLastNameError('Last name is required');
    } else {
      setLastNameError(null);
    }
  };

  const validateEmail = (val: string) => {
    setEmail(val);
    if (!val.trim()) {
      setEmailError('Official email is required');
      return;
    }
    const isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val.trim());
    if (!isValid) {
      setEmailError('Enter a valid email address');
    } else {
      setEmailError(null);
    }
  };

  const validatePhone = (val: string) => {
    setPhone(val);
    if (!val.trim()) {
      setPhoneError('Phone number is required');
      return;
    }
    // Basic phone validation (allowing digits, +, -, (, ), spaces)
    const digitsOnly = val.replace(/\D/g, '');
    if (digitsOnly.length < 7 || digitsOnly.length > 15) {
      setPhoneError('Enter a valid phone number (7-15 digits)');
    } else {
      setPhoneError(null);
    }
  };

  const validateMessage = (val: string) => {
    setMessage(val);
    if (!val.trim()) {
      setMessageError('Message cannot be empty');
    } else if (val.trim().length < 10) {
      setMessageError('Please enter at least 10 characters');
    } else {
      setMessageError(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setGeneralError(null);

    let hasError = false;

    if (!firstName.trim()) {
      setFirstNameError('First name is required');
      hasError = true;
    }
    if (!lastName.trim()) {
      setLastNameError('Last name is required');
      hasError = true;
    }

    if (!email.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      setEmailError('A valid official email is required');
      hasError = true;
    }

    const digitsOnly = phone.replace(/\D/g, '');
    if (!phone.trim() || digitsOnly.length < 7 || digitsOnly.length > 15) {
      setPhoneError('A valid phone number is required');
      hasError = true;
    }

    if (!message.trim() || message.trim().length < 10) {
      setMessageError('Message must be at least 10 characters');
      hasError = true;
    }

    if (hasError) {
      const err = 'Please resolve all required fields highlighted in red.';
      setGeneralError(err);
      toast.error(err);
      return;
    }

    setIsSubmitting(true);

    try {
      const result = await messagesService.submitPublicMessage({
        first_name: firstName.trim(),
        last_name: lastName.trim(),
        email: email.trim(),
        phone: phone.trim(),
        message: message.trim(),
        subject: 'Forensic Incident / Case Inquiry',
        category: 'Incident Escalation'
      });

      const generatedTicket = result.reference || `አሻራ-${Date.now().toString().slice(-6)}`;
      setTicketId(generatedTicket);

      // Reset form fields
      setFirstName('');
      setLastName('');
      setEmail('');
      setPhone('');
      setMessage('');

      toast.success(`Message transmitted! Reference case ticket #${generatedTicket}`);
    } catch (err: any) {
      console.error('Contact transmission failed:', err);
      const errText = err?.message || 'Transmission failed. Please check network connection.';
      setGeneralError(errText);
      toast.error(errText);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      className={`min-h-[calc(100vh-61px)] w-full flex flex-col lg:flex-row transition-colors ${
        isLight ? 'bg-slate-50' : 'bg-[#090807]'
      }`}
    >
      {/* =================================================================== */}
      {/* LEFT 50% OF SCREEN: FULL-BLEED EDGE-TO-EDGE ARTWORK IMAGE           */}
      {/* Spans full viewport height on desktop, stacks on top on mobile      */}
      {/* =================================================================== */}
      <div className="w-full lg:w-1/2 h-[200px] sm:h-[280px] md:h-[340px] lg:h-auto lg:min-h-[calc(100vh-61px)] relative overflow-hidden bg-[#070606] flex items-center justify-center shrink-0">
        <img
          src="/assets/contact_art.png"
          alt="Hooded figure running along forest pathway"
          className="w-full h-full object-cover object-center"
          loading="eager"
          decoding="sync"
        />
        {/* Subtle vignette gradient for smooth visual blend */}
        <div className="absolute inset-0 bg-gradient-to-t from-black/40 via-transparent to-black/20 pointer-events-none" />
      </div>

      {/* =================================================================== */}
      {/* RIGHT 50% OF SCREEN: CLEAN CENTERED CONTACT FORM                    */}
      {/* No outer card boxes, no enclosing borders, exactly matches Sign In  */}
      {/* =================================================================== */}
      <div className="w-full lg:w-1/2 flex items-center justify-center px-4 sm:px-8 lg:px-14 xl:px-20 py-6 sm:py-8 lg:py-12">
        <div className="w-full max-w-md">

          {/* Header */}
          <div className="space-y-1.5 mb-6">
            <h1
              className={`text-2xl sm:text-3xl font-extrabold tracking-tight font-sans ${
                isLight ? 'text-slate-900' : 'text-white'
              }`}
            >
              Contact Us
            </h1>
            <p
              className={`text-xs sm:text-sm font-sans ${
                isLight ? 'text-slate-500' : 'text-[#a8a29e]'
              }`}
            >
              Send us a message and our team will get back to you shortly
            </p>
          </div>

          {/* Success Banner */}
          {ticketId && (
            <div className="mb-5 p-4 rounded-xl bg-emerald-950/70 border border-emerald-600/70 text-emerald-300 text-xs space-y-1 animate-fadeIn">
              <div className="flex items-center gap-2 font-semibold text-emerald-200">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>Message Sent Successfully</span>
              </div>
              <p className="text-[11px] text-emerald-300/90 pl-6 font-mono">
                Case Ticket Reference: <strong className="text-white select-all">#{ticketId}</strong>
              </p>
            </div>
          )}

          {/* General Error Notification */}
          {generalError && (
            <div className="mb-5 p-3.5 rounded-xl bg-red-950/70 border border-red-800/80 text-red-300 text-xs flex items-center gap-2 animate-fadeIn">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{generalError}</span>
            </div>
          )}

          {/* Contact Form */}
          <form onSubmit={handleSubmit} className="space-y-4">

            {/* Name Fields: First Name and Last Name */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              {/* First Name */}
              <div className="space-y-1.5">
                <label
                  htmlFor="contact-first-name"
                  className={`block text-xs font-medium font-sans ${
                    isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                  }`}
                >
                  First Name <span className="text-[#f95721]">*</span>
                </label>
                <div className="relative">
                  <input
                    id="contact-first-name"
                    type="text"
                    required
                    value={firstName}
                    onChange={(e) => validateFirstName(e.target.value)}
                    placeholder=""
                    className={`w-full px-3.5 py-2.5 sm:py-3 rounded-xl text-sm transition-all outline-none font-sans ${
                      firstNameError
                        ? isLight
                          ? 'bg-red-50/50 border border-red-500 text-red-600 focus:ring-1 focus:ring-red-500'
                          : 'bg-[#1f0d0a] border border-red-600/90 text-red-400 placeholder:text-red-400/50 focus:ring-1 focus:ring-red-500'
                        : isLight
                        ? 'bg-white border border-slate-300 text-slate-900 placeholder:text-slate-400 focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]'
                        : 'bg-[#141211] border border-[#2b2523] text-white placeholder:text-[#655f5c] focus:border-[#f95721] focus:bg-[#1a1715] focus:ring-1 focus:ring-[#f95721]'
                    }`}
                  />
                </div>
                {firstNameError && (
                  <p className="text-[11px] text-red-500 font-sans mt-0.5">
                    {firstNameError}
                  </p>
                )}
              </div>

              {/* Last Name */}
              <div className="space-y-1.5">
                <label
                  htmlFor="contact-last-name"
                  className={`block text-xs font-medium font-sans ${
                    isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                  }`}
                >
                  Last Name <span className="text-[#f95721]">*</span>
                </label>
                <div className="relative">
                  <input
                    id="contact-last-name"
                    type="text"
                    required
                    value={lastName}
                    onChange={(e) => validateLastName(e.target.value)}
                    placeholder=""
                    className={`w-full px-3.5 py-2.5 sm:py-3 rounded-xl text-sm transition-all outline-none font-sans ${
                      lastNameError
                        ? isLight
                          ? 'bg-red-50/50 border border-red-500 text-red-600 focus:ring-1 focus:ring-red-500'
                          : 'bg-[#1f0d0a] border border-red-600/90 text-red-400 placeholder:text-red-400/50 focus:ring-1 focus:ring-red-500'
                        : isLight
                        ? 'bg-white border border-slate-300 text-slate-900 placeholder:text-slate-400 focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]'
                        : 'bg-[#141211] border border-[#2b2523] text-white placeholder:text-[#655f5c] focus:border-[#f95721] focus:bg-[#1a1715] focus:ring-1 focus:ring-[#f95721]'
                    }`}
                  />
                </div>
                {lastNameError && (
                  <p className="text-[11px] text-red-500 font-sans mt-0.5">
                    {lastNameError}
                  </p>
                )}
              </div>
            </div>

            {/* Email Field */}
            <div className="space-y-1.5">
              <label
                htmlFor="contact-email"
                className={`block text-xs font-medium font-sans ${
                  isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                }`}
              >
                Official Email <span className="text-[#f95721]">*</span>
              </label>
              <div className="relative">
                <input
                  id="contact-email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => validateEmail(e.target.value)}
                  placeholder=""
                  className={`w-full px-3.5 py-2.5 sm:py-3 rounded-xl text-sm transition-all outline-none font-sans ${
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
                <p className="text-[11px] text-red-500 font-sans mt-0.5">
                  {emailError}
                </p>
              )}
            </div>

            {/* Phone Number Field */}
            <div className="space-y-1.5">
              <label
                htmlFor="contact-phone"
                className={`block text-xs font-medium font-sans ${
                  isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                }`}
              >
                Phone Number <span className="text-[#f95721]">*</span>
              </label>
              <div className="relative">
                <input
                  id="contact-phone"
                  type="tel"
                  required
                  value={phone}
                  onChange={(e) => validatePhone(e.target.value)}
                  placeholder=""
                  className={`w-full px-3.5 py-2.5 sm:py-3 rounded-xl text-sm transition-all outline-none font-sans ${
                    phoneError
                      ? isLight
                        ? 'bg-red-50/50 border border-red-500 text-red-600 focus:ring-1 focus:ring-red-500'
                        : 'bg-[#1f0d0a] border border-red-600/90 text-red-400 placeholder:text-red-400/50 focus:ring-1 focus:ring-red-500'
                      : isLight
                      ? 'bg-white border border-slate-300 text-slate-900 placeholder:text-slate-400 focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]'
                      : 'bg-[#141211] border border-[#2b2523] text-white placeholder:text-[#655f5c] focus:border-[#f95721] focus:bg-[#1a1715] focus:ring-1 focus:ring-[#f95721]'
                  }`}
                />
                {phoneError && (
                  <div className="absolute right-3 top-1/2 -translate-y-1/2 text-red-500 pointer-events-none">
                    <AlertCircle className="w-4 h-4" />
                  </div>
                )}
              </div>
              {phoneError && (
                <p className="text-[11px] text-red-500 font-sans mt-0.5">
                  {phoneError}
                </p>
              )}
            </div>

            {/* Message Field */}
            <div className="space-y-1.5">
              <label
                htmlFor="contact-message"
                className={`block text-xs font-medium font-sans ${
                  isLight ? 'text-slate-700' : 'text-[#d6d3d1]'
                }`}
              >
                Message <span className="text-[#f95721]">*</span>
              </label>
              <textarea
                id="contact-message"
                rows={4}
                required
                value={message}
                onChange={(e) => validateMessage(e.target.value)}
                placeholder="Tell us what happened or how we can help..."
                className={`w-full px-3.5 py-2.5 sm:py-3 rounded-xl text-sm transition-all outline-none resize-none font-sans ${
                  messageError
                    ? isLight
                      ? 'bg-red-50/50 border border-red-500 text-red-600 focus:ring-1 focus:ring-red-500'
                      : 'bg-[#1f0d0a] border border-red-600/90 text-red-400 placeholder:text-red-400/50 focus:ring-1 focus:ring-red-500'
                    : isLight
                    ? 'bg-white border border-slate-300 text-slate-900 placeholder:text-slate-400 focus:border-[#f95721] focus:ring-1 focus:ring-[#f95721]'
                    : 'bg-[#141211] border border-[#2b2523] text-white placeholder:text-[#655f5c] focus:border-[#f95721] focus:bg-[#1a1715] focus:ring-1 focus:ring-[#f95721]'
                }`}
              />
              {messageError && (
                <p className="text-[11px] text-red-500 font-sans mt-0.5">
                  {messageError}
                </p>
              )}
            </div>

            {/* Submit Button */}
            <div className="pt-2">
              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full bg-[#f95721] hover:bg-[#ea580c] text-white font-semibold py-2.5 sm:py-3 rounded-xl transition-all shadow-[0_0_20px_rgba(249,87,33,0.3)] hover:shadow-[0_0_28px_rgba(249,87,33,0.5)] cursor-pointer flex items-center justify-center gap-2 font-sans disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Transmitting Message...</span>
                  </>
                ) : (
                  <>
                    <Send className="w-4 h-4" />
                    <span>Send Message</span>
                  </>
                )}
              </button>
            </div>

          </form>

        </div>
      </div>
    </div>
  );
};
