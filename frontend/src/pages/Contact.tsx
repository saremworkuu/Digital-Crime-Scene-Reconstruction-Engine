import React, { useState } from 'react';
import { useApp } from '../store';
import {
  Mail,
  Phone,
  MapPin,
  Send,
  CheckCircle2,
  Copy,
  Check,
  Lock,
  Building,
  User
} from 'lucide-react';
import { Forensic3DCore } from '../components/Forensic3DCore';

export const Contact: React.FC = () => {
  const { setCurrentPage, theme } = useApp();
  const isLight = theme === 'light';

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [organization, setOrganization] = useState('');
  const [inquiryType, setInquiryType] = useState('emergency_breach');
  const [priority, setPriority] = useState<'critical' | 'high' | 'normal'>('critical');
  const [message, setMessage] = useState('');
  const [ticketId, setTicketId] = useState<string | null>(null);
  const [copiedFingerprint, setCopiedFingerprint] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const pgpFingerprint = 'E4B2 91A0 39F8 D82C 7E10 B149 2C87 F320 9D1A 4E02';

  const handleCopyFingerprint = () => {
    navigator.clipboard.writeText(pgpFingerprint);
    setCopiedFingerprint(true);
    setTimeout(() => setCopiedFingerprint(false), 2000);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);

    // Simulate cryptographic ticket issuance
    setTimeout(() => {
      const generatedTicket = `DCSRE-${Date.now().toString().slice(-6)}`;
      setTicketId(generatedTicket);
      setIsSubmitting(false);
    }, 700);
  };

  return (
    <div className="space-y-10 pb-16 max-w-5xl mx-auto px-2 sm:px-4">
      {/* Header Banner */}
      <div className={`relative rounded-3xl overflow-hidden border ${
        isLight
          ? 'border-slate-200 bg-gradient-to-b from-white via-slate-50 to-slate-100 shadow-xl'
          : 'border-[#2b2523] bg-gradient-to-b from-[#181514] via-[#121110] to-[#0d0c0c] shadow-2xl'
      } p-6 sm:p-10 transition-colors`}>
        <div className="absolute top-0 right-0 w-80 h-80 bg-[#f95721]/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-3 max-w-2xl">
            <h1 className="text-2xl sm:text-4xl font-black tracking-tight text-[#fafaf9]">
              Contact Forensic Triage
            </h1>

            <p className="text-xs sm:text-sm text-[#a8a29e] leading-relaxed">
              Direct dispatch for active incident response, evidence handoff, and forensic support.
            </p>
          </div>

          <div className="shrink-0 flex items-center justify-center">
            <div className={`p-3 rounded-2xl ${isLight ? 'bg-white border-slate-200' : 'bg-[#161413] border-[#2c2624]'} border shadow-lg`}>
              <Forensic3DCore size={72} interactive={true} />
            </div>
          </div>
        </div>
      </div>

      {/* Ticket Success Confirmation Modal / Banner */}
      {ticketId && (
        <div className="p-6 rounded-2xl bg-[#1a1411] border-2 border-[#f95721] shadow-2xl space-y-4 animate-fadeIn">
          <div className="flex items-start gap-4">
            <div className="w-10 h-10 rounded-xl bg-[#2b130a] border border-[#ea580c]/60 flex items-center justify-center text-[#f95721] shrink-0">
              <CheckCircle2 className="w-6 h-6" />
            </div>
            <div className="space-y-1 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-800 text-emerald-300 font-bold">
                  Dispatch Recorded
                </span>
                <span className="text-xs font-mono text-[#a8a29e]">Ref: {ticketId}</span>
              </div>
              <h3 className="text-base font-bold text-[#fafaf9]">
                Forensic Incident Triage Request Acknowledged
              </h3>
              <p className="text-xs text-[#d6d3d1] leading-relaxed">
                Your dispatch ticket <strong className="text-[#f95721] font-mono">{ticketId}</strong> has been logged to the DCSRE on-call duty queue. Our standby digital forensics examiner will contact <strong className="text-[#fafaf9]">{email}</strong> within {priority === 'critical' ? '15 minutes' : '2 hours'}.
              </p>
            </div>
          </div>

          <div className="flex items-center justify-end gap-3 pt-2 border-t border-[#2d221e]">
            <button
              type="button"
              onClick={() => {
                setTicketId(null);
                setMessage('');
              }}
              className="px-4 py-2 bg-[#27130b] hover:bg-[#38180e] border border-[#ea580c]/50 text-[#ff8d60] rounded-xl text-xs font-semibold transition-colors cursor-pointer"
            >
              Submit Another Inquiry
            </button>
            <button
              type="button"
              onClick={() => setCurrentPage('home')}
              className="px-4 py-2 bg-[#f95721] hover:bg-[#ea580c] text-white rounded-xl text-xs font-semibold transition-colors cursor-pointer"
            >
              Return to Home
            </button>
          </div>
        </div>
      )}

      {/* Main Grid: Contact Cards & Form */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left Column: Direct Channels & Information (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          {/* Rapid Response Hotline */}
          <div className="p-5 rounded-2xl bg-[#141211] border border-[#2b2523] space-y-3 shadow-lg">
            <div className="flex items-center gap-2 text-xs font-bold text-[#ff8d60] uppercase tracking-wider font-mono">
              <Phone className="w-4 h-4 text-[#f95721]" />
              <span>Incident Hotline</span>
            </div>
            <div className="text-xl font-bold font-mono text-[#fafaf9] tracking-tight">
              +1 (800) 555-DFIR (3347)
            </div>
          </div>

          {/* Secure Email */}
          <div className="p-5 rounded-2xl bg-[#141211] border border-[#2b2523] space-y-3 shadow-lg">
            <div className="flex items-center gap-2 text-xs font-bold text-[#ff8d60] uppercase tracking-wider font-mono">
              <Mail className="w-4 h-4 text-[#f95721]" />
              <span>Forensic Inboxes</span>
            </div>
            <div className="space-y-1 text-xs font-mono">
              <div className="flex justify-between items-center text-[#fafaf9]">
                <span className="text-[#a8a29e]">Incident Response:</span>
                <span className="text-[#f95721]">triage@dcsre.corp</span>
              </div>
              <div className="flex justify-between items-center text-[#fafaf9]">
                <span className="text-[#a8a29e]">Evidence Custody:</span>
                <span>evidence@dcsre.corp</span>
              </div>
              <div className="flex justify-between items-center text-[#fafaf9]">
                <span className="text-[#a8a29e]">Admin Command:</span>
                <span>saremworkuu@gmail.com</span>
              </div>
            </div>
          </div>

          {/* PGP Fingerprint Card */}
          <div className="p-5 rounded-2xl bg-[#141211] border border-[#2b2523] space-y-3 shadow-lg">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold text-[#ff8d60] uppercase tracking-wider font-mono">
                <Lock className="w-4 h-4 text-[#f95721]" />
                <span>PGP Fingerprint</span>
              </div>
              <button
                type="button"
                onClick={handleCopyFingerprint}
                className="text-[11px] font-mono text-[#a8a29e] hover:text-[#fafaf9] flex items-center gap-1 transition-colors cursor-pointer"
              >
                {copiedFingerprint ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <div className="p-3 bg-[#0d0c0c] border border-[#282321] rounded-xl text-[11px] font-mono text-[#d6d3d1] break-all leading-relaxed select-all">
              {pgpFingerprint}
            </div>
          </div>

          {/* Physical Enclave Location */}
          <div className="p-5 rounded-2xl bg-[#141211] border border-[#2b2523] space-y-3 shadow-lg">
            <div className="flex items-center gap-2 text-xs font-bold text-[#ff8d60] uppercase tracking-wider font-mono">
              <MapPin className="w-4 h-4 text-[#f95721]" />
              <span>Laboratory Location</span>
            </div>
            <div className="text-xs text-[#d6d3d1] space-y-0.5">
              <div className="font-semibold text-[#fafaf9]">DCSRE Secure Forensics Laboratory</div>
              <div>Intake Bay 4 · Incident Defense Center</div>
            </div>
          </div>
        </div>

        {/* Right Column: Interactive Dispatch Form (7 cols) */}
        <div className="lg:col-span-7 bg-[#141211] border border-[#2b2523] rounded-2xl p-6 sm:p-8 shadow-xl space-y-6">
          <div>
            <h2 className="text-lg font-bold text-[#fafaf9] tracking-tight">
              Submit Incident Dispatch / Inquiry
            </h2>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4 text-xs">
            {/* Name & Email */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-[#d6d3d1] font-medium block">
                  Full Name <span className="text-[#f95721]">*</span>
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-[#78716c] absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. Inspector Alex Thorne"
                    className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg pl-9 pr-3 py-2.5 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] transition-colors"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-[#d6d3d1] font-medium block">
                  Email Address <span className="text-[#f95721]">*</span>
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-[#78716c] absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="e.g. athorne@agency.gov"
                    className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg pl-9 pr-3 py-2.5 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] transition-colors"
                  />
                </div>
              </div>
            </div>

            {/* Organization & Inquiry Type */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-[#d6d3d1] font-medium block">Organization / Agency</label>
                <div className="relative">
                  <Building className="w-4 h-4 text-[#78716c] absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    placeholder="e.g. State Cyber Bureau / Corp SOC"
                    className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg pl-9 pr-3 py-2.5 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] transition-colors"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-[#d6d3d1] font-medium block">Inquiry Classification</label>
                <select
                  value={inquiryType}
                  onChange={(e) => setInquiryType(e.target.value)}
                  className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg px-3 py-2.5 text-[#fafaf9] focus:outline-none focus:border-[#f95721] transition-colors cursor-pointer font-mono"
                >
                  <option value="emergency_breach">Active Breach / Ransomware Triage</option>
                  <option value="evidence_intake">Evidence Ingestion & Verification</option>
                  <option value="expert_testimony">Courtroom Forensic Attestation</option>
                  <option value="general_inquiry">General Question / Partnership</option>
                </select>
              </div>
            </div>

            {/* Severity / Priority */}
            <div className="space-y-1.5">
              <label className="text-[#d6d3d1] font-medium block">Priority Level</label>
              <div className="grid grid-cols-3 gap-2">
                <button
                  type="button"
                  onClick={() => setPriority('critical')}
                  className={`py-2 px-3 rounded-lg border text-xs font-mono font-semibold transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                    priority === 'critical'
                      ? 'bg-red-950/80 border-red-700 text-red-300 shadow-md ring-1 ring-red-500'
                      : 'bg-[#0d0c0c] border-[#2b2523] text-[#a8a29e] hover:text-[#fafaf9]'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                  <span>P1 Critical (Active)</span>
                </button>

                <button
                  type="button"
                  onClick={() => setPriority('high')}
                  className={`py-2 px-3 rounded-lg border text-xs font-mono font-semibold transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                    priority === 'high'
                      ? 'bg-[#29160d] border-[#ea580c] text-[#ff8d60] shadow-md ring-1 ring-[#f95721]'
                      : 'bg-[#0d0c0c] border-[#2b2523] text-[#a8a29e] hover:text-[#fafaf9]'
                  }`}
                >
                  <span>P2 High</span>
                </button>

                <button
                  type="button"
                  onClick={() => setPriority('normal')}
                  className={`py-2 px-3 rounded-lg border text-xs font-mono font-semibold transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                    priority === 'normal'
                      ? 'bg-[#181615] border-[#443c39] text-[#fafaf9] shadow-md'
                      : 'bg-[#0d0c0c] border-[#2b2523] text-[#a8a29e] hover:text-[#fafaf9]'
                  }`}
                >
                  <span>P3 Standard</span>
                </button>
              </div>
            </div>

            {/* Message Body */}
            <div className="space-y-1.5">
              <label className="text-[#d6d3d1] font-medium block">
                Incident Summary / Message <span className="text-[#f95721]">*</span>
              </label>
              <textarea
                required
                rows={4}
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Describe the affected hosts, observable IOCs, timeline constraints, or request details..."
                className="w-full bg-[#0d0c0c] border border-[#2b2523] rounded-lg p-3 text-[#fafaf9] placeholder-[#78716c] focus:outline-none focus:border-[#f95721] transition-colors font-sans text-xs resize-y"
              />
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-3 px-4 bg-gradient-to-r from-[#f95721] to-[#ea580c] hover:from-[#ea580c] hover:to-[#c2410c] text-white font-bold rounded-xl text-xs flex items-center justify-center gap-2 transition-all shadow-md cursor-pointer disabled:opacity-50"
            >
              {isSubmitting ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Logging Dispatch Record...</span>
                </>
              ) : (
                <>
                  <Send className="w-4 h-4" />
                  <span>Dispatch Incident Request</span>
                </>
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
