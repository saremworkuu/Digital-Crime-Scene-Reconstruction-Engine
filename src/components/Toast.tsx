import React, { useState, useEffect } from 'react';
import { CheckCircle2, AlertCircle, Info, AlertTriangle, X } from 'lucide-react';

export type ToastType = 'success' | 'error' | 'info' | 'warning';

export interface ToastItem {
  id: string;
  type: ToastType;
  title?: string;
  message: string;
  duration?: number;
}

type ToastListener = (toasts: ToastItem[]) => void;

class ToastManager {
  private toasts: ToastItem[] = [];
  private listeners: Set<ToastListener> = new Set();

  private notify() {
    this.listeners.forEach((listener) => listener([...this.toasts]));
  }

  public subscribe(listener: ToastListener) {
    this.listeners.add(listener);
    listener([...this.toasts]);
    return () => {
      this.listeners.delete(listener);
    };
  }

  public show(message: string, type: ToastType = 'info', title?: string, duration: number = 3800) {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const newToast: ToastItem = { id, type, title, message, duration };
    this.toasts = [newToast, ...this.toasts].slice(0, 5); // Keep at most 5 toasts visible
    this.notify();

    if (duration > 0) {
      setTimeout(() => {
        this.dismiss(id);
      }, duration);
    }
    return id;
  }

  public dismiss(id: string) {
    this.toasts = this.toasts.filter((t) => t.id !== id);
    this.notify();
  }

  public success(message: string, title?: string, duration?: number) {
    return this.show(message, 'success', title, duration);
  }

  public error(message: string, title?: string, duration?: number) {
    return this.show(message, 'error', title, duration);
  }

  public info(message: string, title?: string, duration?: number) {
    return this.show(message, 'info', title, duration);
  }

  public warning(message: string, title?: string, duration?: number) {
    return this.show(message, 'warning', title, duration);
  }
}

export const toast = new ToastManager();

export const ToastContainer: React.FC = () => {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  useEffect(() => {
    return toast.subscribe((updated) => setToasts(updated));
  }, []);

  if (toasts.length === 0) return null;

  return (
    <div
      aria-live="polite"
      className="fixed top-18 right-4 sm:right-6 z-[9999] flex flex-col gap-2.5 max-w-sm sm:max-w-md w-full pointer-events-none select-none"
    >
      {toasts.map((item) => {
        const isSuccess = item.type === 'success';
        const isError = item.type === 'error';
        const isWarning = item.type === 'warning';
        const isInfo = item.type === 'info';

        return (
          <div
            key={item.id}
            role="status"
            className={`pointer-events-auto relative overflow-hidden rounded-xl border shadow-2xl backdrop-blur-xl p-3.5 transition-all duration-300 animate-slide-in-right ${
              isSuccess
                ? 'bg-[#091a13]/95 border-emerald-600/80 text-emerald-100 shadow-[0_10px_30px_rgba(16,185,129,0.25)]'
                : isError
                ? 'bg-[#220c0c]/95 border-red-600/80 text-red-100 shadow-[0_10px_30px_rgba(239,68,68,0.25)]'
                : isWarning
                ? 'bg-[#211409]/95 border-amber-600/80 text-amber-100 shadow-[0_10px_30px_rgba(245,158,11,0.25)]'
                : 'bg-[#0f172a]/95 border-cyan-600/80 text-cyan-100 shadow-[0_10px_30px_rgba(6,182,212,0.25)]'
            }`}
          >
            <div className="flex items-start gap-3">
              <div className="shrink-0 mt-0.5">
                {isSuccess && <CheckCircle2 className="w-5 h-5 text-emerald-400 animate-bounce-short" />}
                {isError && <AlertCircle className="w-5 h-5 text-red-400" />}
                {isWarning && <AlertTriangle className="w-5 h-5 text-amber-400" />}
                {isInfo && <Info className="w-5 h-5 text-cyan-400" />}
              </div>

              <div className="flex-1 min-w-0 pr-4">
                {item.title && (
                  <h4 className="text-xs font-bold font-sans tracking-wide uppercase text-white mb-0.5">
                    {item.title}
                  </h4>
                )}
                <p className="text-xs font-sans leading-relaxed text-slate-100">
                  {item.message}
                </p>
              </div>

              <button
                type="button"
                onClick={() => toast.dismiss(item.id)}
                className="shrink-0 p-1 -mr-1 -mt-1 text-slate-400 hover:text-white transition-colors cursor-pointer rounded-lg hover:bg-white/10"
                aria-label="Close notification"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Toastify Animated Progress Bar */}
            <div
              className={`absolute bottom-0 left-0 right-0 h-1 bg-current opacity-30 origin-left`}
              style={{
                animation: `toast-progress ${item.duration || 3800}ms linear forwards`
              }}
            />
          </div>
        );
      })}
    </div>
  );
};
