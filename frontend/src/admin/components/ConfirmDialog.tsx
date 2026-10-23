import React, { useEffect } from 'react';
import { AlertTriangle, X, Loader2 } from 'lucide-react';
import { useApp } from '../../store';

interface ConfirmDialogProps {
  isOpen: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'danger' | 'warning' | 'primary';
  isLoading?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  isOpen,
  title,
  message,
  confirmLabel = 'Confirm Action',
  cancelLabel = 'Cancel',
  variant = 'danger',
  isLoading = false,
  onConfirm,
  onCancel
}) => {
  const { theme } = useApp();
  const isLight = theme === 'light';

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen && !isLoading) {
        onCancel();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, isLoading, onCancel]);

  if (!isOpen) return null;

  const variantStyles = {
    danger: {
      border: isLight ? 'border-red-200' : 'border-red-800/80',
      iconBg: isLight ? 'bg-red-50 text-red-600 border-red-200' : 'bg-red-950/80 text-red-400 border-red-700/60',
      button: 'bg-red-600 hover:bg-red-700 text-white shadow-sm'
    },
    warning: {
      border: isLight ? 'border-amber-200' : 'border-amber-800/80',
      iconBg: isLight ? 'bg-amber-50 text-amber-600 border-amber-200' : 'bg-amber-950/80 text-amber-400 border-amber-700/60',
      button: 'bg-amber-600 hover:bg-amber-700 text-black font-bold shadow-sm'
    },
    primary: {
      border: isLight ? 'border-orange-200' : 'border-[#ea580c]/60',
      iconBg: isLight ? 'bg-orange-50 text-[#f95721] border-orange-200' : 'bg-[#29130a] text-[#f95721] border-[#ea580c]/40',
      button: 'bg-[#f95721] hover:bg-[#ea580c] text-white shadow-sm'
    }
  }[variant];

  return (
    <div
      className={`fixed inset-0 z-50 flex items-center justify-center p-4 backdrop-blur-sm animate-fadeIn ${
        isLight ? 'bg-slate-900/40' : 'bg-black/80'
      }`}
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-dialog-title"
    >
      <div
        className={`w-full max-w-md rounded-2xl border p-6 shadow-2xl space-y-4 ${
          isLight ? 'bg-white border-slate-200' : 'bg-[#141211]'
        } ${variantStyles.border}`}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl border ${variantStyles.iconBg}`}>
              <AlertTriangle className="w-5 h-5" />
            </div>
            <h3
              id="confirm-dialog-title"
              className={`text-base sm:text-lg font-bold font-sans ${
                isLight ? 'text-slate-900' : 'text-white'
              }`}
            >
              {title}
            </h3>
          </div>

          <button
            type="button"
            onClick={onCancel}
            disabled={isLoading}
            className={`p-1 rounded-lg transition-colors cursor-pointer ${
              isLight ? 'text-slate-400 hover:text-slate-700 hover:bg-slate-100' : 'text-stone-400 hover:text-white hover:bg-stone-800'
            }`}
            aria-label="Close dialog"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className={`text-xs sm:text-sm leading-relaxed font-sans ${isLight ? 'text-slate-600' : 'text-stone-300'}`}>
          {message}
        </p>

        <div className={`flex items-center justify-end gap-3 pt-3 border-t ${isLight ? 'border-slate-100' : 'border-[#26201e]'}`}>
          <button
            type="button"
            onClick={onCancel}
            disabled={isLoading}
            className={`px-4 py-2 rounded-xl text-xs sm:text-sm font-semibold border transition-all cursor-pointer ${
              isLight
                ? 'text-slate-700 bg-slate-100 hover:bg-slate-200 border-slate-300'
                : 'text-stone-300 bg-stone-900 hover:bg-stone-800 border-stone-700'
            }`}
          >
            {cancelLabel}
          </button>

          <button
            type="button"
            onClick={onConfirm}
            disabled={isLoading}
            className={`px-4 py-2 rounded-xl text-xs sm:text-sm font-semibold transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${variantStyles.button}`}
          >
            {isLoading && <Loader2 className="w-4 h-4 animate-spin" />}
            <span>{confirmLabel}</span>
          </button>
      </div>
    </div>
  );
};
