import React from 'react';
import { Database } from 'lucide-react';
import { useApp } from '../../store';

interface EmptyStateProps {
  title?: string;
  message?: string;
  icon?: React.ComponentType<{ className?: string }>;
  actionLabel?: string;
  onAction?: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title = 'No records found',
  message = 'Try adjusting your search criteria or filter options to locate items.',
  icon: Icon = Database,
  actionLabel,
  onAction
}) => {
  const { theme } = useApp();
  const isLight = theme === 'light';

  return (
    <div
      className={`flex flex-col items-center justify-center p-8 sm:p-12 text-center rounded-2xl border border-dashed space-y-3 ${
        isLight
          ? 'bg-slate-50/70 border-slate-300'
          : 'bg-black/20 border-[#332b27]'
      }`}
    >
      <div
        className={`p-4 rounded-2xl border shadow-inner ${
          isLight
            ? 'bg-orange-50 border-orange-200 text-[#f95721]'
            : 'bg-[#1d1613] border-[#3d2b21] text-[#f95721]'
        }`}
      >
        <Icon className="w-8 h-8 opacity-80" />
      </div>

      <div className="space-y-1 max-w-sm">
        <h4 className={`text-sm sm:text-base font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
          {title}
        </h4>
        <p className={`text-xs font-sans leading-relaxed ${isLight ? 'text-slate-500' : 'text-stone-400'}`}>
          {message}
        </p>
      </div>

      {actionLabel && onAction && (
        <button
          type="button"
          onClick={onAction}
          className="mt-2 px-4 py-2 rounded-xl text-xs font-semibold text-white bg-[#f95721] hover:bg-[#ea580c] transition-all shadow-[0_0_15px_rgba(249,87,33,0.3)] cursor-pointer"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
};
