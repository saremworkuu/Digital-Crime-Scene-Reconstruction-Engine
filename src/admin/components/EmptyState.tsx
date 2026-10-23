import React from 'react';
import { Database } from 'lucide-react';

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
  return (
    <div className="flex flex-col items-center justify-center p-8 sm:p-12 text-center rounded-2xl bg-black/20 border border-dashed border-[#332b27] space-y-3">
      <div className="p-4 rounded-2xl bg-[#1d1613] border border-[#3d2b21] text-[#f95721] shadow-inner">
        <Icon className="w-8 h-8 opacity-80" />
      </div>

      <div className="space-y-1 max-w-sm">
        <h4 className="text-sm sm:text-base font-bold text-white font-sans">{title}</h4>
        <p className="text-xs text-stone-400 font-sans leading-relaxed">{message}</p>
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
