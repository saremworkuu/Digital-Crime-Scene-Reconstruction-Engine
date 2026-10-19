import React from 'react';
import { LucideIcon, Inbox } from 'lucide-react';

interface EmptyStateProps {
  title: string;
  description: string;
  icon?: LucideIcon;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title,
  description,
  icon: Icon = Inbox,
  action,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-8 text-center border border-dashed border-[#2b2523] rounded-2xl bg-[#161413]/50 my-4 space-y-3 backdrop-blur-sm">
      <div className="w-10 h-10 rounded-xl bg-[#24130d] border border-[#ea580c]/30 flex items-center justify-center text-[#f95721]">
        <Icon className="w-5 h-5" />
      </div>
      <div className="space-y-1">
        <h4 className="text-xs font-semibold text-[#fafaf9]">{title}</h4>
        <p className="text-[11px] text-[#a8a29e] max-w-sm">{description}</p>
      </div>
      {action && (
        <button
          onClick={action.onClick}
          className="mt-2 px-3.5 py-1.5 rounded-lg bg-[#f95721] hover:bg-[#ea580c] text-white text-xs font-semibold transition-all shadow-[0_0_12px_rgba(249,87,33,0.3)] cursor-pointer"
        >
          {action.label}
        </button>
      )}
    </div>
  );
};
