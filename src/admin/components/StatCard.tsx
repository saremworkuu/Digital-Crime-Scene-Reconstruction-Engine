import React from 'react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: { text: string; color?: 'green' | 'amber' | 'red' | 'orange' };
  onClick?: () => void;
  className?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  badge,
  onClick,
  className = ''
}) => {
  const badgeColors = {
    green: 'bg-emerald-950/70 border-emerald-600/50 text-emerald-400',
    amber: 'bg-amber-950/70 border-amber-600/50 text-amber-400',
    red: 'bg-red-950/70 border-red-700/60 text-red-400',
    orange: 'bg-orange-950/70 border-orange-600/50 text-orange-400'
  };

  const badgeStyle = badge?.color ? badgeColors[badge.color] : badgeColors.orange;

  return (
    <div
      onClick={onClick}
      className={`relative overflow-hidden rounded-2xl bg-[#141211]/90 border border-[#2b2523] p-5 shadow-lg backdrop-blur-md transition-all duration-200 group ${
        onClick ? 'cursor-pointer hover:border-[#f95721]/60 hover:shadow-[0_0_20px_rgba(249,87,33,0.15)]' : ''
      } ${className}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1">
          <span className="text-xs font-mono tracking-wider text-[#a8a29e] uppercase font-semibold">
            {title}
          </span>
          <div className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight font-sans">
            {value}
          </div>
          {subtitle && (
            <p className="text-xs text-stone-400 font-sans pt-0.5 line-clamp-1">{subtitle}</p>
          )}
        </div>

        <div className="p-3 rounded-xl bg-black/40 border border-[#38312e] text-[#f95721] group-hover:scale-105 group-hover:border-[#f95721]/40 transition-all shrink-0">
          <Icon className="w-5 h-5" />
        </div>
      </div>

      {badge && (
        <div className="mt-3 pt-3 border-t border-[#26201e] flex items-center justify-between">
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${badgeStyle}`}>
            {badge.text}
          </span>
        </div>
      )}
    </div>
  );
};
