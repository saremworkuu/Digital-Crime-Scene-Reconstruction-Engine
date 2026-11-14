import React from 'react';
import { useApp } from '../../store';

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
  const { theme } = useApp();
  const isLight = theme === 'light';

  const badgeColorsDark = {
    green: 'bg-emerald-950/70 border-emerald-600/50 text-emerald-400',
    amber: 'bg-amber-950/70 border-amber-600/50 text-amber-400',
    red: 'bg-red-950/70 border-red-700/60 text-red-400',
    orange: 'bg-orange-950/70 border-orange-600/50 text-orange-400'
  };

  const badgeColorsLight = {
    green: 'bg-emerald-50 border-emerald-200 text-emerald-700',
    amber: 'bg-amber-50 border-amber-200 text-amber-700',
    red: 'bg-rose-50 border-rose-200 text-rose-700',
    orange: 'bg-orange-50 border-orange-200 text-orange-700'
  };

  const badgeColors = isLight ? badgeColorsLight : badgeColorsDark;
  const badgeStyle = badge?.color ? badgeColors[badge.color] : badgeColors.orange;

  return (
    <div
      onClick={onClick}
      className={`relative overflow-hidden rounded-2xl p-5 shadow-lg backdrop-blur-md transition-all duration-200 group ${
        isLight
          ? 'bg-white border border-slate-200 text-slate-900 shadow-sm'
          : 'bg-[#141211]/90 border border-[#2b2523] text-white'
      } ${
        onClick
          ? isLight
            ? 'cursor-pointer hover:border-[#f95721] hover:shadow-[0_0_20px_rgba(249,87,33,0.1)]'
            : 'cursor-pointer hover:border-[#f95721]/60 hover:shadow-[0_0_20px_rgba(249,87,33,0.15)]'
          : ''
      } ${className}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1">
          <span
            className={`text-xs font-mono tracking-wider uppercase font-semibold ${
              isLight ? 'text-slate-500' : 'text-[#a8a29e]'
            }`}
          >
            {title}
          </span>
          <div
            className={`text-2xl sm:text-3xl font-extrabold tracking-tight font-sans ${
              isLight ? 'text-slate-900' : 'text-white'
            }`}
          >
            {value}
          </div>
          {subtitle && (
            <p
              className={`text-xs font-sans pt-0.5 line-clamp-1 ${
                isLight ? 'text-slate-500' : 'text-stone-400'
              }`}
            >
              {subtitle}
            </p>
          )}
        </div>

        <div
          className={`p-3 rounded-xl group-hover:scale-105 transition-all shrink-0 ${
            isLight
              ? 'bg-orange-50 border border-orange-200 text-[#f95721] group-hover:border-[#f95721]'
              : 'bg-black/40 border border-[#38312e] text-[#f95721] group-hover:border-[#f95721]/40'
          }`}
        >
          <Icon className="w-5 h-5" />
        </div>
      </div>

      {badge && (
        <div
          className={`mt-3 pt-3 border-t flex items-center justify-between ${
            isLight ? 'border-slate-100' : 'border-[#26201e]'
          }`}
        >
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${badgeStyle}`}>
            {badge.text}
          </span>
        </div>
      )}
    </div>
  );
};
