import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  label: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: 'orange' | 'cyan' | 'red' | 'amber' | 'slate';
}

export const StatCard: React.FC<StatCardProps> = ({ 
  label, 
  value, 
  subtitle, 
  icon: Icon, 
  variant = 'orange' 
}) => {
  const colorMap = {
    orange: 'text-[#f95721] bg-[#2a140d] border-[#ea580c]/40',
    cyan: 'text-[#f95721] bg-[#2a140d] border-[#ea580c]/40', // normalized to cyber orange
    red: 'text-[#fca5a5] bg-[#3b1219] border-[#ef4444]/40',
    amber: 'text-[#fbbf24] bg-[#2a200d] border-[#d97706]/40',
    slate: 'text-[#a8a29e] bg-[#241f1d] border-[#38312d]',
  };

  return (
    <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-5 flex items-center justify-between shadow-xl backdrop-blur-xl">
      <div className="space-y-1">
        <span className="text-[11px] font-medium text-[#a8a29e]">{label}</span>
        <div className="text-2xl font-bold font-mono text-[#fafaf9]">{value}</div>
        {subtitle && <p className="text-[10px] text-[#78716c] font-mono">{subtitle}</p>}
      </div>
      <div className={`w-11 h-11 rounded-xl border flex items-center justify-center shrink-0 shadow-sm ${colorMap[variant]}`}>
        <Icon className="w-5 h-5" />
      </div>
    </div>
  );
};
