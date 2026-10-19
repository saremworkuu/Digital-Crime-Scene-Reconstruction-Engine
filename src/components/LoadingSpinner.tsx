import React from 'react';
import { Loader2 } from 'lucide-react';

interface LoadingSpinnerProps {
  label?: string;
  size?: 'sm' | 'md' | 'lg';
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ 
  label = 'Processing Forensic Data...', 
  size = 'md' 
}) => {
  const sizeMap = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-8 h-8',
  };

  return (
    <div className="flex flex-col items-center justify-center p-8 space-y-3 text-center">
      <Loader2 className={`${sizeMap[size]} text-[#f95721] animate-spin`} />
      <span className="text-xs text-[#a8a29e] font-mono">{label}</span>
    </div>
  );
};
