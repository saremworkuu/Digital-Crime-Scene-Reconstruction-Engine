import React from 'react';
import { useStore } from '../store';
import { AlertCircle, ArrowLeft } from 'lucide-react';

export const NotFound: React.FC = () => {
  const { setTab } = useStore();

  return (
    <div className="flex-1 flex items-center justify-center p-6 text-center">
      <div className="max-w-md w-full bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-8 space-y-4 backdrop-blur-xl shadow-2xl">
        <div className="w-12 h-12 rounded-xl bg-[#24130d] border border-[#ea580c]/40 flex items-center justify-center text-[#f95721] mx-auto">
          <AlertCircle className="w-6 h-6" />
        </div>
        <h2 className="text-base font-bold text-[#fafaf9]">404 - Forensic Route Not Found</h2>
        <p className="text-xs text-[#a8a29e]">
          The requested forensic resource or case endpoint does not exist in the current investigation scope.
        </p>
        <button
          onClick={() => setTab('cases')}
          className="px-4 py-2 bg-[#f95721] hover:bg-[#ea580c] text-white text-xs font-semibold rounded-lg inline-flex items-center gap-1.5 transition-all shadow-[0_0_12px_rgba(249,87,33,0.3)] cursor-pointer"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Return to Investigations</span>
        </button>
      </div>
    </div>
  );
};
