import React, { ReactNode } from 'react';
import { TopNav } from '../TopNav';

interface AppShellProps {
  children: ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({ children }) => {
  return (
    <div className="min-h-screen bg-[#0e0d0d] text-[#e7e5e4] flex flex-col font-sans selection:bg-[#f95721]/30 selection:text-[#ff936b]">
      <TopNav />
      <main className="flex-1 flex flex-col overflow-hidden">
        {children}
      </main>
    </div>
  );
};
