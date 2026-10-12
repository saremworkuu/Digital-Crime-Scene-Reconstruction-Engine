import React from 'react';
import { useApp } from '../store';
import {
  LayoutDashboard,
  FolderLock,
  FileCheck2,
  Clock,
  Network,
  GitBranch,
  ShieldAlert,
  FileText,
  History,
  Home as HomeIcon
} from 'lucide-react';

interface SidebarItem {
  id: string;
  label: string;
  code?: string;
  icon?: React.ComponentType<{ className?: string }>;
}

export const SIDEBAR_ITEMS: SidebarItem[] = [
  { id: 'dashboard', label: 'Dashboard', code: 'DB', icon: LayoutDashboard },
  { id: 'cases', label: 'Investigations', code: 'CS', icon: FolderLock },
  { id: 'evidence', label: 'Evidence', code: 'EV', icon: FileCheck2 },
  { id: 'timeline', label: 'Timeline', code: 'TL', icon: Clock },
  { id: 'attack_graph', label: 'Correlation', code: 'CR', icon: Network },
  { id: 'attack_path', label: 'Attack Path', code: 'AP', icon: GitBranch },
  { id: 'detections', label: 'Findings', code: 'FN', icon: ShieldAlert },
  { id: 'reports', label: 'Reports', code: 'RP', icon: FileText },
  { id: 'audit_log', label: 'Audit Trail', code: 'AT', icon: History },
];

interface SidebarNavProps {
  className?: string;
}

export const SidebarNav: React.FC<SidebarNavProps> = ({ className = '' }) => {
  const { currentPage, setCurrentPage, theme, currentUser } = useApp();

  const isLight = theme === 'light';
  const isAdmin = currentUser?.role === 'admin';

  // Admin only can see the dashboard; filter it out for investigators to mitigate operational risk
  const visibleItems = SIDEBAR_ITEMS.filter((item) => {
    if (item.id === 'dashboard') {
      return isAdmin;
    }
    return true;
  });

  return (
    <aside
      className={`w-60 shrink-0 select-none flex flex-col py-4 px-3 space-y-1.5 transition-colors duration-200 ${
        isLight
          ? 'bg-white/80 border-r border-[#e4e4e7]'
          : 'bg-[#121110]/90 border-r border-[#24201e]'
      } backdrop-blur-md ${className}`}
    >
      <div className="text-[10px] font-mono tracking-wider text-[#a8a29e] uppercase px-2 mb-2 font-semibold flex items-center justify-between">
        <span>Navigation</span>
        <span className="text-[9px] font-mono text-[#f95721] lowercase">
          {isAdmin ? 'admin' : 'investigator'}
        </span>
      </div>

      <nav className="flex flex-col space-y-1">
        {visibleItems.map((item) => {
          const isActive = currentPage === item.id;

          const handleClick = () => {
            setCurrentPage(item.id);
          };

          return (
            <button
              key={item.id}
              type="button"
              onClick={handleClick}
              className={`w-full flex items-center px-3.5 py-2.5 rounded-xl text-left text-sm font-medium transition-all group cursor-pointer ${
                isActive
                  ? isLight
                    ? 'bg-[#ea580c]/10 text-[#ea580c] border border-[#ea580c]/30 shadow-sm'
                    : 'bg-[#221712] text-[#f95721] border border-[#ea580c]/50 shadow-[0_0_12px_rgba(249,87,33,0.18)]'
                  : isLight
                  ? 'text-[#52525b] hover:text-[#18181b] hover:bg-[#f4f4f5] border border-transparent'
                  : 'text-[#a8a29e] hover:text-[#fafaf9] hover:bg-[#1a1716] border border-transparent'
              }`}
            >
              {/* Navigation Label */}
              <span
                className={`font-semibold tracking-tight transition-colors truncate ${
                  isActive
                    ? isLight
                      ? 'text-[#ea580c] font-bold'
                      : 'text-[#fafaf9] font-bold'
                    : isLight
                    ? 'text-[#3f3f46] group-hover:text-[#18181b]'
                    : 'text-[#d6d3d1] group-hover:text-[#fafaf9]'
                }`}
              >
                {item.label}
              </span>
            </button>
          );
        })}
      </nav>

      {/* Return to Home Page button for signed-in users */}
      <div className={`pt-3 mt-auto border-t ${isLight ? 'border-slate-200' : 'border-[#24201e]'}`}>
        <button
          type="button"
          onClick={() => setCurrentPage('home')}
          className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-medium transition-all group cursor-pointer ${
            currentPage === 'home'
              ? isLight
                ? 'bg-[#ea580c]/10 text-[#ea580c] border border-[#ea580c]/30'
                : 'bg-[#221712] text-[#f95721] border border-[#ea580c]/50'
              : isLight
              ? 'text-[#52525b] hover:text-[#18181b] hover:bg-[#f4f4f5] border border-transparent'
              : 'text-[#a8a29e] hover:text-[#fafaf9] hover:bg-[#1a1716] border border-[#26211f]'
          }`}
          title="Redirect to Home Page"
        >
          <div className="flex items-center gap-2">
            <HomeIcon className="w-4 h-4 text-[#f95721] group-hover:scale-110 transition-transform" />
            <span className="font-medium">Go to Home</span>
          </div>
          <span className={`font-mono text-[9px] uppercase px-1.5 py-0.5 rounded ${
            isLight
              ? 'bg-orange-50 text-orange-700 border border-orange-200'
              : 'bg-[#24130d] text-[#f95721] border border-[#ea580c]/40'
          }`}>
            Public
          </span>
        </button>
      </div>
    </aside>
  );
};
