import React, { useState } from 'react';
import { useApp, DEMO_USERS } from '../../store';
import { 
  LayoutDashboard, 
  Crosshair, 
  ShieldAlert, 
  CheckSquare, 
  FolderLock, 
  Boxes, 
  HelpCircle, 
  Plus, 
  ChevronDown, 
  LogOut, 
  Shield, 
  UserCheck,
  RefreshCw 
} from 'lucide-react';
import { UserRole } from '../../types';

interface SidebarProps {
  onOpenNewTask: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ onOpenNewTask }) => {
  const { 
    currentPage, 
    setCurrentPage, 
    currentUser, 
    setCurrentUser, 
    logAuditAction,
    resetToInitialScenarios
  } = useApp();

  const [profileDropdownOpen, setProfileDropdownOpen] = useState(false);

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'findings', label: 'Findings', icon: Crosshair },
    { id: 'incidents', label: 'Incidents', icon: ShieldAlert },
    { id: 'compliance', label: 'Compliance', icon: CheckSquare },
    { id: 'vault', label: 'Vault', icon: FolderLock },
    { id: 'integrations', label: 'Integrations', icon: Boxes },
  ];

  const handleLogout = () => {
    logAuditAction('USER_LOGOUT', 'user', currentUser?.id || 'anon', { reason: 'User logged out' });
    setCurrentUser(null);
    setCurrentPage('login');
  };

  const currentHandle = currentUser?.role === 'admin' 
    ? '@sarem_admin' 
    : '@chen_dfir';

  return (
    <aside className="w-60 bg-[#0a0a0d] border-r border-neutral-800/80 flex flex-col justify-between shrink-0 select-none z-30">
      
      {/* Top Brand & New Task Button */}
      <div className="p-4 space-y-4">
        {/* Brand Header (CY · FOCUS) */}
        <div className="flex items-center gap-2 px-1">
          <div className="w-2.5 h-2.5 rounded-full bg-[#ff461e] shadow-[0_0_10px_#ff461e]" />
          <span className="text-base font-bold tracking-tight text-white font-sans">
            CY <span className="text-[#ff461e]">·</span> FOCUS
          </span>
          <span className="text-[10px] font-mono text-neutral-500 uppercase ml-auto">
            v2.6
          </span>
        </div>

        {/* Primary Action Button (Screenshot 1, 2, 3: [New task +]) */}
        <button
          onClick={onOpenNewTask}
          className="w-full py-2.5 px-3.5 rounded-xl bg-gradient-to-r from-[#ff461e] to-[#ff5722] hover:from-[#ff5722] hover:to-[#ff6a3d] text-white font-semibold text-xs tracking-wide transition-all shadow-[0_0_20px_rgba(255,70,30,0.35)] hover:shadow-[0_0_30px_rgba(255,70,30,0.5)] flex items-center justify-between cursor-pointer active:scale-98"
        >
          <span>New task</span>
          <div className="w-5 h-5 rounded-md bg-white/20 flex items-center justify-center">
            <Plus className="w-3.5 h-3.5" />
          </div>
        </button>

        {/* Main Navigation Links */}
        <nav className="space-y-1 pt-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = 
              currentPage === item.id || 
              (item.id === 'findings' && currentPage === 'cases') ||
              (item.id === 'incidents' && currentPage === 'detections') ||
              (item.id === 'compliance' && currentPage === 'evidence') ||
              (item.id === 'vault' && (currentPage === 'timeline' || currentPage === 'attack_graph')) ||
              (item.id === 'integrations' && (currentPage === 'reports' || currentPage === 'audit_log'));

            return (
              <button
                key={item.id}
                onClick={() => setCurrentPage(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-medium transition-all cursor-pointer ${
                  isActive
                    ? 'bg-neutral-850/80 text-white shadow-sm border border-neutral-700/60'
                    : 'text-neutral-400 hover:text-neutral-100 hover:bg-neutral-900/60'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-[#ff461e]' : 'text-neutral-500'}`} />
                  <span>{item.label}</span>
                </div>

                {/* Active Glowing Dot (Matching Screenshot 1 & 3 on Findings / Dashboard!) */}
                {isActive && (
                  <span className="w-2 h-2 rounded-full bg-white shadow-[0_0_8px_#ffffff]" />
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Profile & Help Section (Matching Reference Screenshots!) */}
      <div className="p-3 border-t border-neutral-800/80 space-y-2">
        {/* Help & Docs */}
        <button
          onClick={() => setCurrentPage('integrations')}
          className="w-full flex items-center gap-3 px-3 py-2 rounded-xl text-xs text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60 transition-colors cursor-pointer"
        >
          <HelpCircle className="w-4 h-4 text-neutral-500" />
          <span>Help & Docs</span>
        </button>

        {/* User Profile Card (Anna Gunn @gunna25) */}
        <div className="relative">
          <button
            onClick={() => setProfileDropdownOpen(!profileDropdownOpen)}
            className="w-full flex items-center justify-between p-2 rounded-xl bg-neutral-950/70 hover:bg-neutral-900/90 border border-neutral-850 transition-all cursor-pointer text-left"
          >
            <div className="flex items-center gap-2.5 truncate">
              {/* Profile Avatar */}
              <div className="w-7 h-7 rounded-lg bg-gradient-to-tr from-[#ff461e] to-[#ff8f3d] flex items-center justify-center text-white font-bold text-[10px] shrink-0 shadow-[0_0_10px_rgba(255,70,30,0.3)]">
                {currentUser?.name?.split(' ').map(n => n[0]).join('') || 'AG'}
              </div>

              <div className="truncate">
                <div className="text-xs font-semibold text-neutral-200 truncate">
                  {currentUser?.name || 'Anna Gunn'}
                </div>
                <div className="text-[10px] text-neutral-500 font-mono truncate">
                  {currentHandle}
                </div>
              </div>
            </div>

            <ChevronDown className="w-3.5 h-3.5 text-neutral-500 shrink-0 ml-1" />
          </button>

          {/* Profile Dropdown: Examiner Session Info & Logout (No Role Switching) */}
          {profileDropdownOpen && (
            <div className="absolute bottom-full left-0 mb-2 w-full rounded-2xl bg-[#121217] border border-neutral-800 shadow-[0_15px_40px_rgba(0,0,0,0.8)] p-3 z-50 space-y-2 backdrop-blur-xl">
              <div className="space-y-1 pb-2 border-b border-neutral-800">
                <div className="text-xs font-semibold text-white truncate">{currentUser?.name}</div>
                <div className="text-[10px] text-neutral-400 font-mono truncate">{currentUser?.email}</div>
                <div className="pt-1 flex items-center justify-between">
                  <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded font-bold ${
                    currentUser?.role === 'admin'
                      ? 'bg-[#3b1219] text-[#fca5a5] border border-[#ef4444]/40'
                      : 'bg-[#24130d] text-[#f95721] border border-[#ea580c]/30'
                  }`}>
                    {currentUser?.role === 'admin' ? 'Administrator' : 'Investigator'}
                  </span>
                  <span className="text-[10px] text-neutral-500 font-mono">
                    {currentUser?.badgeId || 'DFIR-4821'}
                  </span>
                </div>
              </div>

              <div className="space-y-1">
                <button
                  type="button"
                  onClick={() => {
                    setProfileDropdownOpen(false);
                    setCurrentPage('about');
                  }}
                  className="w-full text-left px-2 py-1.5 rounded-lg text-xs text-neutral-300 hover:bg-neutral-800 hover:text-white transition-colors cursor-pointer"
                >
                  About አሻራ Engine
                </button>
                <button
                  type="button"
                  onClick={() => {
                    resetToInitialScenarios();
                    setProfileDropdownOpen(false);
                  }}
                  className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg text-xs text-[#f95721] hover:bg-[#24130d] hover:text-[#fb923c] transition-colors cursor-pointer font-medium"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Reset Case</span>
                </button>
              </div>

              <div className="border-t border-neutral-800/80 pt-1.5 mt-1">
                <button
                  onClick={handleLogout}
                  className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg text-xs text-red-400 hover:bg-red-950/40 transition-colors cursor-pointer font-medium"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>Sign Out</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

    </aside>
  );
};
