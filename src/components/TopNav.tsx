import React, { useState } from 'react';
import { useApp } from '../store';
import {
  Shield,
  ChevronDown,
  RefreshCw,
  FolderLock,
  PlusCircle,
  Check,
  LogOut,
  UserPlus,
  LogIn,
  BadgeCheck,
  Flame,
  Sun,
  Moon,
  Menu,
  X,
  Info,
  Home as HomeIcon,
  Mail
} from 'lucide-react';
import { UserRole } from '../types';
import { Forensic3DCore } from './Forensic3DCore';

interface TopNavProps {
  onToggleMobileMenu?: () => void;
  mobileMenuOpen?: boolean;
}

export const TopNav: React.FC<TopNavProps> = ({
  onToggleMobileMenu,
  mobileMenuOpen = false
}) => {
  const {
    users,
    currentUser,
    currentPage,
    setCurrentPage,
    cases,
    activeCaseId,
    setActiveCaseId,
    resetToInitialScenarios,
    logout,
    theme,
    toggleTheme
  } = useApp();

  const [caseDropdownOpen, setCaseDropdownOpen] = useState(false);
  const [roleDropdownOpen, setRoleDropdownOpen] = useState(false);

  const activeCase = cases.find(c => c.id === activeCaseId);

  const navLinks = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'cases', label: 'Cases' },
    { id: 'evidence', label: 'Evidence' },
    { id: 'timeline', label: 'Timeline' },
    { id: 'attack_graph', label: 'Attack Graph' },
    { id: 'detections', label: 'Detections' },
    { id: 'reports', label: 'Reports' },
    { id: 'audit_log', label: 'Audit Trail' }
  ];

  return (
    <header className="fixed top-0 left-0 right-0 z-50 w-full bg-[#121110]/95 backdrop-blur-md border-b border-[#282422] px-4 sm:px-6 py-3 transition-colors shadow-lg">
      <div className="flex items-center justify-between gap-4 max-w-7xl mx-auto">
        
        {/* Zone 1: Brand wordmark & mobile toggle */}
        <div className="flex items-center gap-2.5 shrink-0">
          {currentUser && (
            <button
              type="button"
              onClick={onToggleMobileMenu}
              className="lg:hidden p-1.5 rounded-lg border border-[#2e2926] bg-[#191716] hover:bg-[#221f1d] text-[#e7e5e4] transition-colors cursor-pointer"
              title="Toggle Navigation Menu"
              aria-label="Toggle Navigation Menu"
            >
              {mobileMenuOpen ? <X className="w-4 h-4 text-[#f95721]" /> : <Menu className="w-4 h-4" />}
            </button>
          )}

          <button
            onClick={() => setCurrentPage('home')}
            className="flex items-center gap-2.5 text-left group focus:outline-none cursor-pointer"
          >
            <div className="flex items-center justify-center text-[#f95721] transition-transform duration-200 group-hover:scale-110">
              <Forensic3DCore size={32} interactive={true} />
            </div>
            <div>
              <span className="text-base font-bold tracking-tight text-[#fafaf9] group-hover:text-[#f95721] transition-colors">
                DCSRE
              </span>
              <span className="text-[10px] block font-mono text-[#a8a29e] leading-none">
                CYBER FORENSICS
              </span>
            </div>
          </button>
        </div>

        {/* Zone 3: Actions */}
        <div className="flex items-center gap-2 sm:gap-2.5 shrink-0">
          {currentUser ? (
            /* Signed-in Actions: Home, About, Contact in between Home and Workspace, then Workspace */
            <>
              {/* Home Button */}
              <button
                type="button"
                onClick={() => setCurrentPage('home')}
                className={`p-1.5 sm:px-2.5 sm:py-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-all cursor-pointer shadow-sm ${
                  currentPage === 'home'
                    ? 'bg-[#2a140d] text-[#f95721] border-[#ea580c]/60'
                    : 'bg-[#191716] hover:bg-[#221f1d] border-[#2e2926] text-[#e7e5e4]'
                }`}
                title="Go to DCSRE Home Page"
                aria-label="Go to DCSRE Home Page"
              >
                <HomeIcon className="w-4 h-4 text-[#f95721]" />
                <span className="hidden sm:inline font-mono text-[11px]">Home</span>
              </button>

              {/* About Button */}
              <button
                type="button"
                onClick={() => setCurrentPage('about')}
                className={`p-1.5 sm:px-2.5 sm:py-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-all cursor-pointer shadow-sm ${
                  currentPage === 'about'
                    ? 'bg-[#2a140d] text-[#f95721] border-[#ea580c]/60'
                    : 'bg-[#191716] hover:bg-[#221f1d] border-[#2e2926] text-[#e7e5e4]'
                }`}
                title="About DCSRE Forensic Platform"
                aria-label="About DCSRE Forensic Platform"
              >
                <Info className="w-4 h-4 text-[#f95721]" />
                <span className="hidden sm:inline font-mono text-[11px]">About</span>
              </button>

              {/* Contact Button */}
              <button
                type="button"
                onClick={() => setCurrentPage('contact')}
                className={`p-1.5 sm:px-2.5 sm:py-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-all cursor-pointer shadow-sm ${
                  currentPage === 'contact'
                    ? 'bg-[#2a140d] text-[#f95721] border-[#ea580c]/60'
                    : 'bg-[#191716] hover:bg-[#221f1d] border-[#2e2926] text-[#e7e5e4]'
                }`}
                title="Contact DFIR Triage & Command Desk"
                aria-label="Contact DFIR Triage & Command Desk"
              >
                <Mail className="w-4 h-4 text-[#f95721]" />
                <span className="hidden sm:inline font-mono text-[11px]">Contact</span>
              </button>

              {/* Workspace Button */}
              <button
                type="button"
                onClick={() => setCurrentPage(currentUser.role === 'admin' ? 'dashboard' : 'cases')}
                className={`p-1.5 sm:px-2.5 sm:py-1.5 rounded-lg border text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
                  currentPage !== 'home' && currentPage !== 'about' && currentPage !== 'contact'
                    ? 'bg-[#f95721] text-white shadow-[0_0_12px_rgba(249,87,33,0.35)] border-transparent'
                    : 'bg-[#2a140d] hover:bg-[#f95721] text-[#f95721] hover:text-white border-[#ea580c]/60 hover:border-transparent shadow-sm'
                }`}
                title="Go to Investigation Workspace"
                aria-label="Go to Investigation Workspace"
              >
                <FolderLock className="w-3.5 h-3.5" />
                <span className="hidden sm:inline font-mono text-[11px]">Workspace</span>
              </button>
            </>
          ) : (
            /* Public Pre-login Actions: Home, About, Contact */
            <>
              {/* Home Button */}
              <button
                type="button"
                onClick={() => setCurrentPage('home')}
                className={`p-1.5 sm:px-2.5 sm:py-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-all cursor-pointer shadow-sm ${
                  currentPage === 'home'
                    ? 'bg-[#2a140d] text-[#f95721] border-[#ea580c]/60'
                    : 'bg-[#191716] hover:bg-[#221f1d] border-[#2e2926] text-[#e7e5e4]'
                }`}
                title="DCSRE Home"
                aria-label="DCSRE Home"
              >
                <HomeIcon className="w-4 h-4 text-[#f95721]" />
                <span className="hidden sm:inline font-mono text-[11px]">Home</span>
              </button>

              {/* About DCSRE Button */}
              <button
                type="button"
                onClick={() => setCurrentPage('about')}
                className={`p-1.5 sm:px-2.5 sm:py-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-all cursor-pointer shadow-sm ${
                  currentPage === 'about'
                    ? 'bg-[#2a140d] text-[#f95721] border-[#ea580c]/60'
                    : 'bg-[#191716] hover:bg-[#221f1d] border-[#2e2926] text-[#e7e5e4]'
                }`}
                title="About DCSRE Forensic Platform"
                aria-label="About DCSRE Forensic Platform"
              >
                <Info className="w-4 h-4 text-[#f95721]" />
                <span className="hidden sm:inline font-mono text-[11px]">About</span>
              </button>

              {/* Contact Button */}
              <button
                type="button"
                onClick={() => setCurrentPage('contact')}
                className={`p-1.5 sm:px-2.5 sm:py-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-all cursor-pointer shadow-sm ${
                  currentPage === 'contact'
                    ? 'bg-[#2a140d] text-[#f95721] border-[#ea580c]/60'
                    : 'bg-[#191716] hover:bg-[#221f1d] border-[#2e2926] text-[#e7e5e4]'
                }`}
                title="Contact DFIR Triage & Command Desk"
                aria-label="Contact DFIR Triage & Command Desk"
              >
                <Mail className="w-4 h-4 text-[#f95721]" />
                <span className="hidden sm:inline font-mono text-[11px]">Contact</span>
              </button>
            </>
          )}

          {/* Light / Dark Mode Toggle Button */}
          <button
            type="button"
            onClick={toggleTheme}
            className="p-1.5 sm:px-2.5 sm:py-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-all cursor-pointer bg-[#191716] hover:bg-[#221f1d] border-[#2e2926] text-[#e7e5e4] shadow-sm"
            title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            aria-label={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          >
            {theme === 'dark' ? (
              <>
                <Sun className="w-4 h-4 text-amber-400" />
                <span className="hidden sm:inline font-mono text-[11px] text-[#d6d3d1]">Light</span>
              </>
            ) : (
              <>
                <Moon className="w-4 h-4 text-indigo-400" />
                <span className="hidden sm:inline font-mono text-[11px] text-[#3f3f46]">Dark</span>
              </>
            )}
          </button>

          {currentUser ? (
            <>
              {/* Active Case Selector */}
              <div className="relative">
                <button
                  onClick={() => {
                    setCaseDropdownOpen(!caseDropdownOpen);
                    setRoleDropdownOpen(false);
                  }}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#191716] hover:bg-[#221f1d] border border-[#2e2926] text-xs text-[#e7e5e4] transition-colors max-w-[200px]"
                  title="Active Investigation Case"
                >
                  <FolderLock className="w-3.5 h-3.5 text-[#f95721] shrink-0" />
                  <span className="truncate font-mono">{activeCase ? activeCase.name : 'Select Case'}</span>
                  <ChevronDown className="w-3 h-3 text-[#78716c] shrink-0 ml-auto" />
                </button>

                {caseDropdownOpen && (
                  <div className="absolute right-0 mt-1.5 w-80 bg-[#181615] border border-[#2e2926] rounded-xl shadow-2xl py-1 z-50 animate-fadeIn">
                    <div className="px-3 py-1.5 text-[11px] font-mono uppercase text-[#78716c] border-b border-[#2e2926] flex justify-between items-center">
                      <span>Active Investigation</span>
                      <button
                        onClick={() => {
                          setCaseDropdownOpen(false);
                          setCurrentPage('cases');
                        }}
                        className="text-[#f95721] hover:underline flex items-center gap-1 font-semibold"
                      >
                        <PlusCircle className="w-3 h-3" /> New
                      </button>
                    </div>
                    <div className="max-h-60 overflow-y-auto py-1">
                      {cases.map((c) => (
                        <button
                          key={c.id}
                          onClick={() => {
                            setActiveCaseId(c.id);
                            setCaseDropdownOpen(false);
                          }}
                          className={`w-full text-left px-3 py-2 text-xs flex items-start gap-2 hover:bg-[#23201e] transition-colors ${
                            c.id === activeCaseId ? 'bg-[#291711] text-[#ff7847]' : 'text-[#d6d3d1]'
                          }`}
                        >
                          <div className="pt-0.5">
                            {c.id === activeCaseId ? (
                              <Check className="w-3.5 h-3.5 text-[#f95721]" />
                            ) : (
                              <span className="w-3.5 h-3.5 block" />
                            )}
                          </div>
                          <div className="min-w-0">
                            <div className="font-medium truncate">{c.name}</div>
                            <div className="text-[11px] text-[#78716c] flex items-center gap-2 mt-0.5">
                              <span>{c.status}</span>
                              <span>·</span>
                              <span className="font-mono">{c.event_count} events</span>
                            </div>
                          </div>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* User Persona / Role Switcher */}
              <div className="relative">
                <button
                  onClick={() => {
                    setRoleDropdownOpen(!roleDropdownOpen);
                    setCaseDropdownOpen(false);
                  }}
                  className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-[#191716] hover:bg-[#221f1d] border border-[#2e2926] text-xs text-[#e7e5e4] transition-colors"
                >
                  <div className="w-5 h-5 rounded-full bg-[#24130d] border border-[#ea580c]/50 flex items-center justify-center text-[10px] font-bold text-[#f95721]">
                    {currentUser?.name.charAt(0) || 'U'}
                  </div>
                  <span className="hidden sm:inline font-medium">{currentUser?.name.split(' ')[0]}</span>
                  <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-[#2a1711] text-[#fb923c] border border-[#7c2d12]/60">
                    {currentUser?.role}
                  </span>
                  <ChevronDown className="w-3 h-3 text-[#78716c]" />
                </button>

                {roleDropdownOpen && (
                  <div className="absolute right-0 mt-1.5 w-72 bg-[#181615] border border-[#2e2926] rounded-xl shadow-2xl py-1 z-50 animate-fadeIn">
                    <div className="px-3 py-2.5 border-b border-[#2e2926] space-y-1">
                      <div className="text-xs font-semibold text-[#fafaf9]">{currentUser?.name}</div>
                      <div className="text-[11px] text-[#a8a29e] truncate font-mono">{currentUser?.email}</div>
                      <div className="flex items-center justify-between text-[10px] font-mono text-[#a8a29e] pt-1">
                        <span className="text-[#f95721] truncate max-w-[160px]">{currentUser?.department}</span>
                        {currentUser?.badgeId && (
                          <span className="px-1.5 py-0.5 rounded bg-[#221f1d] text-[#d6d3d1] border border-[#332c28]">
                            {currentUser.badgeId}
                          </span>
                        )}
                      </div>
                    </div>
                    
                    <div className="px-3 py-2 bg-[#121110] border-b border-[#2e2926] flex items-center justify-between text-[11px] font-mono">
                      <span className="text-[#a8a29e]">Clearance:</span>
                      <span className={`font-semibold uppercase tracking-wider text-[10px] px-1.5 py-0.5 rounded ${
                        currentUser?.role === 'admin'
                          ? 'bg-[#3b1219] text-[#fca5a5] border border-[#ef4444]/40'
                          : 'bg-[#2a140d] text-[#fb923c] border border-[#ea580c]/50'
                      }`}>
                        {currentUser?.role === 'admin' ? 'Administrator' : 'Investigator'}
                      </span>
                    </div>

                    <div className="border-t border-[#2e2926] mt-1 pt-1 space-y-0.5">
                      <button
                        onClick={() => {
                          setRoleDropdownOpen(false);
                          setCurrentPage('register');
                        }}
                        className="w-full text-left px-3 py-1.5 text-xs text-[#f95721] hover:bg-[#23201e] flex items-center gap-1.5 transition-colors font-medium"
                      >
                        <UserPlus className="w-3.5 h-3.5" />
                        <span>Register New Examiner</span>
                      </button>

                      <button
                        onClick={() => {
                          setRoleDropdownOpen(false);
                          setCurrentPage('admin_login');
                        }}
                        className="w-full text-left px-3 py-1.5 text-xs text-[#ff936b] hover:bg-[#23201e] flex items-center gap-1.5 transition-colors font-medium cursor-pointer"
                      >
                        <Shield className="w-3.5 h-3.5 text-[#f95721]" />
                        <span>Admin Login Page</span>
                      </button>

                      <button
                        onClick={() => {
                          resetToInitialScenarios();
                          setRoleDropdownOpen(false);
                        }}
                        className="w-full text-left px-3 py-1.5 text-xs text-[#f59e0b] hover:bg-[#23201e] flex items-center gap-1.5 transition-colors"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                        <span>Reset Scenario Data</span>
                      </button>

                      <div className="border-t border-[#2e2926] my-1" />

                      <button
                        onClick={() => {
                          setRoleDropdownOpen(false);
                          logout();
                        }}
                        className="w-full text-left px-3 py-1.5 text-xs text-red-400 hover:bg-red-950/30 flex items-center gap-1.5 transition-colors"
                      >
                        <LogOut className="w-3.5 h-3.5" />
                        <span>Sign Out / Lock Terminal</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            /* Unauthenticated Top Navigation: Single Unified Login & Portal Access Gateway */
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setCurrentPage('login')}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
                  currentPage === 'login' || currentPage === 'admin_login' || currentPage === 'register'
                    ? 'bg-[#f95721] text-white shadow-[0_0_12px_rgba(249,87,33,0.4)]'
                    : 'bg-[#191716] border border-[#2e2926] text-[#fafaf9] hover:bg-[#24130d] hover:border-[#ea580c]/50'
                }`}
                title="Unified Access Gateway for Investigators, Admins, and Registration"
              >
                <LogIn className="w-3.5 h-3.5 text-[#f95721]" />
                <span>Log In</span>
              </button>
            </div>
          )}
        </div>

      </div>
    </header>
  );
};
