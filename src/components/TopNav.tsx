import React, { useState, useRef, useEffect } from 'react';
import { useApp } from '../store';
import {
  Shield,
  ChevronDown,
  RefreshCw,
  LogOut,
  Sun,
  Moon,
  Menu,
  X,
  UserCog
} from 'lucide-react';
import { Forensic3DCore } from './Forensic3DCore';
import { EditProfileModal } from './EditProfileModal';

interface TopNavProps {
  onToggleMobileMenu?: () => void;
  mobileMenuOpen?: boolean;
}

export const TopNav: React.FC<TopNavProps> = ({
  onToggleMobileMenu,
  mobileMenuOpen = false
}) => {
  const {
    currentUser,
    currentPage,
    setCurrentPage,
    resetToInitialScenarios,
    logout,
    theme,
    toggleTheme
  } = useApp();

  const isLight = theme === 'light';
  const [roleDropdownOpen, setRoleDropdownOpen] = useState(false);
  const [isEditProfileOpen, setIsEditProfileOpen] = useState(false);
  const closeTimeoutRef = useRef<any>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Clear timeout on unmount and handle outside click
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setRoleDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      if (closeTimeoutRef.current) {
        clearTimeout(closeTimeoutRef.current);
      }
    };
  }, []);

  const handleMouseEnter = () => {
    if (closeTimeoutRef.current) {
      clearTimeout(closeTimeoutRef.current);
      closeTimeoutRef.current = null;
    }
    setRoleDropdownOpen(true);
  };

  const handleMouseLeave = () => {
    if (closeTimeoutRef.current) {
      clearTimeout(closeTimeoutRef.current);
    }
    closeTimeoutRef.current = setTimeout(() => {
      setRoleDropdownOpen(false);
    }, 150);
  };

  return (
    <header className="fixed top-0 left-0 right-0 z-50 w-full bg-[#121110]/95 backdrop-blur-md border-b border-[#282422] px-4 sm:px-6 py-3 transition-colors shadow-lg">
      <div className="flex items-center justify-between gap-4 max-w-7xl mx-auto">

        {/* Zone 1: Brand wordmark & mobile toggle */}
        <div className="flex items-center gap-2 sm:gap-2.5 shrink-0">
          <button
            type="button"
            onClick={onToggleMobileMenu}
            className={`${currentUser ? 'lg:hidden' : 'md:hidden'} p-1.5 rounded-lg border transition-colors cursor-pointer ${isLight
                ? 'border-slate-200 bg-slate-100 hover:bg-slate-200 text-slate-800'
                : 'border-[#2e2926] bg-[#191716] hover:bg-[#221f1d] text-[#e7e5e4]'
              }`}
            title="Toggle Navigation Menu"
            aria-label="Toggle Navigation Menu"
          >
            {mobileMenuOpen ? <X className="w-4 h-4 text-[#f95721]" /> : <Menu className="w-4 h-4" />}
          </button>

          <button
            onClick={() => setCurrentPage('home')}
            className="flex items-center gap-2 sm:gap-2.5 text-left group focus:outline-none cursor-pointer"
          >
            <div className="flex items-center justify-center text-[#f95721] transition-transform duration-200 group-hover:scale-110 shrink-0">
              <Forensic3DCore size={28} interactive={true} />
            </div>
            <div>
              <span className={`text-sm sm:text-base font-bold tracking-tight transition-colors ${isLight ? 'text-slate-900 group-hover:text-[#ea580c]' : 'text-[#fafaf9] group-hover:text-[#f95721]'
                }`}>
                አሻራ
              </span>
              <span className={`text-[9px] sm:text-[10px] block font-mono leading-none ${isLight ? 'text-slate-500' : 'text-[#a8a29e]'
                }`}>
                CYBER FORENSICS
              </span>
            </div>
          </button>
        </div>

        {/* Zone 2: Navigation Links & Actions (Collapses gracefully on mobile) */}
        <div className="flex items-center gap-2 sm:gap-4 shrink-0">
          {currentUser ? (
            /* Signed-in Actions: Clean text links without boxes or symbols */
            <div className="hidden md:flex items-center gap-3 sm:gap-5 mr-1">
              <button
                type="button"
                onClick={() => setCurrentPage('home')}
                className={`text-sm font-semibold transition-colors cursor-pointer ${currentPage === 'home'
                    ? (isLight ? 'text-[#ea580c]' : 'text-[#f95721]')
                    : (isLight ? 'text-slate-800 hover:text-[#ea580c]' : 'text-[#e7e5e4] hover:text-[#f95721]')
                  }`}
              >
                Home
              </button>

              <button
                type="button"
                onClick={() => setCurrentPage('about')}
                className={`text-sm font-medium transition-colors cursor-pointer ${currentPage === 'about'
                    ? (isLight ? 'text-[#ea580c]' : 'text-[#f95721]')
                    : (isLight ? 'text-slate-800 hover:text-[#ea580c]' : 'text-[#e7e5e4] hover:text-[#f95721]')
                  }`}
              >
                About
              </button>

              <button
                type="button"
                onClick={() => setCurrentPage('contact')}
                className={`text-sm font-medium transition-colors cursor-pointer ${currentPage === 'contact'
                    ? (isLight ? 'text-[#ea580c]' : 'text-[#f95721]')
                    : (isLight ? 'text-slate-800 hover:text-[#ea580c]' : 'text-[#e7e5e4] hover:text-[#f95721]')
                  }`}
              >
                Contact
              </button>

              {currentUser.role === 'admin' ? (
                <button
                  type="button"
                  onClick={() => {
                    if (typeof window !== 'undefined') {
                      window.location.hash = '#/admin/dashboard';
                    }
                    setCurrentPage('admin');
                  }}
                  className={`text-sm font-medium transition-colors cursor-pointer ${
                    currentPage === 'admin' || (typeof window !== 'undefined' && window.location.hash.startsWith('#/admin'))
                      ? (isLight ? 'text-[#ea580c] font-semibold' : 'text-[#f95721] font-semibold')
                      : (isLight ? 'text-slate-800 hover:text-[#ea580c]' : 'text-[#e7e5e4] hover:text-[#f95721]')
                  }`}
                >
                  Admin Dashboard
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => {
                    if (typeof window !== 'undefined') {
                      window.location.hash = '';
                    }
                    setCurrentPage('dashboard');
                  }}
                  className={`text-sm font-medium transition-colors cursor-pointer ${
                    currentPage !== 'home' && currentPage !== 'about' && currentPage !== 'contact' && currentPage !== 'login' && currentPage !== 'register'
                      ? (isLight ? 'text-[#ea580c] font-semibold' : 'text-[#f95721] font-semibold')
                      : (isLight ? 'text-slate-800 hover:text-[#ea580c]' : 'text-[#e7e5e4] hover:text-[#f95721]')
                  }`}
                >
                  Dashboard
                </button>
              )}
            </div>
          ) : (
            /* Public Pre-login Actions: Clean text links */
            <div className="hidden md:flex items-center gap-3 sm:gap-5 mr-1">
              <button
                type="button"
                onClick={() => setCurrentPage('home')}
                className={`text-sm font-semibold transition-colors cursor-pointer ${currentPage === 'home'
                    ? (isLight ? 'text-[#ea580c]' : 'text-[#f95721]')
                    : (isLight ? 'text-slate-800 hover:text-[#ea580c]' : 'text-[#e7e5e4] hover:text-[#f95721]')
                  }`}
              >
                Home
              </button>

              <button
                type="button"
                onClick={() => setCurrentPage('about')}
                className={`text-sm font-medium transition-colors cursor-pointer ${currentPage === 'about'
                    ? (isLight ? 'text-[#ea580c]' : 'text-[#f95721]')
                    : (isLight ? 'text-slate-800 hover:text-[#ea580c]' : 'text-[#e7e5e4] hover:text-[#f95721]')
                  }`}
              >
                About
              </button>

              <button
                type="button"
                onClick={() => setCurrentPage('contact')}
                className={`text-sm font-medium transition-colors cursor-pointer ${currentPage === 'contact'
                    ? (isLight ? 'text-[#ea580c]' : 'text-[#f95721]')
                    : (isLight ? 'text-slate-800 hover:text-[#ea580c]' : 'text-[#e7e5e4] hover:text-[#f95721]')
                  }`}
              >
                Contact
              </button>
            </div>
          )}

          {/* Light / Dark Mode Toggle Button */}
          <button
            type="button"
            onClick={toggleTheme}
            className={`w-9 h-9 rounded-lg border flex items-center justify-center transition-colors cursor-pointer shadow-sm ${isLight
                ? 'border-slate-300 bg-slate-100 hover:bg-slate-200 text-slate-700'
                : 'border-[#2e2926] bg-[#191716]/80 hover:bg-[#221f1d] text-[#e7e5e4]'
              }`}
            title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            aria-label={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          >
            {theme === 'dark' ? (
              <Sun className="w-4 h-4 text-amber-400" />
            ) : (
              <Moon className="w-4 h-4 text-indigo-500" />
            )}
          </button>

          {currentUser ? (
            /* User Avatar & Name only (No role badge like INVESTIGATOR as requested) */
            <div
              ref={dropdownRef}
              className="relative"
              onMouseEnter={handleMouseEnter}
              onMouseLeave={handleMouseLeave}
            >
              <button
                type="button"
                onClick={() => setRoleDropdownOpen(!roleDropdownOpen)}
                className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg border text-xs transition-colors cursor-pointer ${isLight
                    ? 'bg-slate-100 hover:bg-slate-200 border-slate-200 text-slate-800'
                    : 'bg-[#191716] hover:bg-[#221f1d] border-[#2e2926] text-[#e7e5e4]'
                  }`}
                title="Account Menu"
              >
                <div className="w-6 h-6 rounded-full bg-[#24130d] border border-[#ea580c]/50 flex items-center justify-center text-[11px] font-bold text-[#f95721] shrink-0">
                  {currentUser?.name.charAt(0) || 'U'}
                </div>
                <span className="font-medium text-xs sm:text-sm hidden sm:inline">{currentUser?.name.split(' ')[0]}</span>
                <ChevronDown className="w-3.5 h-3.5 text-[#78716c]" />
              </button>

              {roleDropdownOpen && (
                <div className={`absolute right-0 mt-1.5 w-72 rounded-xl shadow-2xl py-1 z-50 animate-fadeIn border ${isLight ? 'bg-white border-slate-200' : 'bg-[#181615] border-[#2e2926]'
                  }`}>
                  <div className={`px-3 py-2.5 border-b space-y-1 ${isLight ? 'border-slate-200' : 'border-[#2e2926]'
                    }`}>
                    <div className={`text-xs font-semibold ${isLight ? 'text-slate-900' : 'text-[#fafaf9]'}`}>
                      {currentUser?.name}
                    </div>
                    <div className={`text-[11px] truncate font-mono ${isLight ? 'text-slate-500' : 'text-[#a8a29e]'}`}>
                      {currentUser?.email}
                    </div>
                    <div className="flex items-center justify-between text-[10px] font-mono text-[#a8a29e] pt-1">
                      <span className="text-[#f95721] truncate max-w-[160px]">{currentUser?.department}</span>
                      {currentUser?.badgeId && (
                        <span className={`px-1.5 py-0.5 rounded border ${isLight ? 'bg-slate-100 text-slate-700 border-slate-200' : 'bg-[#221f1d] text-[#d6d3d1] border-[#332c28]'
                          }`}>
                          {currentUser.badgeId}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className={`px-3 py-2 border-b flex items-center justify-center text-[11px] font-mono ${isLight ? 'bg-slate-50 border-slate-200 text-slate-700' : 'bg-[#121110] border-[#2e2926] text-[#a8a29e]'
                    }`}>
                    <span className={`w-full text-center font-semibold uppercase tracking-wider text-[10px] px-2 py-0.5 rounded ${currentUser?.role === 'admin'
                        ? (isLight ? 'bg-red-50 text-red-700 border border-red-200' : 'bg-[#3b1219] text-[#fca5a5] border border-[#ef4444]/40')
                        : (isLight ? 'bg-orange-50 text-orange-700 border border-orange-200' : 'bg-[#2a140d] text-[#fb923c] border border-[#ea580c]/50')
                      }`}>
                      {currentUser?.role === 'admin' ? 'Administrator' : 'Investigator'}
                    </span>
                  </div>

                  <div className={`border-t mt-1 pt-1 space-y-0.5 ${isLight ? 'border-slate-200' : 'border-[#2e2926]'}`}>
                    {currentUser?.role === 'admin' ? (
                      <button
                        type="button"
                        onClick={() => {
                          if (typeof window !== 'undefined') {
                            window.location.hash = '#/admin/dashboard';
                          }
                          setCurrentPage('admin');
                          setRoleDropdownOpen(false);
                        }}
                        className={`w-full text-left px-3 py-2 text-xs text-[#f95721] hover:text-[#fb923c] flex items-center gap-2 transition-colors cursor-pointer font-medium ${isLight ? 'hover:bg-slate-100' : 'hover:bg-[#23201e]'}`}
                      >
                        <Shield className="w-3.5 h-3.5 text-[#f95721]" />
                        <span>Admin Dashboard</span>
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={() => {
                          resetToInitialScenarios();
                          setRoleDropdownOpen(false);
                        }}
                        className={`w-full text-left px-3 py-2 text-xs text-[#f95721] hover:text-[#fb923c] flex items-center gap-2 transition-colors cursor-pointer font-medium ${isLight ? 'hover:bg-slate-100' : 'hover:bg-[#23201e]'}`}
                      >
                        <RefreshCw className="w-3.5 h-3.5 text-[#f95721]" />
                        <span>Reset Case</span>
                      </button>
                    )}

                    <button
                      type="button"
                      onClick={() => {
                        setRoleDropdownOpen(false);
                        setIsEditProfileOpen(true);
                      }}
                      className={`w-full text-left px-3 py-2 text-xs flex items-center gap-2 transition-colors cursor-pointer font-medium ${
                        isLight ? 'text-slate-700 hover:bg-slate-100' : 'text-[#e7e5e4] hover:bg-[#23201e]'
                      }`}
                    >
                      <UserCog className="w-3.5 h-3.5 text-[#f95721]" />
                      <span>Edit Profile</span>
                    </button>

                    <div className={`border-t my-1 ${isLight ? 'border-slate-200' : 'border-[#2e2926]'}`} />

                    <button
                      onClick={() => {
                        setRoleDropdownOpen(false);
                        logout();
                      }}
                      className={`w-full text-left px-3 py-1.5 text-xs text-red-500 flex items-center gap-1.5 transition-colors cursor-pointer ${isLight ? 'hover:bg-red-50' : 'hover:bg-red-950/30'
                        }`}
                    >
                      <LogOut className="w-3.5 h-3.5" />
                      <span>Sign Out</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          ) : (
            /* Unauthenticated Top Navigation: Clean Log In Button */
            <div className="flex items-center ml-1">
              <button
                type="button"
                onClick={() => setCurrentPage('login')}
                className={`px-3 py-1.5 text-sm font-bold transition-colors cursor-pointer ${currentPage === 'login'
                    ? (isLight ? 'text-[#ea580c]' : 'text-[#f95721]')
                    : (isLight ? 'text-slate-900 hover:text-[#ea580c]' : 'text-white hover:text-[#f95721]')
                  }`}
                title="Log In to DCSRE Investigation Platform"
              >
                Log In
              </button>
            </div>
          )}
        </div>

      </div>

      <EditProfileModal
        isOpen={isEditProfileOpen}
        onClose={() => setIsEditProfileOpen(false)}
      />
    </header>
  );
};
