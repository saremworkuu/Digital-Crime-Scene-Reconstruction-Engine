import React, { useState, useEffect } from 'react';
import {
  LayoutDashboard,
  Users,
  ShieldCheck,
  FolderLock,
  FileCheck2,
  ShieldAlert,
  Mail,
  Activity,
  Settings,
  ChevronLeft,
  ChevronRight,
  Shield,
  ExternalLink,
  Menu,
  X,
  UserCheck,
  UserCog,
  LogOut
} from 'lucide-react';
import { useApp } from '../../store';
import { messagesService } from '../../services/admin';
import { EditProfileModal } from '../../components/EditProfileModal';

interface NavItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  auditorAllowed?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'users', label: 'User Directory', icon: Users },
  { id: 'audit', label: 'Audit Trail', icon: ShieldCheck, auditorAllowed: true },
  { id: 'cases', label: 'Case Management', icon: FolderLock },
  { id: 'evidence', label: 'Forensic Vault', icon: FileCheck2 },
  { id: 'rules', label: 'Detection Rules', icon: ShieldAlert },
  { id: 'messages', label: 'Inbox', icon: Mail },
  { id: 'health', label: 'Engine Health', icon: Activity },
  { id: 'settings', label: 'Settings', icon: Settings }
];

interface AdminLayoutProps {
  activeTab: string;
  onSelectTab: (tabId: string) => void;
  onExitAdmin: () => void;
  children: React.ReactNode;
}

export const AdminLayout: React.FC<AdminLayoutProps> = ({
  activeTab,
  onSelectTab,
  onExitAdmin,
  children
}) => {
  const { currentUser, theme, logout, setCurrentPage } = useApp();
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [unreadMessages, setUnreadMessages] = useState<number>(0);
  const [isEditProfileOpen, setIsEditProfileOpen] = useState(false);

  // Poll or refresh unread messages count periodically
  useEffect(() => {
    let mounted = true;
    const fetchCount = async () => {
      try {
        const count = await messagesService.getNewMessagesCount();
        if (mounted) setUnreadMessages(count);
      } catch {
        // ignore
      }
    };
    fetchCount();
    const timer = setInterval(fetchCount, 15000);
    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, []);

  const isAuditor = (currentUser?.role as string) === 'auditor';

  // Filter navigation items: Auditors may only see Audit Log
  const visibleNavItems = NAV_ITEMS.filter((item) => {
    if (isAuditor) {
      return item.auditorAllowed === true;
    }
    return true;
  });

  return (
    <div className={`min-h-screen ${theme === 'light' ? 'bg-[#f8fafc] text-[#0f172a]' : 'bg-[#0e0d0d] text-[#e7e5e4]'} flex flex-col font-sans selection:bg-[#f95721]/30 selection:text-[#ff936b]`}>
      {/* Top Bar for Admin Console */}
      <header className={`h-14 border-b ${theme === 'light' ? 'border-slate-200 bg-white/95' : 'border-[#24201e] bg-[#121110]/95'} backdrop-blur-md sticky top-0 z-30 px-4 flex items-center justify-between`}>
        {/* Left: Mobile hamburger & Console Title */}
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className={`md:hidden p-1.5 rounded-lg cursor-pointer ${
              theme === 'light'
                ? 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                : 'text-[#a8a29e] hover:text-[#e7e5e4] hover:bg-[#1c1917]'
            }`}
            aria-label="Toggle Navigation Menu"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>

          <div className="flex items-center gap-2.5">
            <div
              className={`w-8 h-8 rounded-lg flex items-center justify-center shadow-sm ${
                theme === 'light'
                  ? 'bg-orange-50 border border-orange-200 text-[#f95721]'
                  : 'bg-[#24130d] border border-[#ea580c]/40 text-[#f95721]'
              }`}
            >
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span
                  className={`font-bold text-sm tracking-tight ${
                    theme === 'light' ? 'text-slate-900' : 'text-[#e7e5e4]'
                  }`}
                >
                  አሻራ DCSRE
                </span>
                <span className="text-[10px] font-mono uppercase px-1.5 py-0.2 rounded font-bold bg-[#f95721]/15 text-[#f95721] border border-[#f95721]/30">
                  Admin Console
                </span>
              </div>
              <p
                className={`text-[10px] hidden sm:block ${
                  theme === 'light' ? 'text-slate-500' : 'text-[#78716c]'
                }`}
              >
                Digital Forensics Engine Administration
              </p>
            </div>
          </div>
        </div>

        {/* Right: User Identity, Role Badge & Exit to Workspace */}
        <div className="flex items-center gap-3">
          {currentUser && (
            <button
              type="button"
              onClick={() => setIsEditProfileOpen(true)}
              title="Click to edit administrator profile"
              className={`hidden sm:flex items-center gap-2.5 px-3 py-1.5 rounded-lg border transition-all cursor-pointer group text-left ${
                theme === 'light'
                  ? 'bg-slate-100 hover:bg-slate-200 border-slate-200 hover:border-slate-300'
                  : 'bg-[#181615] hover:bg-[#201d1b] border-[#262220] hover:border-[#383330]'
              }`}
            >
              <div
                className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold border transition-transform group-hover:scale-105 ${
                  theme === 'light'
                    ? 'bg-orange-100 text-[#f95721] border-orange-200'
                    : 'bg-[#24130d] text-[#f95721] border-[#ea580c]/30'
                }`}
              >
                {currentUser.name ? currentUser.name.charAt(0) : 'A'}
              </div>
              <div className="text-left text-xs">
                <div
                  className={`font-medium leading-tight truncate max-w-[130px] ${
                    theme === 'light' ? 'text-slate-900' : 'text-[#e7e5e4]'
                  }`}
                >
                  {currentUser.name}
                </div>
                <div
                  className={`text-[10px] font-mono leading-tight ${
                    theme === 'light' ? 'text-slate-500' : 'text-[#78716c]'
                  }`}
                >
                  {currentUser.email}
                </div>
              </div>
              <span
                className={`text-[9px] font-mono uppercase font-bold px-1.5 py-0.5 rounded border ml-1 ${
                  theme === 'light'
                    ? currentUser.role === 'admin'
                      ? 'bg-red-50 text-red-700 border-red-200'
                      : (currentUser.role as string) === 'auditor'
                      ? 'bg-purple-50 text-purple-700 border-purple-200'
                      : 'bg-orange-50 text-orange-700 border-orange-200'
                    : currentUser.role === 'admin'
                    ? 'bg-red-950/40 text-red-400 border-red-500/40'
                    : (currentUser.role as string) === 'auditor'
                    ? 'bg-purple-950/40 text-purple-400 border-purple-500/40'
                    : 'bg-orange-950/40 text-[#f95721] border-[#ea580c]/40'
                }`}
              >
                {currentUser.role}
              </span>
              <UserCog className="w-3.5 h-3.5 text-[#f95721] opacity-75 group-hover:opacity-100 transition-opacity ml-0.5" />
            </button>
          )}

        </div>
      </header>

      {/* Main Body */}
      <div className="flex-1 flex relative">
        {/* Desktop Collapsible Sidebar */}
        <aside
          className={`hidden md:flex flex-col border-r ${
            theme === 'light' ? 'border-slate-200 bg-white' : 'border-[#24201e] bg-[#121110]'
          } transition-all duration-200 shrink-0 select-none sticky top-14 h-[calc(100vh-56px)] z-20 ${
            isCollapsed ? 'w-16' : 'w-60'
          }`}
        >
          {/* Collapse/Expand Toggle */}
          <div
            className={`p-2 flex justify-end border-b ${
              theme === 'light' ? 'border-slate-200' : 'border-[#24201e]'
            }`}
          >
            <button
              type="button"
              onClick={() => setIsCollapsed(!isCollapsed)}
              className={`p-1 rounded transition-colors cursor-pointer ${
                theme === 'light'
                  ? 'text-slate-500 hover:text-slate-900 hover:bg-slate-100'
                  : 'text-[#78716c] hover:text-[#e7e5e4] hover:bg-[#1c1917]'
              }`}
              title={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
              aria-label={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
            >
              {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
            </button>
          </div>

          {/* Navigation Links */}
          <nav className="p-2 space-y-1 flex-1 overflow-y-auto">
            {visibleNavItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              const hasBadge = item.id === 'messages' && unreadMessages > 0;

              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => onSelectTab(item.id)}
                  title={isCollapsed ? item.label : undefined}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-all cursor-pointer relative ${
                    isActive
                      ? theme === 'light'
                        ? 'bg-orange-50 text-orange-600 border border-orange-200 font-semibold shadow-sm'
                        : 'bg-[#24130d] text-[#f95721] border border-[#ea580c]/40 font-semibold shadow-sm'
                      : theme === 'light'
                      ? 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 border border-transparent'
                      : 'text-[#a8a29e] hover:bg-[#1a1816] hover:text-[#e7e5e4] border border-transparent'
                  } ${isCollapsed ? 'justify-center px-0' : ''}`}
                >
                  <Icon
                    className={`w-4 h-4 shrink-0 ${
                      isActive
                        ? theme === 'light'
                          ? 'text-orange-600'
                          : 'text-[#f95721]'
                        : theme === 'light'
                        ? 'text-slate-400'
                        : 'text-[#78716c]'
                    }`}
                  />
                  {!isCollapsed && <span className="truncate">{item.label}</span>}

                  {/* Badge Counter for Messages */}
                  {hasBadge && (
                    <span
                      className={`font-mono text-[10px] font-bold px-1.5 py-0.2 rounded-full bg-[#f95721] text-white shadow-sm ${
                        isCollapsed ? 'absolute -top-1 -right-1 px-1 text-[9px]' : 'ml-auto'
                      }`}
                    >
                      {unreadMessages}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Sidebar Bottom Actions (Vertically stacked, no boxes, no icons) */}
          <div
            className={`p-3 border-t flex flex-col gap-1.5 ${
              theme === 'light' ? 'border-slate-200' : 'border-[#24201e]'
            }`}
          >
            <button
              type="button"
              onClick={() => setIsEditProfileOpen(true)}
              className={`text-left text-xs font-medium transition-colors cursor-pointer py-1 px-2 ${
                theme === 'light'
                  ? 'text-slate-600 hover:text-[#ea580c]'
                  : 'text-[#a8a29e] hover:text-[#f95721]'
              } ${isCollapsed ? 'text-center px-0' : ''}`}
              title="Edit Profile"
            >
              {isCollapsed ? 'Profile' : 'Edit Profile'}
            </button>

            <button
              type="button"
              onClick={() => {
                if (typeof window !== 'undefined') window.location.hash = '';
                setCurrentPage('home');
              }}
              className={`text-left text-xs font-medium transition-colors cursor-pointer py-1 px-2 ${
                theme === 'light'
                  ? 'text-slate-600 hover:text-[#ea580c]'
                  : 'text-[#a8a29e] hover:text-[#f95721]'
              } ${isCollapsed ? 'text-center px-0' : ''}`}
              title="Public Site"
            >
              {isCollapsed ? 'Site' : 'Public Site'}
            </button>

            <button
              type="button"
              onClick={logout}
              className={`text-left text-xs font-medium transition-colors cursor-pointer py-1 px-2 ${
                theme === 'light'
                  ? 'text-red-600 hover:text-red-700'
                  : 'text-red-400 hover:text-red-300'
              } ${isCollapsed ? 'text-center px-0' : ''}`}
              title="Sign Out"
            >
              {isCollapsed ? 'Exit' : 'Sign Out'}
            </button>
          </div>
        </aside>

        {/* Mobile Slide-over Drawer */}
        {mobileMenuOpen && (
          <div className="md:hidden fixed inset-0 z-50 flex">
            <div
              className={`fixed inset-0 backdrop-blur-sm ${
                theme === 'light' ? 'bg-slate-900/40' : 'bg-black/70'
              }`}
              onClick={() => setMobileMenuOpen(false)}
            />
            <div
              className={`relative flex flex-col w-64 h-full border-r p-4 shadow-2xl z-10 space-y-4 ${
                theme === 'light'
                  ? 'bg-white border-slate-200 text-slate-900'
                  : 'bg-[#121110] border-[#24201e]'
              }`}
            >
              <div
                className={`flex items-center justify-between pb-3 border-b ${
                  theme === 'light' ? 'border-slate-200' : 'border-[#24201e]'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-[#f95721]" />
                  <span
                    className={`font-bold text-sm ${
                      theme === 'light' ? 'text-slate-900' : 'text-[#e7e5e4]'
                    }`}
                  >
                    አሻራ Admin
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setMobileMenuOpen(false)}
                  className={`p-1 ${
                    theme === 'light' ? 'text-slate-400 hover:text-slate-700' : 'text-[#78716c] hover:text-[#e7e5e4]'
                  }`}
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <nav className="space-y-1">
                {visibleNavItems.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.id;
                  const hasBadge = item.id === 'messages' && unreadMessages > 0;

                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        onSelectTab(item.id);
                        setMobileMenuOpen(false);
                      }}
                      className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                        isActive
                          ? theme === 'light'
                            ? 'bg-orange-50 text-orange-600 border border-orange-200 font-semibold'
                            : 'bg-[#24130d] text-[#f95721] border border-[#ea580c]/40 font-semibold'
                          : theme === 'light'
                          ? 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                          : 'text-[#a8a29e] hover:bg-[#1a1816] hover:text-[#e7e5e4]'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <Icon className="w-4 h-4" />
                        <span>{item.label}</span>
                      </div>
                      {hasBadge && (
                        <span className="font-mono text-[10px] font-bold px-1.5 py-0.2 rounded-full bg-[#f95721] text-white">
                          {unreadMessages}
                        </span>
                      )}
                    </button>
                  );
                })}
              </nav>

              {/* Mobile Drawer Bottom Actions */}
              <div
                className={`pt-4 border-t flex flex-col gap-2 ${
                  theme === 'light' ? 'border-slate-200' : 'border-[#24201e]'
                }`}
              >
                <button
                  type="button"
                  onClick={() => {
                    setMobileMenuOpen(false);
                    setIsEditProfileOpen(true);
                  }}
                  className={`text-left text-xs font-medium transition-colors cursor-pointer py-1.5 px-2 ${
                    theme === 'light'
                      ? 'text-slate-600 hover:text-[#ea580c]'
                      : 'text-[#a8a29e] hover:text-[#f95721]'
                  }`}
                >
                  Edit Profile
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setMobileMenuOpen(false);
                    if (typeof window !== 'undefined') window.location.hash = '';
                    setCurrentPage('home');
                  }}
                  className={`text-left text-xs font-medium transition-colors cursor-pointer py-1.5 px-2 ${
                    theme === 'light'
                      ? 'text-slate-600 hover:text-[#ea580c]'
                      : 'text-[#a8a29e] hover:text-[#f95721]'
                  }`}
                >
                  Public Site
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setMobileMenuOpen(false);
                    logout();
                  }}
                  className={`text-left text-xs font-medium transition-colors cursor-pointer py-1.5 px-2 ${
                    theme === 'light'
                      ? 'text-red-600 hover:text-red-700'
                      : 'text-red-400 hover:text-red-300'
                  }`}
                >
                  Sign Out
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Main Content Area */}
        <main className="flex-1 min-w-0 p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto w-full">
          {children}
        </main>
      </div>

      <EditProfileModal
        isOpen={isEditProfileOpen}
        onClose={() => setIsEditProfileOpen(false)}
      />
    </div>
  );
};
