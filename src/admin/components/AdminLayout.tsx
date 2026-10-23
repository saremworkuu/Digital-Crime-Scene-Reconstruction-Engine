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
  LogOut
} from 'lucide-react';
import { useApp } from '../../store';
import { messagesService } from '../../services/admin';

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
  { id: 'messages', label: 'Inquiries & Inbox', icon: Mail },
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
            className="md:hidden p-1.5 rounded-lg text-[#a8a29e] hover:text-[#e7e5e4] hover:bg-[#1c1917] cursor-pointer"
            aria-label="Toggle Navigation Menu"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>

          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-[#24130d] border border-[#ea580c]/40 flex items-center justify-center text-[#f95721] shadow-sm">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm tracking-tight text-[#e7e5e4]">አሻራ DCSRE</span>
                <span className="text-[10px] font-mono uppercase px-1.5 py-0.2 rounded font-bold bg-[#f95721]/15 text-[#f95721] border border-[#f95721]/30">
                  Admin Console
                </span>
              </div>
              <p className="text-[10px] text-[#78716c] hidden sm:block">Digital Forensics Engine Administration</p>
            </div>
          </div>
        </div>

        {/* Right: User Identity, Role Badge & Exit to Workspace */}
        <div className="flex items-center gap-3">
          {currentUser && (
            <div className="hidden sm:flex items-center gap-2.5 px-3 py-1 rounded-lg bg-[#181615] border border-[#262220]">
              <div className="w-6 h-6 rounded-full bg-[#24130d] text-[#f95721] flex items-center justify-center text-xs font-bold border border-[#ea580c]/30">
                {currentUser.name ? currentUser.name.charAt(0) : 'A'}
              </div>
              <div className="text-left text-xs">
                <div className="font-medium text-[#e7e5e4] leading-tight truncate max-w-[130px]">{currentUser.name}</div>
                <div className="text-[10px] text-[#78716c] font-mono leading-tight">{currentUser.email}</div>
              </div>
              <span
                className={`text-[9px] font-mono uppercase font-bold px-1.5 py-0.5 rounded border ml-1 ${
                  currentUser.role === 'admin'
                    ? 'bg-red-950/40 text-red-400 border-red-500/40'
                    : (currentUser.role as string) === 'auditor'
                    ? 'bg-purple-950/40 text-purple-400 border-purple-500/40'
                    : 'bg-orange-950/40 text-[#f95721] border-[#ea580c]/40'
                }`}
              >
                {currentUser.role}
              </span>
            </div>
          )}

          <button
            type="button"
            onClick={() => {
              if (typeof window !== 'undefined') window.location.hash = '';
              setCurrentPage('home');
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-[#1c1917] hover:bg-[#25201e] text-[#d6d3d1] hover:text-white border border-[#332c28] transition-colors cursor-pointer"
            title="View Public Portal"
          >
            <span>Public Site</span>
            <ExternalLink className="w-3.5 h-3.5 text-[#f95721]" />
          </button>

          <button
            type="button"
            onClick={logout}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-red-950/40 hover:bg-red-900/60 text-red-400 border border-red-500/30 transition-colors cursor-pointer"
            title="Sign Out of Admin Console"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Sign Out</span>
          </button>
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
          <div className="p-2 flex justify-end border-b border-[#24201e]">
            <button
              type="button"
              onClick={() => setIsCollapsed(!isCollapsed)}
              className="p-1 rounded text-[#78716c] hover:text-[#e7e5e4] hover:bg-[#1c1917] transition-colors cursor-pointer"
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
                      ? 'bg-[#24130d] text-[#f95721] border border-[#ea580c]/40 font-semibold shadow-sm'
                      : 'text-[#a8a29e] hover:bg-[#1a1816] hover:text-[#e7e5e4] border border-transparent'
                  } ${isCollapsed ? 'justify-center px-0' : ''}`}
                >
                  <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-[#f95721]' : 'text-[#78716c]'}`} />
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

          {/* Sidebar Footer */}
          {!isCollapsed && (
            <div className="p-3 border-t border-[#24201e] text-[10px] font-mono text-[#78716c] text-center">
              DCSRE Admin v2.4 (Mock Mode)
            </div>
          )}
        </aside>

        {/* Mobile Slide-over Drawer */}
        {mobileMenuOpen && (
          <div className="md:hidden fixed inset-0 z-50 flex">
            <div
              className="fixed inset-0 bg-black/70 backdrop-blur-sm"
              onClick={() => setMobileMenuOpen(false)}
            />
            <div className="relative flex flex-col w-64 h-full bg-[#121110] border-r border-[#24201e] p-4 shadow-2xl z-10 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-[#24201e]">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-[#f95721]" />
                  <span className="font-bold text-sm text-[#e7e5e4]">አሻራ Admin</span>
                </div>
                <button
                  type="button"
                  onClick={() => setMobileMenuOpen(false)}
                  className="p-1 text-[#78716c] hover:text-[#e7e5e4]"
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
                          ? 'bg-[#24130d] text-[#f95721] border border-[#ea580c]/40 font-semibold'
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
            </div>
          </div>
        )}

        {/* Main Content Area */}
        <main className="flex-1 min-w-0 p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto w-full">
          {children}
        </main>
      </div>
    </div>
  );
};
