/**
 * Digital Crime Scene Reconstruction Engine (DCSRE)
 * Forensic Investigation Platform with 3D Cyber Threat Visualizer
 */

import React, { useState, useEffect } from 'react';
import { AppProvider, useApp } from './store';
import { TopNav } from './components/TopNav';
import { SidebarNav } from './components/SidebarNav';
import { Forensic3DBackdrop } from './components/Forensic3DBackdrop';
import { Dashboard } from './pages/Dashboard';
import { Cases } from './pages/Cases';
import { CaseDetail } from './pages/CaseDetail';
import { Evidence } from './pages/Evidence';
import { Timeline } from './pages/Timeline';
import { AttackGraph } from './pages/AttackGraph';
import { AttackPath } from './pages/AttackPath';
import { Detections } from './pages/Detections';
import { Reports } from './pages/Reports';
import { AuditLog } from './pages/AuditLog';
import { About } from './pages/About';
import { Contact } from './pages/Contact';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Home } from './pages/Home';
import { AdminApp } from './admin/AdminApp';
import { ToastContainer } from './components/Toast';
import { Shield, X } from 'lucide-react';

const MainLayout: React.FC = () => {
  const { currentUser, currentPage, setCurrentPage, logout, theme } = useApp();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [isAdminRoute, setIsAdminRoute] = useState(() => {
    if (typeof window === 'undefined') return false;
    return (
      window.location.pathname.startsWith('/admin') ||
      window.location.hash.startsWith('#/admin')
    );
  });

  // Track browser location hash or pathname changes for /admin routing
  useEffect(() => {
    const checkAdmin = () => {
      setIsAdminRoute(
        window.location.pathname.startsWith('/admin') ||
        window.location.hash.startsWith('#/admin')
      );
    };
    window.addEventListener('hashchange', checkAdmin);
    window.addEventListener('popstate', checkAdmin);
    return () => {
      window.removeEventListener('hashchange', checkAdmin);
      window.removeEventListener('popstate', checkAdmin);
    };
  }, []);

  // Guarantee every page transition starts cleanly from the top of the viewport
  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    document.documentElement.scrollTop = 0;
    document.body.scrollTop = 0;
  }, [currentPage, isAdminRoute]);

  // Role-based route boundaries & access control
  const isPublicPage = currentPage === 'home' || currentPage === 'about' || currentPage === 'contact';
  const isAdmin = currentUser?.role === 'admin';

  // Dedicated route for /admin/*:
  // If an Admin is authenticated and not explicitly viewing public informational pages,
  // they are strictly contained within the Admin Console and never redirected to investigator pages.
  if (isAdminRoute || currentPage === 'admin' || (isAdmin && !isPublicPage)) {
    return (
      <div className={`min-h-screen ${theme === 'light' ? 'bg-[#f8fafc] text-[#0f172a]' : 'bg-[#0e0d0d] text-[#e7e5e4]'} relative overflow-x-hidden`}>
        <AdminApp />
        <ToastContainer />
      </div>
    );
  }

  const renderPage = () => {
    // Unauthenticated visitors can ONLY view Home, About, Contact, and auth pages (Login, Register)
    if (!currentUser) {
      if (currentPage === 'home') {
        return <Home />;
      }
      if (currentPage === 'about') {
        return <About />;
      }
      if (currentPage === 'contact') {
        return <Contact />;
      }
      if (currentPage === 'login') {
        return <Login />;
      }
      if (currentPage === 'register') {
        return <Register />;
      }
      // Any other page or functionality is restricted; fallback to Home
      return <Home />;
    }

    switch (currentPage) {
      case 'home':
        return <Home />;
      case 'dashboard':
        return <Dashboard />;
      case 'cases':
        return <Cases />;
      case 'case_detail':
        return <CaseDetail />;
      case 'evidence':
        return <Evidence />;
      case 'timeline':
        return <Timeline />;
      case 'attack_graph':
        return <AttackGraph />;
      case 'attack_path':
        return <AttackPath />;
      case 'detections':
        return <Detections />;
      case 'reports':
        return <Reports />;
      case 'audit_log':
        return <AuditLog />;
      case 'login':
        return <Login />;
      case 'register':
        return <Register />;
      case 'about':
        return <About />;
      case 'contact':
        return <Contact />;
      default:
        return currentUser.role === 'admin' ? <Dashboard /> : <Cases />;
    }
  };

  const isAuthPage = !currentUser || currentPage === 'home' || currentPage === 'about' || currentPage === 'contact' || currentPage === 'login' || currentPage === 'register';
  const isSplitScreenPage = currentPage === 'login' || currentPage === 'register' || currentPage === 'contact';

  return (
    <div className={`min-h-screen pt-[61px] ${theme === 'light' ? 'bg-[#f8fafc] text-[#0f172a]' : 'bg-[#0e0d0d] text-[#e7e5e4]'} flex flex-col font-sans selection:bg-[#f95721]/30 selection:text-[#ff936b] relative overflow-x-hidden transition-colors duration-200`}>
      {/* Subtle Interactive 3D Three.js Ambient Particle Constellation */}
      <Forensic3DBackdrop />

      {/* Top Bar (3-Zone Contract with Warm Charcoal & Burnt Orange Palette) */}
      <TopNav
        onToggleMobileMenu={() => setMobileMenuOpen(!mobileMenuOpen)}
        mobileMenuOpen={mobileMenuOpen}
      />

      {/* Global Toastify Notification Layer */}
      <ToastContainer />

      {/* Mobile Slide-over Drawer for Investigator Sidebar */}
      {!isAuthPage && mobileMenuOpen && (
        <div className="lg:hidden fixed top-[57px] sm:top-[61px] bottom-0 left-0 right-0 z-40 flex">
          {/* Backdrop */}
          <div
            className="fixed inset-0 top-[57px] sm:top-[61px] bg-black/70 backdrop-blur-sm z-10 transition-opacity cursor-pointer"
            onClick={() => setMobileMenuOpen(false)}
          />
          {/* Sidebar panel */}
          <div className={`relative z-20 flex flex-col w-52 sm:w-56 max-w-[65vw] h-full shadow-2xl animate-fadeIn ${theme === 'light' ? 'bg-white border-r border-slate-200' : 'bg-[#121110] border-r border-[#24201e]'}`}>
            <div
              onClick={() => setMobileMenuOpen(false)}
              className="h-full overflow-y-auto"
            >
              <SidebarNav className="h-full border-r-0 w-full" />
            </div>
          </div>
        </div>
      )}

      {/* Mobile Slide-over Drawer for Public Pages (Home, About, Contact, Login, Register) */}
      {isAuthPage && mobileMenuOpen && (
        <div className="md:hidden fixed top-[57px] sm:top-[61px] bottom-0 left-0 right-0 z-40 flex">
          {/* Backdrop */}
          <div
            className="fixed inset-0 top-[57px] sm:top-[61px] bg-black/70 backdrop-blur-sm z-10 transition-opacity cursor-pointer"
            onClick={() => setMobileMenuOpen(false)}
          />
          {/* Drawer panel */}
          <div className={`relative z-20 flex flex-col w-52 sm:w-56 max-w-[65vw] h-full shadow-2xl animate-fadeIn ${theme === 'light' ? 'bg-white border-r border-slate-200 text-slate-800' : 'bg-[#121110] border-r border-[#24201e] text-[#e7e5e4]'}`}>
            {/* Navigation Header */}
            <div className={`px-3 py-2 text-[10px] font-mono tracking-wider uppercase font-semibold flex items-center justify-between border-b ${theme === 'light' ? 'border-slate-200 text-slate-500 bg-slate-50' : 'border-[#24201e] text-[#a8a29e] bg-[#161413]'}`}>
              <span>Navigation</span>
              <span className="text-[9px] font-mono text-[#f95721] lowercase">menu</span>
            </div>

            {/* Navigation Links */}
            <div className="flex-1 overflow-y-auto p-2.5 space-y-1">
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setCurrentPage('home');
                  setMobileMenuOpen(false);
                }}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-left text-sm font-medium transition-all cursor-pointer ${
                  currentPage === 'home'
                    ? theme === 'light'
                      ? 'bg-[#ea580c]/10 text-[#ea580c] font-bold border border-[#ea580c]/30'
                      : 'bg-[#221712] text-[#f95721] font-bold border border-[#ea580c]/50'
                    : theme === 'light'
                    ? 'text-slate-700 hover:bg-slate-100'
                    : 'text-[#e7e5e4] hover:bg-[#1a1816]'
                }`}
              >
                <span>Home</span>
                {currentPage === 'home' && <span className="text-[10px] text-[#f95721] font-mono">●</span>}
              </button>

              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setCurrentPage('about');
                  setMobileMenuOpen(false);
                }}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-left text-sm font-medium transition-all cursor-pointer ${
                  currentPage === 'about'
                    ? theme === 'light'
                      ? 'bg-[#ea580c]/10 text-[#ea580c] font-bold border border-[#ea580c]/30'
                      : 'bg-[#221712] text-[#f95721] font-bold border border-[#ea580c]/50'
                    : theme === 'light'
                    ? 'text-slate-700 hover:bg-slate-100'
                    : 'text-[#e7e5e4] hover:bg-[#1a1816]'
                }`}
              >
                <span>About</span>
                {currentPage === 'about' && <span className="text-[10px] text-[#f95721] font-mono">●</span>}
              </button>

              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setCurrentPage('contact');
                  setMobileMenuOpen(false);
                }}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-left text-sm font-medium transition-all cursor-pointer ${
                  currentPage === 'contact'
                    ? theme === 'light'
                      ? 'bg-[#ea580c]/10 text-[#ea580c] font-bold border border-[#ea580c]/30'
                      : 'bg-[#221712] text-[#f95721] font-bold border border-[#ea580c]/50'
                    : theme === 'light'
                    ? 'text-slate-700 hover:bg-slate-100'
                    : 'text-[#e7e5e4] hover:bg-[#1a1816]'
                }`}
              >
                <span>Contact</span>
                {currentPage === 'contact' && <span className="text-[10px] text-[#f95721] font-mono">●</span>}
              </button>

              {currentUser && (
                <div className="pt-2">
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      if (currentUser.role === 'admin') {
                        if (typeof window !== 'undefined') window.location.hash = '#/admin/dashboard';
                        setCurrentPage('admin');
                      } else {
                        if (typeof window !== 'undefined') window.location.hash = '';
                        setCurrentPage('dashboard');
                      }
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-left text-xs font-semibold transition-all cursor-pointer ${
                      theme === 'light'
                        ? 'bg-orange-50 text-orange-700 border border-orange-200'
                        : 'bg-[#24130d] text-[#f95721] border border-[#ea580c]/40'
                    }`}
                  >
                    <span>{currentUser.role === 'admin' ? 'Admin Dashboard' : 'Investigator Console'}</span>
                    <span className="text-[10px] font-mono uppercase font-bold">&rarr;</span>
                  </button>
                </div>
              )}
            </div>

            {/* Drawer Bottom Actions */}
            <div className={`p-3 border-t space-y-2 ${theme === 'light' ? 'border-slate-200 bg-slate-50' : 'border-[#24201e] bg-[#171514]'}`}>
              {!currentUser ? (
                <div className="space-y-2">
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setCurrentPage('login');
                      setMobileMenuOpen(false);
                    }}
                    className="w-full py-2 px-3 rounded-xl bg-[#f95721] hover:bg-[#ea580c] text-white text-xs font-bold text-center transition-all shadow-md cursor-pointer"
                  >
                    Log In to Platform
                  </button>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setCurrentPage('register');
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full py-1.5 px-3 rounded-xl text-xs text-center border font-medium cursor-pointer transition-colors ${
                      theme === 'light'
                        ? 'border-slate-300 text-slate-700 hover:bg-slate-100'
                        : 'border-[#2e2926] text-[#d6d3d1] hover:bg-[#1f1b19]'
                    }`}
                  >
                    Register New Account
                  </button>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <div className="w-7 h-7 rounded-full bg-[#24130d] border border-[#ea580c]/50 flex items-center justify-center text-xs font-bold text-[#f95721] shrink-0">
                    {currentUser.name.charAt(0)}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-xs font-semibold truncate text-[#fafaf9]">{currentUser.name}</div>
                    <div className="text-[9px] font-mono text-[#a8a29e] truncate">{currentUser.email}</div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Main Body with Vertical Navigation Sidebar */}
      <div className="flex-1 flex w-full relative z-10">
        {/* Desktop Vertical Sidebar matching Image 2 */}
        {!isAuthPage && (
          <div className="hidden lg:block shrink-0 sticky top-[61px] h-[calc(100vh-61px)] overflow-y-auto z-20">
            <SidebarNav className="h-full" />
          </div>
        )}

        {/* Main Content Area */}
        <main className={`flex-1 min-w-0 w-full ${isSplitScreenPage ? 'p-0 max-w-none' : 'max-w-7xl mx-auto px-4 sm:px-6 py-6'}`}>
          {renderPage()}
        </main>
      </div>

      {/* Footer */}
      <footer className={`no-print border-t ${theme === 'light' ? 'border-[#e4e4e7] bg-[#ffffff]/90 text-[#71717a]' : 'border-[#25201e] bg-[#12100f]/90 text-[#78716c]'} backdrop-blur-md px-6 py-3 text-xs font-mono relative z-10 transition-colors duration-200`}>
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Shield className="w-3.5 h-3.5 text-[#f95721]" />
            <span className={`${theme === 'light' ? 'text-[#3f3f46]' : 'text-[#a8a29e]'} font-medium`}>አሻራ</span>
            <span className="text-[11px] text-[#78716c]">· Digital Crime Scene Reconstruction Engine</span>
          </div>
          <div className="text-[10px] text-[#78716c]">
            <a
              href="https://www.flaticon.com/free-icons/finger-print"
              target="_blank"
              rel="noopener noreferrer"
              title="finger print icons"
              className="hover:text-[#f95721] transition-colors"
            >
              Finger print icons created by sonnycandra - Flaticon
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default function App() {
  return (
    <AppProvider>
      <MainLayout />
    </AppProvider>
  );
}
