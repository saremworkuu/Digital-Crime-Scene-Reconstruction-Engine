/**
 * Digital Crime Scene Reconstruction Engine (DCSRE)
 * Forensic Investigation Platform with 3D Cyber Threat Visualizer
 */

import React, { useState } from 'react';
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
import { AdminLogin } from './pages/AdminLogin';
import { Register } from './pages/Register';
import { Home } from './pages/Home';
import { Shield, X } from 'lucide-react';
import { ToastContainer } from './components/Toast';

const MainLayout: React.FC = () => {
  const { currentUser, currentPage, theme } = useApp();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const renderPage = () => {
    // Unauthenticated visitors can ONLY view Home, About, Contact, and auth pages (Login, AdminLogin, Register)
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
      if (currentPage === 'admin_login') {
        return <AdminLogin />;
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
      case 'admin_login':
        return <AdminLogin />;
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

  const isAuthPage = !currentUser || currentPage === 'home' || currentPage === 'about' || currentPage === 'contact' || currentPage === 'login' || currentPage === 'admin_login' || currentPage === 'register';

  return (
    <div className={`min-h-screen pt-[61px] ${theme === 'light' ? 'bg-[#f8fafc] text-[#0f172a]' : 'bg-[#0e0d0d] text-[#e7e5e4]'} flex flex-col font-sans selection:bg-[#f95721]/30 selection:text-[#ff936b] relative overflow-x-hidden transition-colors duration-200`}>
      {/* Subtle Interactive 3D Three.js Ambient Particle Constellation */}
      <Forensic3DBackdrop />

      {/* Top Bar (3-Zone Contract with Warm Charcoal & Burnt Orange Palette) */}
      <TopNav
        onToggleMobileMenu={() => setMobileMenuOpen(!mobileMenuOpen)}
        mobileMenuOpen={mobileMenuOpen}
      />

      {/* Main Body with Vertical Navigation Sidebar */}
      <div className="flex-1 flex w-full relative z-10">
        {/* Desktop Vertical Sidebar matching Image 2 */}
        {!isAuthPage && (
          <div className="hidden lg:block shrink-0 sticky top-[61px] h-[calc(100vh-61px)] overflow-y-auto z-20">
            <SidebarNav className="h-full" />
          </div>
        )}

        {/* Mobile Slide-over Drawer for Sidebar */}
        {!isAuthPage && mobileMenuOpen && (
          <div className="lg:hidden fixed inset-0 z-50 flex">
            {/* Backdrop */}
            <div
              className="fixed inset-0 bg-black/70 backdrop-blur-sm transition-opacity"
              onClick={() => setMobileMenuOpen(false)}
            />
            {/* Sidebar panel */}
            <div className={`relative flex flex-col w-auto h-full shadow-2xl animate-fadeIn ${theme === 'light' ? 'bg-white border-r border-slate-200' : 'bg-[#121110]'}`}>
              <div className={`flex justify-end p-2 border-b ${theme === 'light' ? 'border-slate-200' : 'border-[#24201e]'}`}>
                <button
                  type="button"
                  onClick={() => setMobileMenuOpen(false)}
                  className={`p-1.5 rounded-lg ${theme === 'light' ? 'bg-orange-50 text-orange-600 border border-orange-200 hover:bg-orange-100' : 'bg-[#24130d] text-[#f95721] border border-[#ea580c]/40 hover:bg-[#34170f]'} cursor-pointer`}
                  aria-label="Close menu"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div onClick={() => setMobileMenuOpen(false)} className="h-full">
                <SidebarNav className="h-full border-r-0" />
              </div>
            </div>
          </div>
        )}

        {/* Main Content Area */}
        <main className="flex-1 min-w-0 max-w-7xl mx-auto px-4 sm:px-6 py-6 w-full">
          {renderPage()}
        </main>
      </div>

      {/* Footer */}
      <footer className={`no-print border-t ${theme === 'light' ? 'border-[#e4e4e7] bg-[#ffffff]/90 text-[#71717a]' : 'border-[#25201e] bg-[#12100f]/90 text-[#78716c]'} backdrop-blur-md px-6 py-3 text-xs font-mono relative z-10 transition-colors duration-200`}>
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-3.5 h-3.5 text-[#f95721]" />
            <span className={`${theme === 'light' ? 'text-[#3f3f46]' : 'text-[#a8a29e]'} font-medium`}>አሻራ</span>
          </div>
          <span className="text-[11px] text-[#78716c]">አሻራ - Digital Crime Scene Reconstruction Engine</span>
        </div>
      </footer>
    </div>
  );
};

export default function App() {
  return (
    <AppProvider>
      <MainLayout />
      <ToastContainer />
    </AppProvider>
  );
}
