import React from 'react';
import { useStore } from './store';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Home } from './pages/Home';
import { About } from './pages/About';
import { Contact } from './pages/Contact';
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
import { NotFound } from './pages/NotFound';

export const AppRouter: React.FC = () => {
  const { state } = useStore();

  if (!state.currentUser) {
    if (state.activeTab === 'home') {
      return <Home />;
    }
    if (state.activeTab === 'about') {
      return <About />;
    }
    if (state.activeTab === 'contact') {
      return <Contact />;
    }
    if (state.activeTab === 'register') {
      return <Register />;
    }
    if (state.activeTab === 'login') {
      return <Login />;
    }
    return <Home />;
  }

  switch (state.activeTab) {
    case 'home':
      return <Home />;
    case 'about':
      return <About />;
    case 'contact':
      return <Contact />;
    case 'dashboard':
      return <Dashboard />;
    case 'cases':
      return <Cases />;
    case 'case-detail':
      return <CaseDetail />;
    case 'evidence':
      return <Evidence />;
    case 'timeline':
      return <Timeline />;
    case 'graph':
      return <AttackGraph />;
    case 'attack_path':
      return <AttackPath />;
    case 'detections':
      return <Detections />;
    case 'reports':
      return <Reports />;
    case 'audit':
      return <AuditLog />;
    case 'login':
      return <Login />;
    case 'register':
      return <Register />;
    default:
      return <NotFound />;
  }
};
