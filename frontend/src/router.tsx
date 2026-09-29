import { createBrowserRouter } from 'react-router-dom'
import AppShell from './components/layout/AppShell'
import ProtectedRoute from './components/layout/ProtectedRoute'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Cases from './pages/Cases'
import CaseDetail from './pages/CaseDetail'
import Evidence from './pages/Evidence'
import Timeline from './pages/Timeline'
import AttackGraph from './pages/AttackGraph'
import Detections from './pages/Detections'
import Reports from './pages/Reports'
import AuditLog from './pages/AuditLog'
import Users from './pages/Users'
import NotFound from './pages/NotFound'

const router = createBrowserRouter([
  {
    path: '/login',
    element: <Login />,
  },
  {
    path: '/',
    element: (
      <ProtectedRoute>
        <AppShell />
      </ProtectedRoute>
    ),
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'cases', element: <Cases /> },
      { path: 'cases/:id', element: <CaseDetail /> },
      { path: 'evidence', element: <Evidence /> },
      { path: 'timeline', element: <Timeline /> },
      { path: 'attack-graph', element: <AttackGraph /> },
      { path: 'detections', element: <Detections /> },
      { path: 'reports', element: <Reports /> },
      { path: 'audit-log', element: <AuditLog /> },
      { path: 'users', element: <Users /> },
    ],
  },
  {
    path: '*',
    element: <NotFound />,
  },
])

export default router
