import { Navigate } from 'react-router-dom'
import { ReactNode } from 'react'

export default function ProtectedRoute({ children }: { children: ReactNode }) {
  const isAuthenticated = localStorage.getItem('dcsre_auth') === 'true'

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}
