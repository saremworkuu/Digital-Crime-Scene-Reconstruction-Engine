import React, { ReactNode } from 'react';
import { useStore } from '../../store';
import { Login } from '../../pages/Login';

interface ProtectedRouteProps {
  children: ReactNode;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const { state } = useStore();
  if (!state.currentUser) {
    return <Login />;
  }
  return <>{children}</>;
};
