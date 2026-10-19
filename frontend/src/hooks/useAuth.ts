import { useApp } from '../store';

export function useAuth() {
  const { users, currentUser, registerUser, loginUser, logout, switchRole } = useApp();
  return {
    currentUser,
    userRole: currentUser?.role || 'investigator',
    users,
    registerUser,
    loginUser,
    logout,
    switchRole,
    isAuthenticated: !!currentUser
  };
}
