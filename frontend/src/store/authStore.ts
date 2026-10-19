import { User } from '../types';

export interface AuthState {
  currentUser: User | null;
  token: string | null;
  isAuthenticated: boolean;
}

export const initialAuthState: AuthState = {
  currentUser: {
    id: 'usr-sarah',
    name: 'Sarah Chen',
    email: 'investigator@dcsre.corp',
    role: 'investigator',
    department: 'Digital Forensics',
    active: true
  },
  token: 'mock-jwt-token-investigator-2026',
  isAuthenticated: true
};
