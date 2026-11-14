import { User } from '../types';

export interface AuthState {
  currentUser: User | null;
  token: string | null;
  isAuthenticated: boolean;
}

export const initialAuthState: AuthState = {
  currentUser: null,
  token: null,
  isAuthenticated: false
};
