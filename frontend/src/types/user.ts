export type UserRole = 'admin' | 'investigator';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  department?: string;
  avatar?: string;
  active?: boolean;
  created_at?: string;
  createdAt?: string;
  badgeId?: string;
  badge_id?: string;
  password?: string;
  pgpKey?: string;
}
