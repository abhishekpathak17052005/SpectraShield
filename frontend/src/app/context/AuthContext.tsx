import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import {
  UserProfile,
  EnterpriseRole,
  LoginResponse,
  Verify2FAResponse,
} from '../types';
import {
  loginUser,
  verify2FA,
  fetchCurrentUser,
  simulateRole,
  logoutUser,
  getAuthToken,
} from '../api';

interface AuthContextType {
  user: UserProfile | null;
  role: EnterpriseRole;
  permissions: string[];
  isAuthenticated: boolean;
  isLoading: boolean;
  isLoginModalOpen: boolean;
  isProfileDrawerOpen: boolean;
  openLoginModal: () => void;
  closeLoginModal: () => void;
  openProfileDrawer: () => void;
  closeProfileDrawer: () => void;
  login: (email: string, password: string) => Promise<LoginResponse>;
  verify2FACode: (code: string, secret?: string, tempToken?: string) => Promise<Verify2FAResponse>;
  switchRole: (newRole: EnterpriseRole) => Promise<void>;
  logout: () => Promise<void>;
  refreshProfile: () => Promise<void>;
  hasPermission: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [permissions, setPermissions] = useState<string[]>([
    "cases:read", "cases:write", "cases:assign", "cases:status",
    "analysis:execute", "sandbox:execute", "reports:generate", "audit:read"
  ]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isLoginModalOpen, setIsLoginModalOpen] = useState<boolean>(false);
  const [isProfileDrawerOpen, setIsProfileDrawerOpen] = useState<boolean>(false);

  const refreshProfile = useCallback(async () => {
    try {
      setIsLoading(true);
      const res = await fetchCurrentUser();
      if (res && res.user) {
        setUser(res.user);
        if (res.permissions) setPermissions(res.permissions);
      }
    } catch (err) {
      console.error("Failed to load user profile", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshProfile();
  }, [refreshProfile]);

  const login = async (email: string, password: string): Promise<LoginResponse> => {
    const res = await loginUser(email, password);
    if (res.status === "SUCCESS" && res.user) {
      setUser(res.user);
      if (res.permissions) setPermissions(res.permissions);
      setIsLoginModalOpen(false);
    }
    return res;
  };

  const verify2FACode = async (code: string, secret?: string, tempToken?: string): Promise<Verify2FAResponse> => {
    const res = await verify2FA(code, secret, tempToken);
    if (res.user) {
      setUser(res.user);
      if (res.permissions) setPermissions(res.permissions);
      setIsLoginModalOpen(false);
    } else {
      await refreshProfile();
    }
    return res;
  };

  const switchRole = async (newRole: EnterpriseRole) => {
    try {
      setIsLoading(true);
      const res = await simulateRole(newRole);
      if (res && res.user) {
        setUser(res.user);
        if (res.permissions) setPermissions(res.permissions);
      }
    } catch (err) {
      console.error("Failed to switch role", err);
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    try {
      await logoutUser();
      setUser(null);
      setPermissions([]);
    } catch (err) {
      console.error("Logout failed", err);
    }
  };

  const hasPermission = useCallback((permission: string): boolean => {
    if (!user) return false;
    if (user.role === 'SUPER_ADMIN') return true;
    return permissions.includes(permission);
  }, [user, permissions]);

  const activeRole: EnterpriseRole = user?.role || 'FORENSIC_ANALYST';
  const isAuthenticated = !!user && !user.is_demo_fallback;

  return (
    <AuthContext.Provider
      value={{
        user,
        role: activeRole,
        permissions,
        isAuthenticated,
        isLoading,
        isLoginModalOpen,
        isProfileDrawerOpen,
        openLoginModal: () => setIsLoginModalOpen(true),
        closeLoginModal: () => setIsLoginModalOpen(false),
        openProfileDrawer: () => setIsProfileDrawerOpen(true),
        closeProfileDrawer: () => setIsProfileDrawerOpen(false),
        login,
        verify2FACode,
        switchRole,
        logout,
        refreshProfile,
        hasPermission,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
