import React, { useState, useEffect, useCallback } from 'react';
import { AuthContext, AuthContextType } from '../contexts/AuthContext';
import { AuthUser, getCurrentUser, login as apiLogin, logout as apiLogout, register as apiRegister } from '../services/apiService';

interface AuthProviderProps {
  children: React.ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Check session on mount
  const checkSession = useCallback(async () => {
    try {
      setIsLoading(true);
      const response = await getCurrentUser();
      if (response.success && response.data) {
        setUser(response.data);
      } else {
        setUser(null);
      }
    } catch (err) {
      console.error('[AuthProvider] Session check failed:', err);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkSession();
  }, [checkSession]);

  const login = useCallback(async (username: string, password: string) => {
    setError(null);
    setIsLoading(true);
    try {
      const response = await apiLogin(username, password);
      if (response.success && response.data) {
        setUser(response.data);
      } else {
        setError(response.error || 'Login failed');
        throw new Error(response.error || 'Login failed');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Login failed';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const register = useCallback(async (username: string, password: string, role: string) => {
    setError(null);
    setIsLoading(true);
    try {
      const response = await apiRegister(username, password, role);
      if (response.success && response.data) {
        setUser(response.data);
      } else {
        setError(response.error || 'Registration failed');
        throw new Error(response.error || 'Registration failed');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Registration failed';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    setError(null);
    try {
      await apiLogout();
      setUser(null);
    } catch (err) {
      console.error('[AuthProvider] Logout error:', err);
      // Clear user anyway
      setUser(null);
    }
  }, []);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const value: AuthContextType = {
    user,
    isLoading,
    error,
    login,
    logout,
    register,
    clearError,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}
