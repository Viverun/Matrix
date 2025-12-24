'use client';

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useRouter } from 'next/navigation';

interface User {
    id: number;
    email: string;
    username: string;
    full_name: string | null;
    company: string | null;
}

interface AuthContextType {
    user: User | null;
    token: string | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    login: (email: string, password: string) => Promise<void>;
    register: (email: string, username: string, password: string, fullName?: string, company?: string) => Promise<void>;
    logout: () => void;
    error: string | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export function AuthProvider({ children }: { children: ReactNode }) {
    const [user, setUser] = useState<User | null>(null);
    const [token, setToken] = useState<string | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const router = useRouter();

    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        setMounted(true);
        
        // Check for stored token on mount
        try {
            const storedToken = localStorage.getItem('matrix_token');
            const storedUser = localStorage.getItem('matrix_user');

            console.log('[Auth] Initializing...', { hasToken: !!storedToken, hasUser: !!storedUser });

            if (storedToken && storedUser) {
                const parsedUser = JSON.parse(storedUser);
                setToken(storedToken);
                setUser(parsedUser);
                console.log('[Auth] Session restored', parsedUser.username);
            }
        } catch (e) {
            console.error('[Auth] Failed to restore session', e);
            localStorage.removeItem('matrix_token');
            localStorage.removeItem('matrix_user');
        } finally {
            // Always set loading to false after checking
            setIsLoading(false);
            console.log('[Auth] Loading complete');
        }
    }, []);

    const login = async (email: string, password: string) => {
        setError(null);
        setIsLoading(true);
        try {
            const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || 'Login failed');
            }

            const { access_token, user: userData } = data;
            setToken(access_token);
            setUser(userData);
            localStorage.setItem('matrix_token', access_token);
            localStorage.setItem('matrix_user', JSON.stringify(userData));

            router.push('/hub');
        } catch (err: any) {
            setError(err.message);
            throw err;
        } finally {
            setIsLoading(false);
        }
    };

    const register = async (email: string, username: string, password: string, fullName?: string, company?: string) => {
        setError(null);
        setIsLoading(true);
        try {
            const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, username, password, full_name: fullName, company }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || 'Registration failed');
            }

            const { access_token, user: userData } = data;
            setToken(access_token);
            setUser(userData);
            localStorage.setItem('matrix_token', access_token);
            localStorage.setItem('matrix_user', JSON.stringify(userData));

            router.push('/hub');
        } catch (err: any) {
            setError(err.message);
            throw err;
        } finally {
            setIsLoading(false);
        }
    };

    const logout = () => {
        setToken(null);
        setUser(null);
        localStorage.removeItem('matrix_token');
        localStorage.removeItem('matrix_user');
        router.push('/');
    };

    return (
        <AuthContext.Provider value={{
            user,
            token,
            isAuthenticated: !!token,
            isLoading,
            login,
            register,
            logout,
            error
        }}>
            {children}
        </AuthContext.Provider>
    );
}

export function useAuth() {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
}
