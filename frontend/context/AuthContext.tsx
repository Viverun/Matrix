'use client';

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useRouter } from 'next/navigation';

import { api, User } from '../lib/matrix_api'; // Import api client and User type



interface AuthContextType {
    user: User | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    login: (email: string, password: string) => Promise<void>;
    register: (email: string, username: string, password: string, fullName?: string, company?: string) => Promise<void>;
    logout: () => void;
    error: string | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);


export function AuthProvider({ children }: { children: ReactNode }) {
    const [user, setUser] = useState<User | null>(null);
    const isAuthenticated = !!user;
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const router = useRouter();

    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        setMounted(true);

        // Check for active session via API (cookies)
        const initAuth = async () => {
            console.log('[Auth] Initializing session...');
            try {
                // First, ensure we have a CSRF token
                await api.ensureCsrf();

                const user = await api.getCurrentUser();
                setUser(user);
                console.log('[Auth] Session restored', user.username);
            } catch (e) {
                console.log('[Auth] No active session');
                setUser(null);
            } finally {
                setIsLoading(false);
            }
        };

        if (isAuthenticated) {
            // Already explicitly authenticated (e.g. just logged in)
            setIsLoading(false);
        } else {
            initAuth();
        }
    }, [isAuthenticated]);

    const login = async (email: string, password: string) => {
        setError(null);
        setIsLoading(true);
        try {
            const data = await api.login(email, password);
            setUser(data.user);
            // No localStorage set
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
            const data = await api.register({ email, username, password, full_name: fullName, company });
            setUser(data.user);
            router.push('/hub');
        } catch (err: any) {
            setError(err.message);
            throw err;
        } finally {
            setIsLoading(false);
        }
    };

    const logout = async () => {
        try {
            await api.logout();
        } catch (e) {
            console.error('Logout failed', e);
        }
        setUser(null);
        router.push('/');
    };

    return (
        <AuthContext.Provider value={{
            user,

            isAuthenticated: !!user,
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
