'use client';

import { useAuth } from '../context/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, ReactNode } from 'react';
import { Loader2 } from 'lucide-react';
import { SpiderWeb } from './SpiderWeb';

export function ProtectedRoute({ children }: { children: ReactNode }) {
    const { isAuthenticated, isLoading } = useAuth();
    const router = useRouter();

    useEffect(() => {
        if (!isLoading && !isAuthenticated) {
            router.push('/login');
        }
    }, [isAuthenticated, isLoading, router]);

    if (isLoading) {
        return (
            <div className="min-h-screen bg-bg-primary flex flex-col items-center justify-center gap-6">
                <div className="relative">
                    <div className="w-20 h-20 rounded-2xl bg-accent-primary/5 flex items-center justify-center animate-pulse">
                        <SpiderWeb className="w-10 h-10 text-accent-primary animate-spin-slow" />
                    </div>
                    <div className="absolute inset-0 border-2 border-accent-primary/20 rounded-2xl animate-ping" />
                </div>
                <p className="text-text-secondary font-serif italic animate-pulse">Synchronizing Identity...</p>
                <div className="text-[10px] text-text-muted mt-4 opacity-30 select-none">
                    Connection: Secured • Auth Status: Pending
                </div>
            </div>
        );
    }

    if (!isAuthenticated) {
        return null;
    }

    return <>{children}</>;
}
