'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { LogOut, User } from 'lucide-react';
import { SpiderWeb } from './SpiderWeb';
import { useAuth } from '../context/AuthContext';

export function Navbar() {
    const { user, isAuthenticated, logout } = useAuth();
    const [isVisible, setIsVisible] = useState(true);
    const [lastScrollY, setLastScrollY] = useState(0);

    useEffect(() => {
        const controlNavbar = () => {
            if (window.scrollY > lastScrollY && window.scrollY > 100) {
                setIsVisible(false);
            } else {
                setIsVisible(true);
            }
            setLastScrollY(window.scrollY);
        };

        window.addEventListener('scroll', controlNavbar);
        return () => window.removeEventListener('scroll', controlNavbar);
    }, [lastScrollY]);

    return (
        <header className={`glass-nav sticky top-0 z-50 transition-transform duration-500 ${isVisible ? 'translate-y-0' : '-translate-y-full'}`}>
            <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
                <Link href="/" className="flex items-center gap-3 group">
                    <div className="w-10 h-10 rounded-xl bg-accent-primary/10 flex items-center justify-center shadow-soft group-hover:shadow-card transition-all">
                        <SpiderWeb className="w-6 h-6 text-accent-primary" />
                    </div>
                    <h1 className="text-xl font-serif font-medium text-text-primary">
                        <span className="text-accent-primary">M</span>atrix
                    </h1>
                </Link>

                <nav className="hidden md:flex items-center gap-8">
                    <Link href="/" className="text-text-secondary hover:text-accent-primary transition-colors font-medium">
                        About
                    </Link>
                    <Link href="/scan" className="text-text-secondary hover:text-accent-primary transition-colors font-medium">
                        Scan
                    </Link>
                    <Link href="/hub" className="text-text-secondary hover:text-accent-primary transition-colors font-medium">
                        Features
                    </Link>
                    <Link href="/repo" className="text-text-secondary hover:text-accent-primary transition-colors font-medium">
                        Repository
                    </Link>
                    <Link href="/docs" className="text-text-secondary hover:text-accent-primary transition-colors font-medium">
                        Docs
                    </Link>
                </nav>

                <div className="flex items-center gap-5">
                    {isAuthenticated && (
                        <div className="flex items-center gap-4 animate-fade-in">
                            {/* User Avatar & Name */}
                            <div className="hidden lg:flex items-center gap-3 px-4 py-2 bg-warm-50/50 rounded-xl border border-warm-200/50 hover:border-accent-primary/30 transition-all">
                                <div className="w-8 h-8 rounded-lg bg-accent-primary/10 flex items-center justify-center text-accent-primary shadow-sm">
                                    <User className="w-4 h-4" />
                                </div>
                                <span className="text-text-primary font-semibold text-sm">
                                    {user?.username}
                                </span>
                            </div>

                            {/* Logout Button */}
                            <button
                                onClick={logout}
                                className="group p-2.5 text-text-muted hover:text-red-500 hover:bg-red-50 rounded-xl transition-all hover:shadow-sm border border-transparent hover:border-red-100"
                                title="Logout"
                            >
                                <LogOut className="w-5 h-5 group-hover:scale-110 transition-transform" />
                            </button>
                        </div>
                    )}
                </div>
            </div>
        </header>
    );
}
