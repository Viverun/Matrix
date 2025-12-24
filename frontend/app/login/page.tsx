'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { Mail, Lock, ArrowRight, Loader2, AlertCircle, ShieldCheck, Cpu, Fingerprint } from 'lucide-react';
import { SpiderWeb } from '../../components/SpiderWeb';
import { useAuth } from '../../context/AuthContext';
import { useSearchParams } from 'next/navigation';

export default function LoginPage() {
    const { login, isLoading, error: authError } = useAuth();
    const searchParams = useSearchParams();
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [alertMessage, setAlertMessage] = useState<string | null>(null);

    useEffect(() => {
        const message = searchParams.get('message');
        if (message) {
            setAlertMessage(message);
        }
    }, [searchParams]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);

        if (!email || !password) {
            setError('Verification credentials required');
            return;
        }

        try {
            await login(email, password);
        } catch (err: any) {
            // Error managed in context
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center px-6 py-20">
            <div className="w-full max-w-4xl">
                {/* Header */}
                <div className="text-center mb-10 animate-slide-up">
                    <Link href="/" className="inline-flex items-center gap-3 group mb-4">
                        <div className="w-12 h-12 rounded-xl bg-accent-primary/10 flex items-center justify-center shadow-soft group-hover:shadow-card transition-all duration-500 group-hover:scale-110">
                            <SpiderWeb className="w-7 h-7 text-accent-primary" />
                        </div>
                        <h1 className="text-2xl font-serif font-medium text-text-primary">
                            <span className="text-accent-primary">M</span>atrix
                        </h1>
                    </Link>
                    <h2 className="text-4xl font-serif-display font-medium text-text-primary mb-2">Initialize Session</h2>
                    <p className="text-sm text-text-secondary font-medium italic">Identity verification protocol active</p>
                </div>

                {/* Login Card */}
                <div className="glass-card shadow-2xl animate-fade-in border border-white/40 overflow-hidden">
                    <form onSubmit={handleSubmit} className="grid grid-cols-1 lg:grid-cols-2">
                        {/* Left Section: Credentials */}
                        <div className="p-8 lg:p-10 space-y-8 border-b lg:border-b-0 lg:border-r border-warm-100/50">
                            <h3 className="text-xl font-serif-display font-medium text-text-primary mb-2 flex items-center gap-2">
                                <div className="w-1 h-5 bg-accent-primary rounded-full" />
                                Credentials
                            </h3>

                            {alertMessage && (
                                <div className="p-4 bg-accent-primary/5 border border-accent-primary/20 rounded-xl flex items-center gap-3 text-accent-primary text-sm animate-fade-in">
                                    <AlertCircle className="w-5 h-5 flex-shrink-0" />
                                    <span>{alertMessage}</span>
                                </div>
                            )}

                            {(error || authError) && (
                                <div className="p-4 bg-red-500/5 border border-red-200 rounded-xl flex items-center gap-3 text-red-600 text-sm animate-shake">
                                    <AlertCircle className="w-5 h-5 flex-shrink-0" />
                                    <span>{error || authError}</span>
                                </div>
                            )}

                            <div className="space-y-6">
                                <div className="space-y-2">
                                    <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-text-muted ml-1">Email Address</label>
                                    <div className="relative group">
                                        <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted transition-colors group-focus-within:text-accent-primary" />
                                        <input
                                            type="email"
                                            value={email}
                                            onChange={(e) => setEmail(e.target.value)}
                                            placeholder="Your Email"
                                            className="w-full pl-10 pr-4 py-3 bg-warm-50/30 border border-warm-200/60 rounded-xl focus:ring-2 focus:ring-accent-primary/20 focus:border-accent-primary transition-all outline-none text-text-primary text-sm font-medium placeholder:text-text-muted/50"
                                        />
                                    </div>
                                </div>

                                <div className="space-y-2">
                                    <div className="flex justify-between items-end mb-1">
                                        <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-text-muted ml-1">Master Cipher Key</label>
                                        <Link href="#" className="text-[10px] text-accent-primary/60 hover:text-accent-primary font-bold uppercase tracking-wider transition-colors">Lost Key?</Link>
                                    </div>
                                    <div className="relative group">
                                        <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted transition-colors group-focus-within:text-accent-primary" />
                                        <input
                                            type="password"
                                            value={password}
                                            onChange={(e) => setPassword(e.target.value)}
                                            placeholder="Master Key"
                                            className="w-full pl-10 pr-4 py-3 bg-warm-50/30 border border-warm-200/60 rounded-xl focus:ring-2 focus:ring-accent-primary/20 focus:border-accent-primary transition-all outline-none text-text-primary text-sm font-medium placeholder:text-text-muted/50"
                                        />
                                    </div>
                                </div>
                            </div>

                            <div className="pt-4 flex items-center gap-3 text-text-muted/60">
                                <ShieldCheck className="w-4 h-4" />
                                <span className="text-[10px] font-bold uppercase tracking-widest">End-to-End Encryption Enabled</span>
                            </div>
                        </div>

                        {/* Right Section: Security Protocol */}
                        <div className="p-8 lg:p-12 bg-accent-primary/[0.02] flex flex-col justify-between relative overflow-hidden">
                            {/* Decorative Background Element */}
                            <div className="absolute top-0 right-0 w-64 h-64 bg-accent-primary/[0.03] rounded-full -translate-y-1/2 translate-x-1/2 blur-3xl pointer-events-none" />

                            <div className="relative flex flex-col justify-center h-full space-y-10">
                                <div className="space-y-6">
                                    <div className="flex items-center gap-4 group">
                                        <div className="w-10 h-10 rounded-xl bg-white shadow-soft border border-warm-200/50 flex items-center justify-center flex-shrink-0">
                                            <Fingerprint className="w-5 h-5 text-accent-primary" />
                                        </div>
                                        <div>
                                            <h4 className="text-[10px] font-bold text-text-muted uppercase tracking-[0.2em] mb-1">Clearance Level</h4>
                                            <p className="text-xs font-bold text-text-primary">Verified Operative</p>
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-4 group">
                                        <div className="w-10 h-10 rounded-xl bg-white shadow-soft border border-warm-200/50 flex items-center justify-center flex-shrink-0">
                                            <Cpu className="w-5 h-5 text-accent-primary" />
                                        </div>
                                        <div>
                                            <h4 className="text-[10px] font-bold text-text-muted uppercase tracking-[0.2em] mb-1">Mesh Connection</h4>
                                            <p className="text-xs font-bold text-text-primary">Encrypted (AES-256)</p>
                                        </div>
                                    </div>
                                </div>

                                <button
                                    type="submit"
                                    disabled={isLoading}
                                    className="w-full btn-primary py-5 rounded-2xl flex items-center justify-center gap-3 font-serif-display text-2xl group hover:shadow-2xl hover:-translate-y-1 active:translate-y-0 relative overflow-hidden"
                                >
                                    <div className="absolute inset-0 bg-white/10 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-1000 ease-in-out" />
                                    {isLoading ? (
                                        <Loader2 className="w-6 h-6 animate-spin" />
                                    ) : (
                                        <>
                                            Verify Identity
                                            <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                                        </>
                                    )}
                                </button>
                            </div>

                            <div className="pt-8 border-t border-warm-200/50 text-center relative z-10">
                                <p className="text-text-muted text-[11px] mb-4 font-bold uppercase tracking-[0.2em]">New Operative?</p>
                                <Link
                                    href="/signup"
                                    className="inline-flex items-center gap-3 px-10 py-3.5 bg-white text-text-primary border border-warm-200/60 rounded-2xl font-bold hover:bg-accent-primary hover:text-white transition-all shadow-sm hover:shadow-card transform hover:-translate-y-1 group"
                                >
                                    Enlist in Matrix
                                    <div className="w-1.5 h-1.5 rounded-full bg-accent-primary group-hover:bg-white transition-colors" />
                                </Link>
                            </div>
                        </div>
                    </form>
                </div>

                {/* Global Security Disclaimer */}
                <p className="mt-8 text-center text-[10px] text-text-muted font-bold uppercase tracking-[0.3em] opacity-40">
                    Sovereign Identity Mesh • Established 2025
                </p>
            </div>
        </div>
    );
}
