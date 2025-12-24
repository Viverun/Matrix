'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { Mail, Lock, User, Building, ArrowRight, Loader2, AlertCircle, CheckCircle2 } from 'lucide-react';
import { SpiderWeb } from '../../components/SpiderWeb';
import { useAuth } from '../../context/AuthContext';

export default function SignupPage() {
    const { register, isLoading, error: authError } = useAuth();
    const [email, setEmail] = useState('');
    const [username, setUsername] = useState('');
    const [fullName, setFullName] = useState('');
    const [company, setCompany] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState<string | null>(null);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);

        if (!email || !username || !password) {
            setError('Core protocols (Email, Username, Cipher) are required');
            return;
        }

        try {
            await register(email, username, password, fullName, company);
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
                    <h2 className="text-4xl font-serif-display font-medium text-text-primary mb-2">Enlist Operative</h2>
                    <p className="text-sm text-text-secondary font-medium italic">Begin your journey into autonomous security mesh</p>
                </div>

                {/* Signup Card */}
                <div className="glass-card shadow-2xl animate-fade-in border border-white/40 overflow-hidden">
                    <form onSubmit={handleSubmit} className="grid grid-cols-1 lg:grid-cols-2">
                        {/* Left Section: Details */}
                        <div className="p-8 lg:p-10 space-y-6 border-b lg:border-b-0 lg:border-r border-warm-100/50">
                            <h3 className="text-xl font-serif-display font-medium text-text-primary mb-4 flex items-center gap-2">
                                <div className="w-1 h-5 bg-accent-primary rounded-full" />
                                Operative Details
                            </h3>

                            {(error || authError) && (
                                <div className="p-4 bg-red-500/5 border border-red-200 rounded-xl flex items-center gap-3 text-red-600 text-sm animate-shake">
                                    <AlertCircle className="w-5 h-5 flex-shrink-0" />
                                    <span>{error || authError}</span>
                                </div>
                            )}

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-text-muted ml-1">Email</label>
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
                                    <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-text-muted ml-1">Alias</label>
                                    <div className="relative group">
                                        <User className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted transition-colors group-focus-within:text-accent-primary" />
                                        <input
                                            type="text"
                                            value={username}
                                            onChange={(e) => setUsername(e.target.value)}
                                            placeholder="Username"
                                            className="w-full pl-10 pr-4 py-3 bg-warm-50/30 border border-warm-200/60 rounded-xl focus:ring-2 focus:ring-accent-primary/20 focus:border-accent-primary transition-all outline-none text-text-primary text-sm font-medium placeholder:text-text-muted/50"
                                        />
                                    </div>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-text-muted ml-1">Full Name</label>
                                    <div className="relative group">
                                        <User className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted transition-colors group-focus-within:text-accent-primary" />
                                        <input
                                            type="text"
                                            value={fullName}
                                            onChange={(e) => setFullName(e.target.value)}
                                            placeholder="Full Name"
                                            className="w-full pl-10 pr-4 py-3 bg-warm-50/30 border border-warm-200/60 rounded-xl focus:ring-2 focus:ring-accent-primary/20 focus:border-accent-primary transition-all outline-none text-text-primary text-sm font-medium placeholder:text-text-muted/50"
                                        />
                                    </div>
                                </div>
                                <div className="space-y-2">
                                    <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-text-muted ml-1">Organization</label>
                                    <div className="relative group">
                                        <Building className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted transition-colors group-focus-within:text-accent-primary" />
                                        <input
                                            type="text"
                                            value={company}
                                            onChange={(e) => setCompany(e.target.value)}
                                            placeholder="Your Organization"
                                            className="w-full pl-10 pr-4 py-3 bg-warm-50/30 border border-warm-200/60 rounded-xl focus:ring-2 focus:ring-accent-primary/20 focus:border-accent-primary transition-all outline-none text-text-primary text-sm font-medium placeholder:text-text-muted/50"
                                        />
                                    </div>
                                </div>
                            </div>

                            <div className="space-y-2">
                                <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-text-muted ml-1">Master Cipher Key</label>
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

                        {/* Right Section: Actions & Protocol Clearance */}
                        <div className="p-8 lg:p-12 bg-accent-primary/[0.02] flex flex-col justify-between relative overflow-hidden">
                            {/* Decorative Background Element */}
                            <div className="absolute top-0 right-0 w-64 h-64 bg-accent-primary/[0.03] rounded-full -translate-y-1/2 translate-x-1/2 blur-3xl pointer-events-none" />

                            <div className="relative flex flex-col justify-center h-full">

                                <div className="space-y-6">
                                    <div className="flex items-start gap-4 p-5 bg-white/60 backdrop-blur-sm rounded-2xl border border-accent-primary/10 shadow-sm relative overflow-hidden group">
                                        <div className="absolute top-0 left-0 w-1 h-full bg-accent-primary/40 group-hover:bg-accent-primary transition-colors" />
                                        <div className="w-8 h-8 rounded-lg bg-accent-primary/5 flex items-center justify-center flex-shrink-0">
                                            <CheckCircle2 className="w-4 h-4 text-accent-primary" />
                                        </div>
                                        <p className="text-[10px] text-text-secondary leading-relaxed uppercase tracking-widest font-bold">
                                            By enlisting, you agree to the Matrix protocols and acknowledge the sovereignty of zero-knowledge audit logs.
                                        </p>
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
                                                Establish Identity
                                                <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                                            </>
                                        )}
                                    </button>
                                </div>
                            </div>

                            <div className="pt-8 border-t border-warm-200/50 text-center relative z-10">
                                <p className="text-text-muted text-[11px] mb-4 font-bold uppercase tracking-[0.2em]">Current Operative?</p>
                                <Link
                                    href="/login"
                                    className="inline-flex items-center gap-3 px-10 py-3.5 bg-white text-text-primary border border-warm-200/60 rounded-2xl font-bold hover:bg-accent-primary hover:text-white transition-all shadow-sm hover:shadow-card transform hover:-translate-y-1 group"
                                >
                                    Access Matrix
                                    <div className="w-1.5 h-1.5 rounded-full bg-accent-primary group-hover:bg-white transition-colors" />
                                </Link>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    );
}
