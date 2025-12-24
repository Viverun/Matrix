'use client';
import React, { useState, useEffect } from 'react';

import { Zap, Search, Code, FileText, ArrowRight, Activity, Database, Lock, Terminal, LogOut } from 'lucide-react';
import Link from 'next/link';
import { SpiderWeb } from '../../components/SpiderWeb';
import { useAuth } from '../../context/AuthContext';

import { Navbar } from '../../components/Navbar';

export default function HubPage() {
    const { user, logout } = useAuth();
    // Navbar visible/scroll logic moved to Navbar component

    const features = [
        {
            title: 'Security Scanner',
            description: 'Intelligent multi-agent web vulnerability scanner targeting OWASP Top 10.',
            icon: SpiderWeb,
            href: '/scan',
            color: 'text-accent-primary',
            bg: 'bg-accent-primary/5',
            border: 'border-accent-primary/20',
            tags: ['Web', 'Active Scan']
        },
        {
            title: 'Repository Analysis',
            description: 'Advanced SAST audit and secret detection for GitHub repositories.',
            icon: Code,
            href: '/repo',
            color: 'text-accent-gold',
            bg: 'bg-accent-gold/5',
            border: 'border-accent-gold/20',
            tags: ['Code', 'SAST']
        },
        {
            title: 'Agentic Workflow',
            description: 'Explore the autonomous orchestration logic behind Matrix security agents.',
            icon: Terminal,
            href: '/docs',
            color: 'text-blue-500',
            bg: 'bg-blue-500/5',
            border: 'border-blue-500/20',
            tags: ['Docs', 'AI']
        },
        {
            title: 'Past Reports',
            description: 'Access detailed vulnerability history, trend analysis, and security insights.',
            icon: Activity,
            href: '/analytics',
            color: 'text-green-500',
            bg: 'bg-green-500/5',
            border: 'border-green-500/20',
            tags: ['Analytics', 'Trends']
        }
    ];

    return (
        <div className="min-h-screen bg-bg-primary">
            <Navbar />

            <main className="max-w-6xl mx-auto px-6 py-20">
                <div className="text-center mb-16 space-y-4">
                    <h2 className="text-5xl font-serif font-medium text-text-primary tracking-tight">
                        Deep into the <span className="text-accent-primary">Matrix</span>
                    </h2>
                    <p className="text-text-secondary text-lg max-w-2xl mx-auto">
                        Select a specialized security interface to begin your autonomous assessment.
                    </p>
                </div>

                <div className="grid md:grid-cols-2 gap-8">
                    {features.map((feature, i) => (
                        <Link
                            key={i}
                            href={feature.href}
                            className={`group relative overflow-hidden glass-card p-8 border-2 ${feature.border} hover:shadow-2xl hover:-translate-y-2 transition-all duration-500`}
                        >
                            {/* Accent Background */}
                            <div className={`absolute -right-12 -top-12 w-48 h-48 ${feature.bg} rounded-full blur-3xl group-hover:scale-150 transition-transform duration-700`} />

                            <div className="relative z-10 flex flex-col h-full">
                                <div className="flex justify-between items-start mb-6">
                                    <div className={`w-14 h-14 rounded-2xl ${feature.bg} flex items-center justify-center`}>
                                        <feature.icon className={`w-7 h-7 ${feature.color}`} />
                                    </div>
                                    <div className="flex gap-2">
                                        {feature.tags.map((tag, j) => (
                                            <span key={j} className="text-[10px] uppercase font-bold tracking-widest px-2 py-1 bg-warm-100 rounded-full text-text-muted">
                                                {tag}
                                            </span>
                                        ))}
                                    </div>
                                </div>

                                <h3 className="text-2xl font-serif font-medium text-text-primary mb-3">
                                    {feature.title}
                                </h3>

                                <p className="text-text-secondary mb-8 leading-relaxed">
                                    {feature.description}
                                </p>

                                <div className="mt-auto flex items-center gap-2 text-sm font-bold uppercase tracking-widest text-accent-primary opacity-0 group-hover:opacity-100 -translate-x-4 group-hover:translate-x-0 transition-all duration-300">
                                    Launch Interface
                                    <ArrowRight className="w-4 h-4" />
                                </div>
                            </div>

                            {/* Decorative line */}
                            <div className={`absolute bottom-0 left-0 h-1 bg-gradient-to-r from-transparent via-${feature.color.split('-')[1]}-${feature.color.split('-')[2]} to-transparent w-full opacity-0 group-hover:opacity-100 transition-opacity`} />
                        </Link>
                    ))}
                </div>

                {/* Footer Insight */}
                <div className="mt-20 glass-card p-10 text-center border-accent-primary/10">
                    <div className="max-w-3xl mx-auto flex flex-col md:flex-row items-center gap-8">
                        <div className="flex-1 text-left">
                            <h4 className="text-xl font-serif font-medium text-text-primary mb-2">Autonomous Security Mesh</h4>
                            <p className="text-text-muted text-sm leading-relaxed">
                                Matrix leverages a multi-agent orchestration layer that shares intelligence across all tools.
                                Findings in your repository automatically inform our web scanner's attack patterns.
                            </p>
                        </div>
                        <Link href="/docs" className="btn-primary whitespace-nowrap">
                            Learn How It Works
                        </Link>
                    </div>
                </div>
            </main>
        </div>
    );
}
