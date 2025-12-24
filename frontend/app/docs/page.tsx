'use client';

import { useState, useEffect } from 'react';
import { ArrowLeft, Terminal, Cpu, Network, Zap, Lock, Code } from 'lucide-react';
import Link from 'next/link';
import { SpiderWeb } from '../../components/SpiderWeb';

import { Navbar } from '../../components/Navbar';

export default function DocsPage() {
    // Navbar visible/scroll logic moved to Navbar component

    return (
        <div className="min-h-screen bg-bg-primary">
            <Navbar />

            <main className="max-w-4xl mx-auto px-6 py-20">
                <Link href="/hub" className="inline-flex items-center gap-2 text-text-muted hover:text-accent-primary transition-colors mb-8">
                    <ArrowLeft className="w-4 h-4" />
                    Back to Hub
                </Link>

                <div className="space-y-12">
                    <section>
                        <h2 className="text-4xl font-serif font-medium text-text-primary mb-6">Agentic Workflow Architecture</h2>
                        <p className="text-text-secondary text-lg leading-relaxed mb-8">
                            Matrix operates on a decentralized multi-agent system where specialized AI agents coordinate
                            to perform comprehensive security evaluations. Unlike traditional linear scanners, Matrix
                            simulates the thought process of a red-team operator.
                        </p>
                    </section>

                    <div className="grid gap-8">
                        <div className="glass-card p-8 border-l-4 border-l-accent-primary">
                            <div className="flex items-center gap-4 mb-4">
                                <Terminal className="w-8 h-8 text-accent-primary" />
                                <h3 className="text-2xl font-serif font-medium text-text-primary">1. Orchestration Layer</h3>
                            </div>
                            <p className="text-text-secondary leading-relaxed">
                                The central brain of Matrix. It analyzes the target (URL or Repository) and determines
                                which specialized agents are best suited for the job. It manages agent concurrency
                                and aggregates findings to prevent redundant testing.
                            </p>
                        </div>

                        <div className="glass-card p-8 border-l-4 border-l-accent-gold">
                            <div className="flex items-center gap-4 mb-4">
                                <Cpu className="w-8 h-8 text-accent-gold" />
                                <h3 className="text-2xl font-serif font-medium text-text-primary">2. Specialized Security Agents</h3>
                            </div>
                            <div className="grid sm:grid-cols-2 gap-4">
                                {[
                                    { name: 'XSS Agent', type: 'Web Scan' },
                                    { name: 'SQLi Agent', type: 'Web Scan' },
                                    { name: 'GitHub Agent', type: 'SAST Audit' },
                                    { name: 'Auth Agent', type: 'Logic Audit' }
                                ].map((agent, i) => (
                                    <div key={i} className="bg-warm-50 p-4 rounded-xl border border-warm-200">
                                        <div className="font-bold text-text-primary text-sm">{agent.name}</div>
                                        <div className="text-[10px] text-accent-primary font-bold uppercase tracking-widest">{agent.type}</div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="glass-card p-8 border-l-4 border-l-blue-500">
                            <div className="flex items-center gap-4 mb-4">
                                <Network className="w-8 h-8 text-blue-500" />
                                <h3 className="text-2xl font-serif font-medium text-text-primary">3. Intelligence Mesh</h3>
                            </div>
                            <p className="text-text-secondary leading-relaxed">
                                Agents share findings in real-time. For example, if the GitHub Agent finds a hardcoded
                                API endpoint in the source code, it immediately informs the Web Scan agents to
                                prioritize that endpoint for active testing.
                            </p>
                        </div>
                    </div>

                    <div className="pt-12 border-t border-warm-200">
                        <h3 className="text-2xl font-serif font-medium text-text-primary mb-4 italic">Next Generation Security</h3>
                        <p className="text-text-muted italic">
                            "Matrix isn't just a tool; it's an evolving digital organism designed to stay one step
                            ahead of modern threats."
                        </p>
                    </div>
                </div>
            </main>
        </div>
    );
}
