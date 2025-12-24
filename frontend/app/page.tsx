'use client';

import { Shield, ArrowRight, Zap, Lock, Search, Code } from 'lucide-react';
import Link from 'next/link';
import { MatrixRain } from '../components/MatrixRain';

export default function Home() {
    return (
        <div className="min-h-screen">
            {/* Navbar */}
            <header className="glass-nav sticky top-0 z-50">
                <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
                    <Link href="/" className="flex items-center gap-3 group">
                        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-accent-primary to-accent-primary/80 flex items-center justify-center shadow-soft group-hover:shadow-card transition-shadow">
                            <Shield className="w-5 h-5 text-white" />
                        </div>
                        <h1 className="text-xl font-serif font-medium text-text-primary">
                            <span className="text-accent-primary">M</span>atrix
                        </h1>
                    </Link>

                    <nav className="hidden md:flex items-center gap-8">
                        <Link href="/" className="text-accent-primary font-medium">
                            About
                        </Link>
                        <Link href="/scan" className="text-text-secondary hover:text-accent-primary transition-colors font-medium">
                            Scan
                        </Link>
                        <Link href="/dashboard" className="text-text-secondary hover:text-accent-primary transition-colors font-medium">
                            Dashboard
                        </Link>
                        <Link href="/docs" className="text-text-secondary hover:text-accent-primary transition-colors font-medium">
                            Docs
                        </Link>
                    </nav>

                    <div className="flex items-center gap-4">
                        <button className="btn-secondary hidden sm:block">
                            Sign In
                        </button>
                        <Link href="/scan" className="btn-primary">
                            Get Started
                        </Link>
                    </div>
                </div>
            </header>

            {/* Hero Section */}
            <section className="hero-gradient min-h-[90vh] flex items-center px-6 md:px-12 relative overflow-hidden">
                <div className="max-w-7xl mx-auto w-full grid md:grid-cols-2 gap-12 items-center relative z-10">
                    {/* Left Column - Content */}
                    <div className="text-left space-y-8 animate-slide-up">
                        <p className="text-2xl md:text-3xl font-serif text-text-secondary leading-relaxed max-w-xl">
                            Empower your security posture with autonomous AI agents that simulate sophisticated
                            real-world cyber attacks. Matrix continuously monitors your infrastructure,
                            identifies critical vulnerabilities with precision, and provides instant,
                            actionable remediation guidance to neutralize threats before they can be exploited.
                        </p>

                        <div className="pt-4">
                            <Link
                                href="/scan"
                                className="btn-primary rounded-none inline-flex items-center gap-3 text-lg px-10 py-5 shadow-lg hover:shadow-xl transform hover:-translate-y-1 transition-all duration-300"
                            >
                                Dive into Matrix
                                <ArrowRight className="w-5 h-5" />
                            </Link>
                        </div>
                    </div>

                    {/* Right Column - Matrix Title */}
                    <div className="flex justify-center md:justify-end items-center relative min-h-[400px] md:-mt-20">
                        {/* Matrix Rain Background */}
                        <div className="absolute inset-0 rounded-full overflow-hidden mask-radial-fade">
                            <MatrixRain />
                        </div>

                        <div className="relative animate-float z-10 p-12">
                            <h2 className="text-[10rem] md:text-[14rem] font-serif font-light text-text-primary tracking-tighter leading-none select-none relative">
                                <span className="text-accent-primary font-light">M</span>atrix
                            </h2>
                            {/* Decorative elements */}
                            <div className="absolute -top-12 -right-12 w-32 h-32 bg-accent-primary/5 rounded-full blur-3xl" />
                            <div className="absolute -bottom-12 -left-12 w-48 h-48 bg-accent-gold/5 rounded-full blur-3xl" />
                        </div>
                    </div>
                </div>

                {/* Background Pattern */}
                <div className="absolute inset-0 opacity-[0.02] pointer-events-none">
                    <div className="absolute top-0 right-0 w-[500px] h-[500px] border border-text-primary rounded-full translate-x-1/2 -translate-y-1/2" />
                    <div className="absolute top-0 right-0 w-[700px] h-[700px] border border-text-primary rounded-full translate-x-1/2 -translate-y-1/2" />
                </div>
            </section>

            {/* Divider */}
            <div className="divider mx-auto max-w-4xl" />

            {/* About Section */}
            <section className="py-20 md:py-24 px-6">
                <div className="max-w-6xl mx-auto">
                    <div className="text-center mb-16">
                        <h3 className="text-3xl md:text-4xl font-serif font-medium text-text-primary mb-4">
                            What is Matrix?
                        </h3>
                        <p className="text-text-secondary max-w-3xl mx-auto text-lg leading-relaxed">
                            Matrix is an AI-powered autonomous security testing platform that democratizes
                            penetration testing. Using intelligent agents powered by Google Gemini, it
                            automatically discovers vulnerabilities and provides actionable fixes.
                        </p>
                    </div>

                    {/* Features Grid */}
                    <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 mt-12">
                        {[
                            {
                                icon: Zap,
                                title: 'AI-Powered Analysis',
                                description: 'Powered by Google Gemini for intelligent vulnerability detection and remediation guidance.'
                            },
                            {
                                icon: Search,
                                title: 'Automated Discovery',
                                description: 'Automatically crawls and analyzes your application to find hidden attack surfaces.'
                            },
                            {
                                icon: Shield,
                                title: 'OWASP Coverage',
                                description: 'Comprehensive testing against OWASP Top 10 vulnerabilities and beyond.'
                            },
                            {
                                icon: Code,
                                title: 'Fix Recommendations',
                                description: 'Get code-level remediation suggestions with examples you can implement directly.'
                            },
                            {
                                icon: Lock,
                                title: 'Multi-Agent System',
                                description: 'Specialized agents work together to test SQL injection, XSS, authentication, and more.'
                            },
                            {
                                icon: ArrowRight,
                                title: 'Easy Integration',
                                description: 'RESTful API for seamless integration with your CI/CD pipeline.'
                            },
                        ].map((feature, i) => (
                            <div key={i} className="feature-card">
                                <feature.icon className="w-8 h-8 text-accent-primary mb-4" />
                                <h4 className="text-lg font-display font-semibold text-text-primary mb-2">{feature.title}</h4>
                                <p className="text-text-muted text-sm leading-relaxed">{feature.description}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* CTA Section */}
            <section className="py-16 px-6">
                <div className="max-w-4xl mx-auto">
                    <div className="glass-card p-8 md:p-12 text-center">
                        <h3 className="text-2xl md:text-3xl font-serif font-medium text-text-primary mb-4">
                            Ready to Secure Your Application?
                        </h3>
                        <p className="text-text-secondary mb-8 max-w-lg mx-auto">
                            Start your first scan in seconds. No complex setup required.
                        </p>
                        <Link
                            href="/scan"
                            className="btn-primary inline-flex items-center gap-2"
                        >
                            Dive into Matrix
                            <ArrowRight className="w-4 h-4" />
                        </Link>
                    </div>
                </div>
            </section>

            {/* Footer */}
            <footer className="border-t border-warm-200 py-8 px-6">
                <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-accent-primary/10 flex items-center justify-center">
                            <Shield className="w-4 h-4 text-accent-primary" />
                        </div>
                        <span className="text-text-muted font-serif">
                            <span className="text-accent-primary">M</span>atrix © 2024
                        </span>
                    </div>
                    <div className="flex items-center gap-6 text-sm text-text-muted">
                        <span>AI-Powered Security</span>
                        <span>•</span>
                        <span>OWASP Top 10 Coverage</span>
                    </div>
                </div>
            </footer>
        </div>
    );
}
