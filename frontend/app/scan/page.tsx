'use client';

import { useState } from 'react';
import { Shield, Target, FileSearch, ArrowRight, CheckCircle, AlertTriangle, XCircle, ArrowLeft } from 'lucide-react';
import Link from 'next/link';

export default function ScanPage() {
    const [targetUrl, setTargetUrl] = useState('');
    const [isScanning, setIsScanning] = useState(false);
    const [scanProgress, setScanProgress] = useState(0);
    const [scanResults, setScanResults] = useState<any>(null);

    const handleStartScan = async () => {
        if (!targetUrl) return;

        setIsScanning(true);
        setScanProgress(0);
        setScanResults(null);

        const interval = setInterval(() => {
            setScanProgress(prev => {
                if (prev >= 100) {
                    clearInterval(interval);
                    setIsScanning(false);
                    setScanResults({
                        total: 7,
                        critical: 1,
                        high: 2,
                        medium: 3,
                        low: 1,
                        vulnerabilities: [
                            { type: 'SQL Injection', severity: 'critical', url: '/api/users', parameter: 'id' },
                            { type: 'XSS (Reflected)', severity: 'high', url: '/search', parameter: 'q' },
                            { type: 'Missing Security Headers', severity: 'medium', url: '/', parameter: null },
                        ]
                    });
                    return 100;
                }
                return prev + Math.random() * 15;
            });
        }, 500);
    };

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
                        <Link href="/" className="text-text-secondary hover:text-accent-primary transition-colors font-medium">
                            About
                        </Link>
                        <Link href="/hub" className="text-text-secondary hover:text-accent-primary transition-colors font-medium">
                            Features
                        </Link>
                        <Link href="/scan" className="text-accent-primary font-medium">
                            Scan
                        </Link>
                        <Link href="/repo" className="text-text-secondary hover:text-accent-primary transition-colors font-medium">
                            Repository
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
                        <Link href="/hub" className="btn-primary">
                            Get Started
                        </Link>
                    </div>
                </div>
            </header>

            {/* Page Header */}
            <section className="py-12 px-6 border-b border-warm-200">
                <div className="max-w-4xl mx-auto">
                    <Link href="/" className="inline-flex items-center gap-2 text-text-muted hover:text-accent-primary transition-colors mb-4">
                        <ArrowLeft className="w-4 h-4" />
                        Back to Home
                    </Link>
                    <h2 className="text-3xl md:text-4xl font-serif font-medium text-text-primary mb-2">
                        Security Scanner
                    </h2>
                    <p className="text-text-secondary">
                        Enter your target URL to begin the security assessment
                    </p>
                </div>
            </section>

            {/* Scan Section */}
            <section className="py-12 px-6">
                <div className="max-w-4xl mx-auto">
                    {/* Scan Input */}
                    <div className="glass-card p-6 mb-8">
                        <label className="block text-sm font-medium text-text-primary mb-3">
                            Target URL
                        </label>
                        <div className="flex items-center gap-3">
                            <div className="flex-1 relative">
                                <Target className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-accent-primary" />
                                <input
                                    type="url"
                                    placeholder="https://example.com"
                                    value={targetUrl}
                                    onChange={(e) => setTargetUrl(e.target.value)}
                                    className="input-glass pl-12 w-full"
                                    disabled={isScanning}
                                />
                            </div>
                            <button
                                onClick={handleStartScan}
                                disabled={!targetUrl || isScanning}
                                className="btn-primary flex items-center gap-2 whitespace-nowrap"
                            >
                                {isScanning ? (
                                    <>
                                        <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                                        Scanning...
                                    </>
                                ) : (
                                    <>
                                        Start Scan
                                        <ArrowRight className="w-4 h-4" />
                                    </>
                                )}
                            </button>
                        </div>
                    </div>

                    {/* Progress */}
                    {isScanning && (
                        <div className="glass-card p-6 mb-8 animate-fade-in">
                            <div className="flex justify-between text-sm mb-3">
                                <span className="text-text-muted">Analyzing target...</span>
                                <span className="text-accent-primary font-medium">{Math.round(scanProgress)}%</span>
                            </div>
                            <div className="progress-bar">
                                <div
                                    className="progress-bar-fill"
                                    style={{ width: `${scanProgress}%` }}
                                />
                            </div>
                            <div className="mt-6 terminal text-left text-sm">
                                <p className="terminal-prompt">Initializing security agents...</p>
                                <p className="terminal-prompt">SQL Injection Agent: Active</p>
                                <p className="terminal-prompt">XSS Agent: Active</p>
                                <p className="terminal-prompt opacity-60">Authentication Agent: Scanning...</p>
                            </div>
                        </div>
                    )}

                    {/* Results */}
                    {scanResults && (
                        <div className="animate-slide-up">
                            <div className="glass-card p-6">
                                <h3 className="text-xl font-display font-bold text-text-primary mb-6 flex items-center gap-3">
                                    <div className="w-10 h-10 rounded-xl bg-accent-primary/10 flex items-center justify-center">
                                        <FileSearch className="w-5 h-5 text-accent-primary" />
                                    </div>
                                    Scan Results
                                </h3>

                                {/* Stats Grid */}
                                <div className="grid grid-cols-5 gap-3 mb-6">
                                    {[
                                        { count: scanResults.critical, label: 'Critical', color: 'bg-red-50 border-red-200 text-red-600' },
                                        { count: scanResults.high, label: 'High', color: 'bg-orange-50 border-orange-200 text-orange-600' },
                                        { count: scanResults.medium, label: 'Medium', color: 'bg-amber-50 border-amber-200 text-amber-600' },
                                        { count: scanResults.low, label: 'Low', color: 'bg-blue-50 border-blue-200 text-blue-600' },
                                        { count: scanResults.total, label: 'Total', color: 'bg-warm-100 border-warm-300 text-accent-primary' },
                                    ].map((stat, i) => (
                                        <div key={i} className={`text-center p-3 rounded-xl border ${stat.color}`}>
                                            <div className="text-2xl font-bold">{stat.count}</div>
                                            <div className="text-xs opacity-75">{stat.label}</div>
                                        </div>
                                    ))}
                                </div>

                                {/* Vulnerability List */}
                                <div className="space-y-3">
                                    {scanResults.vulnerabilities.map((vuln: any, i: number) => (
                                        <div
                                            key={i}
                                            className="flex items-center justify-between p-4 bg-white/50 rounded-xl border border-warm-200 hover:border-warm-400 transition-colors"
                                        >
                                            <div className="flex items-center gap-4">
                                                {vuln.severity === 'critical' && <XCircle className="w-5 h-5 text-red-500" />}
                                                {vuln.severity === 'high' && <AlertTriangle className="w-5 h-5 text-orange-500" />}
                                                {vuln.severity === 'medium' && <AlertTriangle className="w-5 h-5 text-amber-500" />}
                                                <div>
                                                    <div className="font-semibold text-text-primary">{vuln.type}</div>
                                                    <div className="text-sm text-text-muted">
                                                        {vuln.url} {vuln.parameter && `→ ${vuln.parameter}`}
                                                    </div>
                                                </div>
                                            </div>
                                            <span className={`severity-${vuln.severity}`}>
                                                {vuln.severity.toUpperCase()}
                                            </span>
                                        </div>
                                    ))}
                                </div>

                                <button className="btn-primary w-full mt-6">
                                    View Full Report
                                </button>
                            </div>
                        </div>
                    )}

                    {/* Empty State */}
                    {!isScanning && !scanResults && (
                        <div className="glass-card p-12 text-center">
                            <Target className="w-16 h-16 text-warm-400 mx-auto mb-4" />
                            <h3 className="text-xl font-display font-semibold text-text-primary mb-2">
                                Ready to Scan
                            </h3>
                            <p className="text-text-muted max-w-md mx-auto">
                                Enter a target URL above to start the security assessment.
                                Our AI agents will analyze your application for vulnerabilities.
                            </p>
                        </div>
                    )}
                </div>
            </section>
        </div>
    );
}
