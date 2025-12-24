'use client';

import { useState, useEffect } from 'react';
import { Target, FileSearch, ArrowRight, CheckCircle, AlertTriangle, XCircle, ArrowLeft, LogOut, Loader2 } from 'lucide-react';
import Link from 'next/link';
import { SpiderWeb } from '../../components/SpiderWeb';
import { ProtectedRoute } from '../../components/ProtectedRoute';
import { useAuth } from '../../context/AuthContext';
import { api, Scan, Vulnerability } from '../../lib/api';
import { useRouter } from 'next/navigation';

import { Navbar } from '../../components/Navbar';

export default function ScanPage() {
    const { user, logout, isAuthenticated } = useAuth();
    const router = useRouter();
    const [targetUrl, setTargetUrl] = useState('');
    const [isScanning, setIsScanning] = useState(false);
    const [scanProgress, setScanProgress] = useState(0);
    const [scanResults, setScanResults] = useState<Scan | null>(null);
    const [findings, setFindings] = useState<Vulnerability[]>([]);
    const [error, setError] = useState<string | null>(null);

    const handleStartScan = async () => {
        if (!targetUrl) return;


        setIsScanning(true);
        setScanProgress(0);
        setScanResults(null);
        setFindings([]);
        setError(null);

        try {
            const newScan = await api.createScan({
                target_url: targetUrl,
                scan_type: 'full'
            });

            setScanResults(newScan);

            // Poll for status
            let failures = 0; // Local counter for the interval closure
            const interval = setInterval(async () => {
                try {
                    const statusUpdate = await api.getScan(newScan.id);
                    // Reset failures on success
                    failures = 0;

                    setScanProgress(statusUpdate.progress);
                    setScanResults(statusUpdate);

                    if (statusUpdate.status === 'completed') {
                        clearInterval(interval);
                        setIsScanning(false);
                        const results = await api.getVulnerabilities(newScan.id);
                        setFindings(results.items);
                    } else if (statusUpdate.status === 'failed' || statusUpdate.status === 'cancelled') {
                        clearInterval(interval);
                        setIsScanning(false);
                        setError(statusUpdate.error_message || 'Scan terminated unexpectedly');
                    }
                } catch (err: any) {
                    console.error('Poll error:', err);
                    failures++;
                    if (failures >= 3) {
                        clearInterval(interval);
                        setIsScanning(false);
                        setError('Lost connection to scan server (timed out)');
                    }
                }
            }, 2000);
        } catch (err: any) {
            setIsScanning(false);
            setError(err.message || 'Failed to initialize security mesh');
        }
    };

    return (
        <ProtectedRoute>
            <div className="min-h-screen">
                <Navbar />

                {/* Page Header */}
                <section className="py-12 px-6 border-b border-warm-200">
                    <div className="max-w-4xl mx-auto">
                        <Link href="/hub" className="inline-flex items-center gap-2 text-text-muted hover:text-accent-primary transition-colors mb-4">
                            <ArrowLeft className="w-4 h-4" />
                            Back to Hub
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

                        {/* Error Alert */}
                        {error && (
                            <div className="mb-8 p-4 bg-red-500/5 border border-red-200 rounded-xl flex items-center gap-3 text-red-600 animate-fade-in">
                                <AlertTriangle className="w-5 h-5 flex-shrink-0" />
                                <div>
                                    <div className="font-bold text-sm uppercase tracking-widest mb-1">Audit Failure</div>
                                    <div className="text-sm opacity-90">{error}</div>
                                </div>
                            </div>
                        )}

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
                                            { count: scanResults.critical_count, label: 'Critical', color: 'bg-red-50 border-red-200 text-red-600' },
                                            { count: scanResults.high_count, label: 'High', color: 'bg-orange-50 border-orange-200 text-orange-600' },
                                            { count: scanResults.medium_count, label: 'Medium', color: 'bg-amber-50 border-amber-200 text-amber-600' },
                                            { count: scanResults.low_count, label: 'Low', color: 'bg-blue-50 border-blue-200 text-blue-600' },
                                            { count: scanResults.total_vulnerabilities, label: 'Total', color: 'bg-warm-100 border-warm-300 text-accent-primary' },
                                        ].map((stat, i) => (
                                            <div key={i} className={`text-center p-3 rounded-xl border ${stat.color}`}>
                                                <div className="text-2xl font-bold">{stat.count}</div>
                                                <div className="text-xs opacity-75 uppercase tracking-tighter font-bold">{stat.label}</div>
                                            </div>
                                        ))}
                                    </div>

                                    {/* Vulnerability List */}
                                    <div className="space-y-3">
                                        {findings.map((vuln, i) => (
                                            <div
                                                key={i}
                                                className="group flex items-center justify-between p-4 bg-white/50 rounded-xl border border-warm-200 hover:border-accent-primary/20 hover:bg-white transition-all duration-300"
                                            >
                                                <div className="flex items-center gap-4">
                                                    {vuln.severity === 'critical' && <XCircle className="w-5 h-5 text-red-500" />}
                                                    {vuln.severity === 'high' && <AlertTriangle className="w-5 h-5 text-orange-500" />}
                                                    {vuln.severity === 'medium' && <AlertTriangle className="w-5 h-5 text-amber-500" />}
                                                    <div className="min-w-0">
                                                        <div className="font-bold text-text-primary uppercase tracking-tight truncate">{vuln.vulnerability_type}</div>
                                                        <div className="text-sm text-text-muted truncate max-w-[200px] sm:max-w-md">
                                                            {vuln.url} {vuln.parameter && <span className="text-accent-primary ml-1 opacity-70">[{vuln.parameter}]</span>}
                                                        </div>
                                                    </div>
                                                </div>
                                                <span className={`severity-tag severity-${vuln.severity} px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-widest`}>
                                                    {vuln.severity}
                                                </span>
                                            </div>
                                        ))}
                                    </div>

                                    <Link
                                        href={`/scans/${scanResults.id}`}
                                        className="btn-primary w-full mt-6 text-center shadow-lg hover:shadow-xl transition-all"
                                    >
                                        Deep Architecture Audit
                                    </Link>
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
        </ProtectedRoute>
    );
}
