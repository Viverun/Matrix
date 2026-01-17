'use client';

import { useState, useEffect } from 'react';
import {
    Target, FileSearch, Activity,
    TrendingUp, AlertTriangle, CheckCircle, Clock,
    Plus, RefreshCw, Download, Zap, ArrowRight, Code, FileText, XCircle, Loader2
} from 'lucide-react';
import Link from 'next/link';
import { SpiderWeb } from '../../components/SpiderWeb';
import { useAuth } from '../../context/AuthContext';
import { ProtectedRoute } from '../../components/ProtectedRoute';
import { LogOut } from 'lucide-react';

import { api, Scan } from '../../lib/matrix_api';

import { Navbar } from '../../components/Navbar';

export default function DashboardPage() {
    const { user, logout } = useAuth();
    // Navbar visible/scroll logic moved to Navbar component

    const [scans, setScans] = useState<Scan[]>([]);
    const [stats, setStats] = useState({
        totalScans: 0,
        totalVulnerabilities: 0,
        criticalVulnerabilities: 0,
        fixedVulnerabilities: 0,
    });
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const fetchData = async () => {
        setIsLoading(true);
        setError(null);
        try {
            const data = await api.getScans(1, 10);
            setScans(data.items);

            const aggregate = data.items.reduce((acc, scan) => ({
                totalScans: data.total,
                totalVulnerabilities: acc.totalVulnerabilities + (scan.total_vulnerabilities || 0),
                criticalVulnerabilities: acc.criticalVulnerabilities + (scan.critical_count || 0),
                fixedVulnerabilities: acc.fixedVulnerabilities + (scan.info_count || 0),
            }), {
                totalScans: data.total,
                totalVulnerabilities: 0,
                criticalVulnerabilities: 0,
                fixedVulnerabilities: 0
            });
            setStats(aggregate);
        } catch (err: any) {
            setError(err.message || 'Failed to fetch security orchestration data');
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, []);

    return (
        <ProtectedRoute>
            <div className="min-h-screen bg-bg-primary pattern-bg">
                <Navbar />
                <main className="max-w-7xl mx-auto px-6 py-12">
                    {/* Page Title */}
                    <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 mb-12">
                        <div className="animate-slide-up">
                            <h2 className="text-4xl font-serif-display font-medium text-text-primary">Security Command Center</h2>
                            <p className="text-text-secondary mt-2 text-lg">Centralized intelligence and historical audit orchestration.</p>
                        </div>
                        <Link
                            href="/scan"
                            className="btn-primary rounded-xl flex items-center gap-2 shadow-lg hover:shadow-xl transition-all"
                        >
                            <Plus className="w-5 h-5" />
                            Initiate New Scan
                        </Link>
                    </div>

                    {/* Stats Grid */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
                        <div className="glass-card p-6 border-b-4 border-b-accent-primary/30">
                            <div className="flex items-center justify-between mb-4">
                                <div className="w-12 h-12 bg-accent-primary/5 rounded-xl flex items-center justify-center">
                                    <Target className="w-6 h-6 text-accent-primary" />
                                </div>
                                <span className="text-xs font-bold uppercase tracking-widest text-text-muted">Aggregate</span>
                            </div>
                            <div className="text-4xl font-serif-display font-medium text-text-primary">{stats.totalScans}</div>
                            <div className="text-sm text-text-secondary mt-1">Total Audit Cycles</div>
                        </div>

                        <div className="glass-card p-6 border-b-4 border-b-yellow-500/30">
                            <div className="flex items-center justify-between mb-4">
                                <div className="w-12 h-12 bg-yellow-500/5 rounded-xl flex items-center justify-center">
                                    <AlertTriangle className="w-6 h-6 text-yellow-600" />
                                </div>
                                <span className="text-xs font-bold uppercase tracking-widest text-yellow-600">Identified</span>
                            </div>
                            <div className="text-4xl font-serif-display font-medium text-text-primary">{stats.totalVulnerabilities}</div>
                            <div className="text-sm text-text-secondary mt-1">Vulnerabilities Detected</div>
                        </div>

                        <div className="glass-card p-6 border-b-4 border-b-red-500/30">
                            <div className="flex items-center justify-between mb-4">
                                <div className="w-12 h-12 bg-red-500/5 rounded-xl flex items-center justify-center">
                                    <Zap className="w-6 h-6 text-red-600" />
                                </div>
                                <span className="text-xs font-bold uppercase tracking-widest text-red-600">Immediate</span>
                            </div>
                            <div className="text-4xl font-serif-display font-medium text-red-600">{stats.criticalVulnerabilities}</div>
                            <div className="text-sm text-text-secondary mt-1">Critical Exceptions</div>
                        </div>

                        <div className="glass-card p-6 border-b-4 border-b-green-500/30">
                            <div className="flex items-center justify-between mb-4">
                                <div className="w-12 h-12 bg-green-500/5 rounded-xl flex items-center justify-center">
                                    <CheckCircle className="w-6 h-6 text-green-600" />
                                </div>
                                <span className="text-xs font-bold uppercase tracking-widest text-green-600">Mitigated</span>
                            </div>
                            <div className="text-4xl font-serif-display font-medium text-green-600">{stats.fixedVulnerabilities}</div>
                            <div className="text-sm text-text-secondary mt-1">Resolved Threats</div>
                        </div>
                    </div>

                    {/* Main Content Grid */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                        {/* Recent Scans / Past Reports */}
                        <div className="lg:col-span-2 glass-card p-8">
                            <div className="flex items-center justify-between mb-8">
                                <h3 className="text-2xl font-serif-display font-medium text-text-primary flex items-center gap-3">
                                    <div className="w-2 h-8 bg-accent-primary rounded-full" />
                                    Historical Audit Log
                                </h3>
                                <button
                                    onClick={fetchData}
                                    disabled={isLoading}
                                    className="p-2 hover:bg-warm-100 rounded-lg transition-colors text-text-muted hover:text-accent-primary disabled:opacity-50"
                                >
                                    <RefreshCw className={`w-5 h-5 ${isLoading ? 'animate-spin' : ''}`} />
                                </button>
                            </div>

                            {error && error !== 'Not Found' && (
                                <div className="mb-6 p-4 bg-red-500/5 border border-red-200 rounded-xl flex items-center gap-3 text-red-600 text-sm animate-fade-in">
                                    <AlertTriangle className="w-5 h-5 flex-shrink-0" />
                                    <span>{error}</span>
                                </div>
                            )}

                            <div className="space-y-4">
                                {isLoading && scans.length === 0 ? (
                                    <div className="py-20 text-center space-y-4">
                                        <Loader2 className="w-10 h-10 text-accent-primary/40 animate-spin mx-auto" />
                                        <p className="text-text-muted font-serif italic text-lg">Synchronizing audit data...</p>
                                    </div>
                                ) : scans.length === 0 ? (
                                    <div className="py-20 text-center space-y-4">
                                        <Target className="w-12 h-12 text-warm-300 mx-auto" />
                                        <p className="text-text-muted font-medium">No historical audit cycles found.</p>
                                        <Link href="/scan" className="text-accent-primary hover:underline font-bold text-sm uppercase tracking-widest">Initiate First Scan</Link>
                                    </div>
                                ) : (
                                    scans.map((scan) => (
                                        <div
                                            key={scan.id}
                                            className="group flex flex-col sm:flex-row sm:items-center justify-between p-5 rounded-2xl border border-warm-200 hover:border-accent-primary/20 hover:bg-white/50 transition-all duration-300"
                                        >
                                            <div className="flex items-center gap-5 mb-4 sm:mb-0">
                                                <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${scan.status === 'running' ? 'bg-accent-primary/5 animate-pulse' :
                                                    scan.status === 'completed' ? 'bg-green-500/5' : 'bg-warm-100'
                                                    }`}>
                                                    <SpiderWeb className={`w-6 h-6 ${scan.status === 'running' ? 'text-accent-primary' :
                                                        scan.status === 'completed' ? 'text-green-600' : 'text-text-muted'
                                                        }`} />
                                                </div>
                                                <div>
                                                    <div className="font-medium text-text-primary text-lg truncate max-w-[250px] sm:max-w-md">{scan.target_url}</div>
                                                    <div className="text-sm text-text-muted flex items-center gap-2 mt-1 font-medium">
                                                        <Clock className="w-3.5 h-3.5" />
                                                        {new Date(scan.created_at).toLocaleDateString(undefined, {
                                                            year: 'numeric',
                                                            month: 'short',
                                                            day: 'numeric',
                                                            hour: '2-digit',
                                                            minute: '2-digit'
                                                        })}
                                                    </div>
                                                </div>
                                            </div>

                                            <div className="flex items-center justify-between sm:justify-end gap-6 pl-16 sm:pl-0">
                                                {scan.status === 'completed' && (
                                                    <div className="text-right">
                                                        <div className={`text-sm font-bold uppercase tracking-tighter ${scan.total_vulnerabilities > 0 ? 'text-yellow-600' : 'text-green-600'}`}>
                                                            {scan.total_vulnerabilities} findings
                                                        </div>
                                                        <div className="text-xs text-text-muted uppercase tracking-widest font-bold opacity-60">Audit Complete</div>
                                                    </div>
                                                )}
                                                {scan.status === 'running' && (
                                                    <div className="text-accent-primary text-sm font-bold uppercase tracking-widest flex items-center gap-2">
                                                        <div className="w-4 h-4 border-2 border-accent-primary border-t-transparent rounded-full animate-spin" />
                                                        {scan.progress}% Analysis
                                                    </div>
                                                )}
                                                {scan.status === 'pending' && (
                                                    <div className="text-warm-400 text-sm font-bold uppercase tracking-widest flex items-center gap-2">
                                                        <Clock className="w-4 h-4" />
                                                        Queued
                                                    </div>
                                                )}
                                                {scan.status === 'failed' && (
                                                    <div className="text-red-500 text-sm font-bold uppercase tracking-widest flex items-center gap-2">
                                                        <XCircle className="w-4 h-4" />
                                                        Scan Failed
                                                    </div>
                                                )}

                                                <div className="flex items-center gap-2">
                                                    {(scan.status === 'running' || scan.status === 'pending') && (
                                                        <button
                                                            onClick={async (e) => {
                                                                e.preventDefault();
                                                                if (confirm('Terminate this security audit?')) {
                                                                    try {
                                                                        await api.cancelScan(scan.id);
                                                                        fetchData(); // Refresh list
                                                                    } catch (err: any) {
                                                                        alert(err.message || 'Cancellation failed');
                                                                    }
                                                                }
                                                            }}
                                                            className="p-2 text-text-muted hover:text-red-500 hover:bg-red-50/50 rounded-lg transition-all"
                                                            title="Cancel Scan"
                                                        >
                                                            <XCircle className="w-5 h-5" />
                                                        </button>
                                                    )}
                                                    <Link
                                                        href={`/scans/${scan.id}`}
                                                        className="px-4 py-2 bg-warm-100 text-text-primary rounded-lg text-sm font-bold uppercase tracking-wider hover:bg-accent-primary hover:text-white transition-all shadow-sm group-hover:shadow-card"
                                                    >
                                                        Report
                                                    </Link>
                                                </div>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>

                        </div>

                        {/* Quick Access - Analytics */}
                        <div className="glass-card p-8">
                            <h3 className="text-2xl font-serif-display font-medium text-text-primary flex items-center gap-3 mb-6">
                                <div className="w-2 h-8 bg-accent-gold rounded-full" />
                                Analytics Hub
                            </h3>

                            {(() => {
                                // Calculate security score based on vulnerabilities
                                // Formula: Start at 100, deduct points based on severity
                                // Critical: -10 points each, Other vulns: -2 points each (capped at min 0)
                                const baseScore = 100;
                                const criticalPenalty = stats.criticalVulnerabilities * 10;
                                const otherPenalty = (stats.totalVulnerabilities - stats.criticalVulnerabilities) * 2;
                                const calculatedScore = Math.max(0, baseScore - criticalPenalty - otherPenalty);
                                const scoreColor = calculatedScore >= 70 ? 'text-green-600' : calculatedScore >= 40 ? 'text-yellow-600' : 'text-red-600';

                                return (
                                    <div className="space-y-4">
                                        <div className="p-4 bg-accent-primary/5 rounded-xl border border-accent-primary/10">
                                            <div className="flex items-center gap-3 mb-2">
                                                <TrendingUp className="w-5 h-5 text-accent-primary" />
                                                <span className="font-medium text-text-primary">Security Score</span>
                                            </div>
                                            <div className={`text-3xl font-serif-display font-medium ${scoreColor}`}>
                                                {calculatedScore}/100
                                            </div>
                                            <div className="text-xs text-text-muted mt-1">
                                                Based on {stats.totalScans} scan{stats.totalScans !== 1 ? 's' : ''}
                                            </div>
                                        </div>

                                        <div className={`p-4 rounded-xl border ${stats.criticalVulnerabilities === 0
                                            ? 'bg-green-500/5 border-green-500/10'
                                            : 'bg-red-500/5 border-red-500/10'
                                            }`}>
                                            <div className="flex items-center gap-3 mb-2">
                                                <Activity className={`w-5 h-5 ${stats.criticalVulnerabilities === 0 ? 'text-green-600' : 'text-red-600'}`} />
                                                <span className="font-medium text-text-primary">System Health</span>
                                            </div>
                                            <p className="text-sm text-text-secondary leading-relaxed">
                                                {stats.criticalVulnerabilities === 0
                                                    ? 'No critical vulnerabilities detected.'
                                                    : `${stats.criticalVulnerabilities} critical issue${stats.criticalVulnerabilities !== 1 ? 's' : ''} require attention.`
                                                }
                                            </p>
                                        </div>
                                    </div>
                                );
                            })()}

                            <Link
                                href="/analytics"
                                className="mt-6 w-full btn-primary rounded-xl flex items-center justify-center gap-2 shadow-lg hover:shadow-xl transition-all"
                            >
                                <TrendingUp className="w-5 h-5" />
                                View Full Analytics
                            </Link>
                        </div>
                    </div>

                    {/* Secondary Actions */}
                    <div className="mt-12 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
                        <Link href="/reports" className="glass-card p-6 border-transparent hover:border-accent-primary/20 transition-all group">
                            <Download className="w-8 h-8 text-accent-primary mb-4 group-hover:scale-110 transition-transform" />
                            <div className="font-serif-display font-medium text-xl text-text-primary">Export Archives</div>
                            <div className="text-sm text-text-muted mt-1">Generate white-labeled PDF/JSON reports.</div>
                        </Link>

                        <Link href="/analytics" className="glass-card p-6 border-transparent hover:border-accent-primary/20 transition-all group">
                            <TrendingUp className="w-8 h-8 text-accent-primary mb-4 group-hover:scale-110 transition-transform" />
                            <div className="font-serif-display font-medium text-xl text-text-primary">Vector Trends</div>
                            <div className="text-sm text-text-muted mt-1">Deep dive into recurring threat patterns.</div>
                        </Link>

                        <Link href="/integrations" className="glass-card p-6 border-transparent hover:border-accent-primary/20 transition-all group">
                            <Code className="w-8 h-8 text-accent-primary mb-4 group-hover:scale-110 transition-transform" />
                            <div className="font-serif-display font-medium text-xl text-text-primary">API Hub</div>
                            <div className="text-sm text-text-muted mt-1">Configure webhooks and CI/CD pipelines.</div>
                        </Link>

                        <Link href="/docs" className="glass-card p-6 border-transparent hover:border-accent-primary/20 transition-all group">
                            <FileText className="w-8 h-8 text-accent-primary mb-4 group-hover:scale-110 transition-transform" />
                            <div className="font-serif-display font-medium text-xl text-text-primary">Compliance</div>
                            <div className="text-sm text-text-muted mt-1">Audit logs for ISO/SOC2 readiness.</div>
                        </Link>
                    </div>
                </main>
            </div >
        </ProtectedRoute >
    );
}
