'use client';

import { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import {
    ArrowLeft, Shield, AlertTriangle, XCircle,
    CheckCircle, Info, Clock, Globe, Zap,
    FileText, Download, Share2, ExternalLink,
    Terminal, Cpu, Fingerprint, Loader2,
    EyeOff, AlertCircle
} from 'lucide-react';
import Link from 'next/link';
import { SpiderWeb } from '@/components/SpiderWeb';
import { useAuth } from '@/context/AuthContext';
import { ProtectedRoute } from '@/components/ProtectedRoute';
import { api, Scan, Vulnerability } from '@/lib/matrix_api';
import { Navbar } from '@/components/Navbar';
import dynamic from 'next/dynamic';
import { RepoScanView } from '@/components/RepoScanView';
import { SecurityScanView } from '@/components/SecurityScanView';

export default function ScanDetailPage() {
    const { id } = useParams();
    const { user, logout } = useAuth();
    const [scan, setScan] = useState<Scan | null>(null);
    const [findings, setFindings] = useState<Vulnerability[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<'active' | 'suppressed'>('active');
    const [terminalLines, setTerminalLines] = useState<string[]>([]);

    const ScanPDFExportButton = dynamic(
        () => import('@/components/ScanPDFExportButton'),
        { ssr: false }
    );

    const counts = {
        critical: findings.filter(f => !f.is_suppressed && f.severity === 'critical').length,
        high: findings.filter(f => !f.is_suppressed && f.severity === 'high').length,
        medium: findings.filter(f => !f.is_suppressed && f.severity === 'medium').length,
        low: findings.filter(f => !f.is_suppressed && f.severity === 'low').length,
        suppressed: findings.filter(f => f.is_suppressed).length
    };

    // Agent status helper
    const getAgentStatus = (agentName: string): 'audited' | 'scanning' | 'waiting' => {
        if (!scan || scan.status !== 'running') {
            return scan?.status === 'completed' ? 'audited' : 'waiting';
        }
        const agents = scan.agents_enabled || [];
        const agentIndex = agents.indexOf(agentName);
        if (agentIndex === -1) return 'waiting';

        const progressPerAgent = 100 / agents.length;
        const agentThreshold = progressPerAgent * (agentIndex + 1);

        if (scan.progress >= agentThreshold) return 'audited';
        if (scan.progress >= agentThreshold - progressPerAgent) return 'scanning';
        return 'waiting';
    };

    // Agent display names
    const agentNames: Record<string, { name: string; icon: string }> = {
        'sql_injection': { name: 'SQL Injection', icon: '🛡️' },
        'xss': { name: 'XSS Detection', icon: '🔍' },
        'csrf': { name: 'CSRF Analysis', icon: '🔄' },
        'ssrf': { name: 'SSRF Scanner', icon: '🌐' },
        'auth': { name: 'Auth Testing', icon: '🔐' },
        'api_security': { name: 'API Security', icon: '⚡' },
        'authentication': { name: 'Auth Testing', icon: '🔐' },
    };

    // Initial fetch
    useEffect(() => {
        const fetchScanDetails = async () => {
            if (!id) return;
            setIsLoading(true);
            try {
                const scanData = await api.getScan(Number(id));
                setScan(scanData);

                const vulnerabilities = await api.getVulnerabilities(Number(id));
                setFindings(vulnerabilities.items);

                // Initialize terminal
                setTerminalLines([
                    `$ Initializing security mesh...`,
                    `[INFO] Target resolved: ${scanData.target_url}`,
                    `[OK] Scan created with ID: ${scanData.id}`,
                ]);
            } catch (err: any) {
                setError(err.message || 'Failed to retrieve audit intelligence');
            } finally {
                setIsLoading(false);
            }
        };

        fetchScanDetails();
    }, [id]);

    // Polling while scan is running
    useEffect(() => {
        if (!scan || scan.status !== 'running') return;

        const pollInterval = setInterval(async () => {
            try {
                const scanData = await api.getScan(Number(id));
                setScan(scanData);

                // Update terminal with progress
                const currentAgent = scanData.agents_enabled?.find((a, i) => {
                    const threshold = (100 / scanData.agents_enabled.length) * (i + 1);
                    return scanData.progress < threshold && scanData.progress >= threshold - (100 / scanData.agents_enabled.length);
                });

                if (currentAgent) {
                    setTerminalLines(prev => {
                        const lastLine = prev[prev.length - 1];
                        if (!lastLine?.includes(currentAgent)) {
                            return [...prev, `[SCAN] Running ${agentNames[currentAgent]?.name || currentAgent} agent...`];
                        }
                        return prev;
                    });
                }

                // Fetch vulnerabilities
                const vulns = await api.getVulnerabilities(Number(id));
                setFindings(vulns.items);

                if (scanData.status !== 'running') {
                    clearInterval(pollInterval);
                    setTerminalLines(prev => [...prev,
                    `[OK] Scan ${scanData.status}`,
                    `[INFO] Found ${vulns.total} vulnerabilities`
                    ]);
                }
            } catch (err) {
                console.error('Poll error:', err);
            }
        }, 2000);

        return () => clearInterval(pollInterval);
    }, [scan?.status, id]);


    if (isLoading) {
        return (
            <ProtectedRoute>
                <div className="min-h-screen bg-bg-primary flex items-center justify-center">
                    <div className="text-center space-y-4">
                        <Loader2 className="w-12 h-12 text-accent-primary animate-spin mx-auto opacity-40" />
                        <p className="text-text-muted font-serif italic text-lg animate-pulse">Decrypting Security Archives...</p>
                    </div>
                </div>
            </ProtectedRoute>
        );
    }

    if (error || !scan) {
        return (
            <ProtectedRoute>
                <div className="min-h-screen bg-bg-primary p-6">
                    <div className="max-w-4xl mx-auto glass-card p-12 text-center mt-20">
                        <XCircle className="w-16 h-16 text-red-500/40 mx-auto mb-6" />
                        <h2 className="text-3xl font-serif-display font-medium text-text-primary mb-4">Protocol Exception</h2>
                        <p className="text-text-secondary mb-8">{error || 'The requested audit record is inaccessible or does not exist.'}</p>
                        <Link href="/dashboard" className="btn-primary inline-flex items-center gap-2">
                            <ArrowLeft className="w-4 h-4" />
                            Return to Command Center
                        </Link>
                    </div>
                </div>
            </ProtectedRoute>
        );
    }

    return (
        <ProtectedRoute>
            <div className="min-h-screen bg-bg-primary pattern-bg pb-20">
                <Navbar />
                <main className="max-w-7xl mx-auto px-6 py-12">
                    {/* Breadcrumbs & Actions */}
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-12">
                        <div className="animate-slide-up">
                            <Link
                                href={scan.scan_type === 'github_sast' ? `/repo?url=${encodeURIComponent(scan.target_url)}&scan_id=${scan.id}` : '/analytics'}
                                className="inline-flex items-center gap-2 text-text-muted hover:text-accent-primary transition-colors mb-4 font-bold text-xs uppercase tracking-widest"
                            >
                                <ArrowLeft className="w-4 h-4" />
                                {scan.scan_type === 'github_sast' ? 'Back to Repository Analysis' : 'Back to Historical Log'}
                            </Link>
                            <h2 className="text-4xl font-serif-display font-medium text-text-primary flex items-center gap-4">
                                {scan.scan_type === 'github_sast' ? 'Source Integrity Audit' : 'Security Infrastructure Audit'}
                                <span className={`text-xs px-3 py-1 rounded-full uppercase tracking-[0.2em] font-bold ${scan.status === 'completed' ? 'bg-green-500/10 text-green-600' : 'bg-red-500/10 text-red-600'
                                    }`}>
                                    {scan.status}
                                </span>
                            </h2>
                            <div className="flex items-center gap-4 mt-3 text-text-secondary font-medium">
                                <div className="flex items-center gap-2">
                                    <Globe className="w-4 h-4 text-accent-primary opacity-60" />
                                    {scan.target_url}
                                </div>
                                <div className="w-1 h-1 bg-warm-300 rounded-full" />
                                <div className="flex items-center gap-2">
                                    <Clock className="w-4 h-4 text-accent-primary opacity-60" />
                                    {new Date(scan.created_at).toLocaleDateString(undefined, { dateStyle: 'long' })}
                                </div>
                            </div>
                        </div>

                        <div className="flex items-center gap-3">
                            <button
                                onClick={() => {
                                    const exportData = {
                                        scan: scan,
                                        findings: findings,
                                        exportedAt: new Date().toISOString(),
                                        version: '1.0'
                                    };
                                    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement('a');
                                    a.href = url;
                                    a.download = `Matrix_Scan_${scan.id}_${new Date().toISOString().split('T')[0]}.json`;
                                    a.click();
                                    URL.revokeObjectURL(url);
                                }}
                                className="px-5 py-2.5 bg-white border border-warm-200 rounded-xl text-text-primary text-sm font-bold uppercase tracking-widest hover:border-accent-primary/30 transition-all flex items-center gap-2"
                            >
                                <Download className="w-4 h-4" />
                                Export JSON
                            </button>
                            <ScanPDFExportButton scan={scan} findings={findings} />
                        </div>
                    </div>

                    {/* Dynamic Scan Progress (only when running) */}
                    {scan.status === 'running' && (
                        <div className="glass-card p-6 mb-12 animate-slide-up">
                            {/* Header with Progress */}
                            <div className="flex items-center justify-between mb-6">
                                <div className="flex items-center gap-4">
                                    <div className="w-12 h-12 rounded-full bg-accent-primary/10 flex items-center justify-center">
                                        <Loader2 className="w-6 h-6 text-accent-primary animate-spin" />
                                    </div>
                                    <div>
                                        <h3 className="text-lg font-serif-display font-medium text-text-primary">Scan in Progress</h3>
                                        <p className="text-sm text-text-secondary">Analyzing {scan.target_url}</p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-6">
                                    <button
                                        onClick={async () => {
                                            if (confirm('Terminate this security audit?')) {
                                                try {
                                                    await api.cancelScan(scan.id);
                                                    const updated = await api.getScan(scan.id);
                                                    setScan(updated);
                                                } catch (err: any) {
                                                    alert(err.message || 'Cancellation failed');
                                                }
                                            }
                                        }}
                                        className="px-4 py-2 border border-red-200 text-red-600 rounded-lg text-xs font-bold uppercase tracking-widest hover:bg-red-50 transition-all"
                                    >
                                        Cancel Scan
                                    </button>
                                    <div className="text-right">
                                        <div className="text-3xl font-serif-display font-medium text-accent-primary">{scan.progress}%</div>
                                        <div className="text-xs text-text-muted uppercase tracking-widest">Complete</div>
                                    </div>
                                </div>
                            </div>

                            {/* Progress Bar */}
                            <div className="h-2 bg-warm-100 rounded-full mb-8 overflow-hidden">
                                <div
                                    className="h-full bg-gradient-to-r from-accent-primary to-green-500 rounded-full transition-all duration-500"
                                    style={{ width: `${scan.progress}%` }}
                                />
                            </div>

                            {/* Agent Status Grid */}
                            <div className="mb-6">
                                <h4 className="text-xs font-bold uppercase tracking-widest text-text-muted mb-4">Security Agents</h4>
                                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                                    {scan.agents_enabled.map((agent) => {
                                        const status = getAgentStatus(agent);
                                        const info = agentNames[agent] || { name: agent.replace(/_/g, ' '), icon: '🔍' };
                                        return (
                                            <div
                                                key={agent}
                                                className={`p-4 rounded-xl border transition-all ${status === 'scanning'
                                                    ? 'bg-accent-primary/10 border-accent-primary animate-pulse'
                                                    : status === 'audited'
                                                        ? 'bg-green-50 border-green-200'
                                                        : 'bg-warm-50 border-warm-200'
                                                    }`}
                                            >
                                                <div className="flex items-center gap-3">
                                                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${status === 'scanning' ? 'bg-accent-primary/20' :
                                                        status === 'audited' ? 'bg-green-100' : 'bg-warm-100'
                                                        }`}>
                                                        {status === 'audited' ? (
                                                            <CheckCircle className="w-4 h-4 text-green-600" />
                                                        ) : status === 'scanning' ? (
                                                            <Loader2 className="w-4 h-4 text-accent-primary animate-spin" />
                                                        ) : (
                                                            <Clock className="w-4 h-4 text-warm-400" />
                                                        )}
                                                    </div>
                                                    <div>
                                                        <div className="font-medium text-sm text-text-primary">{info.name}</div>
                                                        <div className={`text-xs capitalize ${status === 'scanning' ? 'text-accent-primary' :
                                                            status === 'audited' ? 'text-green-600' : 'text-warm-400'
                                                            }`}>
                                                            {status === 'scanning' ? 'Scanning...' : status === 'audited' ? 'Audited' : 'Waiting'}
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>

                            {/* Live Terminal Output */}
                            <div>
                                <h4 className="text-xs font-bold uppercase tracking-widest text-text-muted mb-4 flex items-center gap-2">
                                    <Terminal className="w-4 h-4" />
                                    Live Output
                                </h4>
                                <div className="bg-gray-900 rounded-xl p-4 font-mono text-sm max-h-48 overflow-y-auto">
                                    {terminalLines.map((line, i) => (
                                        <div key={i} className={`${line.startsWith('[OK]') ? 'text-green-400' :
                                            line.startsWith('[SCAN]') ? 'text-yellow-400' :
                                                line.startsWith('[INFO]') ? 'text-blue-400' :
                                                    line.startsWith('$') ? 'text-accent-primary' :
                                                        'text-gray-300'
                                            }`}>
                                            {line}
                                        </div>
                                    ))}
                                    <div className="text-green-400 animate-pulse">█</div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Report Content - Specialized Views */}
                    {scan.status !== 'running' && (
                        <div>
                            {/* Tabs - Shared between both views */}
                            <div className="flex gap-1 p-1 bg-warm-100 rounded-xl w-fit mb-8">
                                <button
                                    onClick={() => setActiveTab('active')}
                                    className={`px-6 py-2 rounded-lg text-xs font-bold uppercase tracking-widest transition-all ${activeTab === 'active' ? 'bg-white text-text-primary shadow-sm' : 'text-text-muted hover:text-text-secondary'}`}
                                >
                                    Confirmed Findings ({findings.length - counts.suppressed})
                                </button>
                                <button
                                    onClick={() => setActiveTab('suppressed')}
                                    className={`px-6 py-2 rounded-lg text-xs font-bold uppercase tracking-widest transition-all ${activeTab === 'suppressed' ? 'bg-white text-text-primary shadow-sm' : 'text-text-muted hover:text-text-secondary'}`}
                                >
                                    Suppressed / FP ({counts.suppressed})
                                </button>
                            </div>

                            {scan.scan_type === 'github_sast' ? (
                                <RepoScanView
                                    scan={scan}
                                    findings={findings}
                                    activeTab={activeTab}
                                />
                            ) : (
                                <SecurityScanView
                                    scan={scan}
                                    findings={findings}
                                    activeTab={activeTab}
                                    terminalLines={terminalLines}
                                />
                            )}
                        </div>
                    )}
                </main>
            </div>
        </ProtectedRoute >
    );
}
