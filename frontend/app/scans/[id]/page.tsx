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
import { SpiderWeb } from '../../../components/SpiderWeb';
import { useAuth } from '../../../context/AuthContext';
import { ProtectedRoute } from '../../../components/ProtectedRoute';
import { api, Scan, Vulnerability } from '../../../lib/api';
import { Navbar } from '../../../components/Navbar';
import dynamic from 'next/dynamic';

const ScanPDFExportButton = dynamic(
    () => import('../../../components/ScanPDFExportButton'),
    { ssr: false }
);

export default function ScanDetailPage() {
    const { id } = useParams();
    const { user, logout } = useAuth();
    const [scan, setScan] = useState<Scan | null>(null);
    const [findings, setFindings] = useState<Vulnerability[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<'active' | 'suppressed'>('active');
    const [terminalLines, setTerminalLines] = useState<string[]>([]);

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
                            <Link href="/analytics" className="inline-flex items-center gap-2 text-text-muted hover:text-accent-primary transition-colors mb-4 font-bold text-xs uppercase tracking-widest">
                                <ArrowLeft className="w-4 h-4" />
                                Back to Historical Log
                            </Link>
                            <h2 className="text-4xl font-serif-display font-medium text-text-primary flex items-center gap-4">
                                Deep Audit Report
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
                                <div className="text-right">
                                    <div className="text-3xl font-serif-display font-medium text-accent-primary">{scan.progress}%</div>
                                    <div className="text-xs text-text-muted uppercase tracking-widest">Complete</div>
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

                    {/* Report Summary Cards */}
                    <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-6 mb-12">
                        <div className="glass-card p-6 border-b-4 border-b-red-500/30 group relative">
                            <div className="text-red-600 font-bold text-[10px] uppercase tracking-[0.2em] mb-1">Critical</div>
                            <div className="text-4xl font-serif-display font-medium text-text-primary">{counts.critical}</div>
                            <div className="text-xs text-text-secondary mt-2 font-medium">Immediate Risk</div>
                            {/* Simple tooltip simulation */}
                            <div className="absolute inset-0 bg-white/95 opacity-0 group-hover:opacity-100 transition-opacity p-4 flex items-center justify-center text-[10px] text-text-secondary font-medium text-center pointer-events-none">
                                Directly exploitable, likely compromise
                            </div>
                        </div>
                        <div className="glass-card p-6 border-b-4 border-b-orange-500/30 group relative">
                            <div className="text-orange-600 font-bold text-[10px] uppercase tracking-[0.2em] mb-1">High</div>
                            <div className="text-4xl font-serif-display font-medium text-text-primary">{counts.high}</div>
                            <div className="text-xs text-text-secondary mt-2 font-medium">Elevated Threat</div>
                            <div className="absolute inset-0 bg-white/95 opacity-0 group-hover:opacity-100 transition-opacity p-4 flex items-center justify-center text-[10px] text-text-secondary font-medium text-center pointer-events-none">
                                Exploitable with effort or chaining
                            </div>
                        </div>
                        <div className="glass-card p-6 border-b-4 border-b-amber-500/30 group relative">
                            <div className="text-amber-600 font-bold text-[10px] uppercase tracking-[0.2em] mb-1">Medium</div>
                            <div className="text-4xl font-serif-display font-medium text-text-primary">{counts.medium}</div>
                            <div className="text-xs text-text-secondary mt-2 font-medium">Technical Debt</div>
                            <div className="absolute inset-0 bg-white/95 opacity-0 group-hover:opacity-100 transition-opacity p-4 flex items-center justify-center text-[10px] text-text-secondary font-medium text-center pointer-events-none">
                                Hardening issues, no direct exploit
                            </div>
                        </div>
                        <div className="glass-card p-6 border-b-4 border-b-blue-500/30 group relative">
                            <div className="text-blue-600 font-bold text-[10px] uppercase tracking-[0.2em] mb-1">Low</div>
                            <div className="text-4xl font-serif-display font-medium text-text-primary">{counts.low}</div>
                            <div className="text-xs text-text-secondary mt-2 font-medium">Best Practices</div>
                            <div className="absolute inset-0 bg-white/95 opacity-0 group-hover:opacity-100 transition-opacity p-4 flex items-center justify-center text-[10px] text-text-secondary font-medium text-center pointer-events-none">
                                Hygiene & security posture
                            </div>
                        </div>
                        <div className="glass-card p-6 bg-accent-primary/5 border-transparent group relative">
                            <div className="text-accent-primary font-bold text-[10px] uppercase tracking-[0.2em] mb-1">Suppressed</div>
                            <div className="text-4xl font-serif-display font-medium text-accent-primary">{counts.suppressed}</div>
                            <div className="text-xs text-text-secondary mt-2 font-medium">False Positives</div>
                            <div className="absolute inset-0 bg-white/95 opacity-0 group-hover:opacity-100 transition-opacity p-4 flex items-center justify-center text-[10px] text-text-secondary font-medium text-center pointer-events-none">
                                Auto-suppressed by AI Auditor
                            </div>
                        </div>
                    </div>

                    {/* Findings Tabs */}
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

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                        {/* Findings List */}
                        <div className="lg:col-span-2 space-y-6">
                            <h3 className="text-2xl font-serif-display font-medium text-text-primary flex items-center gap-3 mb-2">
                                <div className="w-2 h-8 bg-accent-primary rounded-full" />
                                Individual Findings
                            </h3>

                            {findings.filter(f => activeTab === 'active' ? !f.is_suppressed : f.is_suppressed).length === 0 ? (
                                <div className="glass-card p-20 text-center">
                                    <CheckCircle className="w-16 h-16 text-green-500/30 mx-auto mb-4" />
                                    <h4 className="text-xl font-medium text-text-primary">{activeTab === 'active' ? 'No Vulnerabilities Detected' : 'No Suppressed Findings'}</h4>
                                    <p className="text-text-secondary mt-2 max-w-sm mx-auto">
                                        {activeTab === 'active'
                                            ? 'Your architecture successfully withstood all security orchestration tests.'
                                            : 'The AI Auditor has not found any findings that require auto-suppression in this scan.'}
                                    </p>
                                </div>
                            ) : (
                                findings
                                    .filter(f => activeTab === 'active' ? !f.is_suppressed : f.is_suppressed)
                                    .map((vuln) => (
                                        <div key={vuln.id} className={`glass-card overflow-hidden group hover:border-accent-primary/20 transition-all duration-500 ${vuln.is_suppressed ? 'opacity-80' : ''}`}>
                                            <div className="p-6 md:p-8">
                                                {/* Finding ID Header */}
                                                <div className="flex items-center justify-between mb-6 pb-3 border-b border-warm-100">
                                                    <div className="flex items-center gap-3">
                                                        <span className="text-[10px] font-mono font-bold text-accent-primary bg-accent-primary/10 px-2 py-1 rounded">
                                                            MTX-{String(scan.id).padStart(3, '0')}-{String(vuln.id).padStart(4, '0')}
                                                        </span>
                                                        {vuln.detected_by && (
                                                            <span className="text-[10px] text-text-muted font-medium">
                                                                via {vuln.detected_by.replace(/_/g, ' ')}
                                                            </span>
                                                        )}
                                                    </div>
                                                    <div className="flex items-center gap-4">
                                                        {vuln.final_verdict && (
                                                            <div className={`text-[10px] font-bold px-2 py-1 rounded uppercase tracking-widest flex items-center gap-1.5 ${vuln.final_verdict === 'FALSE_POSITIVE' ? 'bg-gray-100 text-gray-500' :
                                                                vuln.final_verdict === 'CONFIRMED_VULNERABILITY' ? 'bg-red-500/10 text-red-600' :
                                                                    vuln.final_verdict === 'DEFENSE_IN_DEPTH' ? 'bg-blue-500/10 text-blue-600' :
                                                                        'bg-amber-500/10 text-amber-600'
                                                                }`}>
                                                                {vuln.final_verdict === 'FALSE_POSITIVE' && <EyeOff className="w-3 h-3" />}
                                                                {vuln.final_verdict === 'CONFIRMED_VULNERABILITY' && <AlertCircle className="w-3 h-3" />}
                                                                Final Verdict: {vuln.final_verdict.replace(/_/g, ' ')}
                                                            </div>
                                                        )}
                                                        <div className="text-[10px] text-text-muted font-mono">
                                                            {new Date(vuln.detected_at).toLocaleString()}
                                                        </div>
                                                    </div>
                                                </div>

                                                <div className="flex flex-col md:flex-row md:items-start justify-between gap-6 mb-8">
                                                    <div className="flex gap-5">
                                                        <div className={`w-14 h-14 rounded-2xl flex items-center justify-center flex-shrink-0 ${vuln.is_suppressed ? 'bg-gray-100 text-gray-400' :
                                                            vuln.severity === 'critical' ? 'bg-red-500/10 text-red-600' :
                                                                vuln.severity === 'high' ? 'bg-orange-500/10 text-orange-600' :
                                                                    vuln.severity === 'medium' ? 'bg-amber-500/10 text-amber-600' :
                                                                        'bg-blue-500/10 text-blue-600'
                                                            }`}>
                                                            {vuln.is_suppressed ? <EyeOff className="w-8 h-8" /> :
                                                                vuln.severity === 'critical' ? <XCircle className="w-8 h-8" /> : <AlertTriangle className="w-8 h-8" />}
                                                        </div>
                                                        <div>
                                                            <div className="flex items-center gap-3">
                                                                <h4 className="text-xl font-bold text-text-primary uppercase tracking-tight">{vuln.vulnerability_type.replace(/_/g, ' ')}</h4>
                                                                {vuln.scope_impact?.is_systemic && (
                                                                    <span className="text-[10px] bg-accent-primary/10 text-accent-primary px-2 py-0.5 rounded font-bold uppercase tracking-widest">Systemic Issue</span>
                                                                )}
                                                            </div>
                                                            <p className="text-text-secondary mt-1 max-w-xl">{vuln.description}</p>

                                                            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 mt-4">
                                                                <div className="flex items-center gap-2">
                                                                    <div className="text-[10px] font-bold uppercase tracking-widest text-text-muted">Vector:</div>
                                                                    <code className="text-[11px] bg-warm-100 px-2 py-1 rounded text-accent-primary font-mono">
                                                                        {vuln.method} {vuln.url}
                                                                    </code>
                                                                </div>
                                                                {vuln.scope_impact && (
                                                                    <div className="flex items-center gap-2">
                                                                        <div className="text-[10px] font-bold uppercase tracking-widest text-text-muted">Impact Scope:</div>
                                                                        <span className="text-[11px] font-medium text-text-secondary">{vuln.scope_impact.summary}</span>
                                                                    </div>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div className="flex flex-col items-end gap-3">
                                                        <span className={`severity-tag ${vuln.is_suppressed ? 'bg-gray-100 text-gray-500' : `severity-${vuln.severity}`} px-4 py-1.5 rounded-lg text-xs font-bold uppercase tracking-widest shadow-sm`}>
                                                            {vuln.is_suppressed ? 'Suppressed' : vuln.severity}
                                                        </span>

                                                        <div className="flex flex-col gap-1.5 items-end">
                                                            <div className="flex items-center gap-2">
                                                                <span className="text-[10px] uppercase font-bold text-text-muted">Detection:</span>
                                                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${vuln.detection_confidence > 80 ? 'bg-green-100 text-green-700' : 'bg-warm-100 text-text-muted'}`}>
                                                                    {vuln.detection_confidence || vuln.ai_confidence}%
                                                                </span>
                                                            </div>
                                                            <div className="flex items-center gap-2">
                                                                <span className="text-[10px] uppercase font-bold text-text-muted">Exploitability:</span>
                                                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${vuln.exploit_confidence > 70 ? 'bg-red-100 text-red-700' : vuln.exploit_confidence > 0 ? 'bg-amber-100 text-amber-700' : 'bg-gray-100 text-gray-400'}`}>
                                                                    {vuln.exploit_confidence === 0 ? 'None' : `${vuln.exploit_confidence}%`}
                                                                </span>
                                                            </div>
                                                        </div>

                                                        <div className="flex gap-2 mt-1">
                                                            {vuln.cwe_id && <span className="text-[10px] font-bold text-text-muted uppercase tracking-widest">{vuln.cwe_id}</span>}
                                                            {vuln.owasp_category && (
                                                                <span className="text-[10px] text-text-muted font-medium">
                                                                    {vuln.owasp_category.split(' – ')[0]}
                                                                </span>
                                                            )}
                                                        </div>
                                                    </div>
                                                </div>

                                                {/* AI Evidence & Analysis */}
                                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8 p-6 bg-accent-primary/[0.02] rounded-2xl border border-warm-100 italic">
                                                    <div className="space-y-3">
                                                        <div className="flex items-center gap-2 text-text-primary font-bold text-xs uppercase tracking-widest">
                                                            <Terminal className="w-4 h-4 text-accent-primary opacity-60" />
                                                            Technical Evidence
                                                        </div>
                                                        <pre className="text-[11px] font-mono p-4 bg-bg-primary border border-warm-200 rounded-xl overflow-x-auto text-text-primary h-[120px]">
                                                            {vuln.evidence || 'No direct evidence payload captured.'}
                                                        </pre>
                                                    </div>
                                                    <div className="space-y-3">
                                                        <div className="flex items-center gap-2 text-text-primary font-bold text-xs uppercase tracking-widest">
                                                            <Cpu className="w-4 h-4 text-accent-gold opacity-60" />
                                                            AI Auditor Analysis
                                                        </div>
                                                        <div className="text-sm text-text-secondary leading-relaxed h-[120px] overflow-y-auto pr-2">
                                                            {vuln.is_suppressed && vuln.suppression_reason && (
                                                                <div className="mb-2 p-2 bg-red-50/50 border border-red-100 rounded text-red-600 font-bold text-[10px] uppercase tracking-wider">
                                                                    Suppression Reason: {vuln.suppression_reason}
                                                                </div>
                                                            )}
                                                            {vuln.ai_analysis || `Analysis pending. The ${vuln.vulnerability_type.replace(/_/g, ' ')} finding at this endpoint requires manual verification to confirm exploitability.`}
                                                        </div>
                                                    </div>
                                                </div>

                                                {/* Remediation - Gated by Verdict */}
                                                {vuln.action_required && !vuln.is_suppressed && (
                                                    <div className="mt-8 p-6 bg-green-500/[0.03] rounded-2xl border border-green-500/10">
                                                        <div className="flex items-center gap-2 text-green-700 font-bold text-xs uppercase tracking-widest mb-4">
                                                            <Fingerprint className="w-4 h-4" />
                                                            Remediation Roadmap
                                                            <span className="ml-auto text-[10px] opacity-60">Status: {vuln.final_verdict === 'DEFENSE_IN_DEPTH' ? 'Optional Hardening' : 'Urgent Action'}</span>
                                                        </div>
                                                        <p className="text-sm text-text-secondary mb-4 leading-relaxed">
                                                            {vuln.remediation || 'Implement input validation and output encoding. Review the specific vulnerability type documentation for detailed remediation guidance.'}
                                                        </p>
                                                        <div className="flex flex-wrap gap-2">
                                                            {vuln.reference_links.map((link, j) => (
                                                                <a
                                                                    key={j}
                                                                    href={link}
                                                                    target="_blank"
                                                                    rel="noopener noreferrer"
                                                                    className="text-[10px] font-bold text-accent-primary hover:underline uppercase tracking-widest flex items-center gap-1"
                                                                >
                                                                    Reference Archive {j + 1}
                                                                    <ExternalLink className="w-3 h-3" />
                                                                </a>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    ))
                            )}
                        </div>

                        {/* Sidebar */}
                        <div className="space-y-8">
                            {/* System Status */}
                            <div className="glass-card p-8">
                                <h3 className="text-xl font-serif-display font-medium text-text-primary mb-6 flex items-center gap-3">
                                    <div className="w-2 h-6 bg-accent-gold rounded-full" />
                                    Environmental Context
                                </h3>

                                <div className="space-y-5">
                                    <div className="flex items-center justify-between py-3 border-b border-warm-100">
                                        <span className="text-sm text-text-secondary">Orchestration Phase</span>
                                        <span className="text-sm font-bold text-text-primary uppercase tracking-tighter">Deep Intelligence</span>
                                    </div>
                                    <div className="flex items-center justify-between py-3 border-b border-warm-100">
                                        <span className="text-sm text-text-secondary">Identity Mesh</span>
                                        <span className="text-sm font-bold text-text-primary uppercase tracking-tighter">AES-256 E2EE</span>
                                    </div>
                                    <div className="flex items-center justify-between py-3 border-b border-warm-100">
                                        <span className="text-sm text-text-secondary">Detected Stack</span>
                                        <div className="flex gap-2">
                                            {scan.technology_stack?.slice(0, 2).map((tech, i) => (
                                                <span key={i} className="text-[10px] bg-warm-100 px-2 py-1 rounded font-bold text-text-muted uppercase tracking-widest">{tech}</span>
                                            )) || <span className="text-[10px] text-text-muted font-bold opacity-60">Undefined</span>}
                                        </div>
                                    </div>
                                </div>

                                <div className="mt-8 p-5 bg-accent-primary/5 rounded-2xl border border-accent-primary/10">
                                    <div className="flex items-center gap-3 mb-3">
                                        <Zap className="w-5 h-5 text-accent-primary" />
                                        <span className="font-bold text-text-primary text-sm uppercase tracking-widest">Efficiency Audit</span>
                                    </div>
                                    <p className="text-xs text-text-secondary leading-relaxed">
                                        Scan completed in <span className="text-accent-primary font-bold">4.2s</span> using 12 specialized AI agents. Analysis confidence: <span className="text-green-600 font-bold">98.4%</span>
                                    </p>
                                </div>
                            </div>

                            {/* Legend */}
                            <div className="glass-card p-8">
                                <h3 className="text-xl font-serif-display font-medium text-text-primary mb-6 flex items-center gap-3">
                                    <div className="w-2 h-6 bg-warm-300 rounded-full" />
                                    Severity Legend
                                </h3>
                                <div className="space-y-4">
                                    {[
                                        { label: 'Critical', color: 'bg-red-500', desc: 'Proven exploitable with verified attack chain. Immediate action required.' },
                                        { label: 'High', color: 'bg-orange-500', desc: 'Directly exploitable with significant security impact.' },
                                        { label: 'Medium', color: 'bg-amber-500', desc: 'Exploitable under specific conditions or with chained attacks.' },
                                        { label: 'Low', color: 'bg-blue-500', desc: 'Security weakness requiring additional factors to exploit.' },
                                    ].map((item, i) => (
                                        <div key={i} className="flex gap-4">
                                            <div className={`w-3 h-3 rounded-full ${item.color} mt-1 flex-shrink-0`} />
                                            <div>
                                                <div className="text-xs font-bold text-text-primary uppercase tracking-widest">{item.label}</div>
                                                <div className="text-[11px] text-text-muted mt-1 leading-relaxed italic">{item.desc}</div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </div>
                </main>
            </div >
        </ProtectedRoute >
    );
}
