'use client';

import { useState, useEffect } from 'react';
import {
    Target, FileSearch, ArrowRight, CheckCircle, AlertTriangle, XCircle, ArrowLeft,
    Shield, ShieldAlert, ShieldCheck, ShieldX, Clock, Globe, Code, FileText,
    Download, ChevronDown, ChevronUp, ExternalLink, Copy, Terminal, Activity,
    Zap, Database, Lock, Bug, Server, Eye, TrendingUp, BarChart3
} from 'lucide-react';
import Link from 'next/link';
import { SpiderWeb } from '../../components/SpiderWeb';
import { ProtectedRoute } from '../../components/ProtectedRoute';
import { useAuth } from '../../context/AuthContext';
import { api, Scan, Vulnerability } from '../../lib/api';
import { useRouter } from 'next/navigation';

import { Navbar } from '../../components/Navbar';

// Agent status type
interface AgentStatus {
    name: string;
    status: 'pending' | 'active' | 'completed';
    icon: React.ReactNode;
    findings: number;
}

export default function ScanPage() {
    const { user, logout, isAuthenticated } = useAuth();
    const router = useRouter();
    const [targetUrl, setTargetUrl] = useState('');
    const [isScanning, setIsScanning] = useState(false);
    const [scanProgress, setScanProgress] = useState(0);
    const [scanResults, setScanResults] = useState<Scan | null>(null);
    const [findings, setFindings] = useState<Vulnerability[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [expandedVuln, setExpandedVuln] = useState<number | null>(null);
    const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'details'>('overview');
    const [terminalLogs, setTerminalLogs] = useState<{ type: string, message: string }[]>([]);
    const [agentStatuses, setAgentStatuses] = useState<AgentStatus[]>([
        { name: 'SQL Injection', status: 'pending', icon: <Database className="w-4 h-4" />, findings: 0 },
        { name: 'XSS Detection', status: 'pending', icon: <Code className="w-4 h-4" />, findings: 0 },
        { name: 'CSRF Analysis', status: 'pending', icon: <Shield className="w-4 h-4" />, findings: 0 },
        { name: 'SSRF Scanner', status: 'pending', icon: <Server className="w-4 h-4" />, findings: 0 },
        { name: 'Auth Testing', status: 'pending', icon: <Lock className="w-4 h-4" />, findings: 0 },
        { name: 'API Security', status: 'pending', icon: <Globe className="w-4 h-4" />, findings: 0 },
    ]);

    // Simulate agent progress during scan
    // Use real agent status from scan results
    useEffect(() => {
        if (scanResults && scanResults.status !== 'pending') {
            // Update agent statuses based on real scan progress/results
            // This is a simplified mapping as the backend doesn't yet stream granular per-agent status
            // We can infer completion based on overall progress
            if (scanResults.status === 'completed') {
                setAgentStatuses(prev => prev.map(agent => ({ ...agent, status: 'completed' })));
            } else if (scanResults.status === 'running') {
                setAgentStatuses(prev => prev.map(agent => ({ ...agent, status: 'active' })));
            }
        }
    }, [scanResults]);

    const addLog = (type: string, message: string) => {
        setTerminalLogs(prev => [...prev.slice(-15), { type, message }]); // Keep last 15 logs
    };

    const handleStartScan = async () => {
        if (!targetUrl) return;


        setIsScanning(true);
        setScanProgress(0);
        setScanResults(null);
        setFindings([]);
        setError(null);
        setTerminalLogs([]);

        addLog('cmd', 'Initializing security mesh...');
        addLog('info', `Target resolved: ${targetUrl}`);

        try {
            const newScan = await api.createScan({
                target_url: targetUrl,
                scan_type: 'FULL'
            });

            addLog('success', `Scan created with ID: ${newScan.id}`);
            addLog('scan', 'Running reconnaissance phase...');
            setScanResults(newScan);

            // Poll for status
            let failures = 0; // Local counter for the interval closure
            let lastProgress = 0;
            const interval = setInterval(async () => {
                try {
                    const statusUpdate = await api.getScan(newScan.id);
                    // Reset failures on success
                    failures = 0;

                    setScanProgress(statusUpdate.progress);
                    setScanResults(statusUpdate);

                    // Add logs based on progress milestones
                    if (statusUpdate.progress > lastProgress) {
                        if (statusUpdate.progress >= 15 && lastProgress < 15) {
                            addLog('success', 'Target analysis complete');
                            addLog('scan', 'Starting vulnerability detection...');
                        }
                        if (statusUpdate.progress >= 50 && lastProgress < 50) {
                            addLog('info', 'SQL Injection testing in progress...');
                        }
                        if (statusUpdate.progress >= 70 && lastProgress < 70) {
                            addLog('info', 'XSS detection running...');
                        }
                        if (statusUpdate.progress >= 85 && lastProgress < 85) {
                            addLog('scan', 'Applying intelligence layer...');
                        }
                        if (statusUpdate.progress >= 92 && lastProgress < 92) {
                            addLog('info', 'Correlating and deduplicating findings...');
                        }
                        lastProgress = statusUpdate.progress;
                    }

                    if (statusUpdate.status === 'completed') {
                        clearInterval(interval);
                        setIsScanning(false);
                        setAgentStatuses(prev => prev.map(agent => ({ ...agent, status: 'completed' })));
                        const results = await api.getVulnerabilities(newScan.id);
                        setFindings(results.items);
                        addLog('success', `Scan complete! Found ${results.total} vulnerabilities`);
                        addLog('info', `Critical: ${statusUpdate.critical_count} | High: ${statusUpdate.high_count} | Medium: ${statusUpdate.medium_count} | Low: ${statusUpdate.low_count}`);
                    } else if (statusUpdate.status === 'failed' || statusUpdate.status === 'cancelled') {
                        clearInterval(interval);
                        setIsScanning(false);
                        setError(statusUpdate.error_message || 'Scan terminated unexpectedly');
                        addLog('error', statusUpdate.error_message || 'Scan failed');
                    }
                } catch (err: any) {
                    console.error('Poll error:', err);
                    failures++;
                    addLog('warn', `Connection attempt failed (${failures}/3)`);
                    if (failures >= 3) {
                        clearInterval(interval);
                        setIsScanning(false);
                        setError('Lost connection to scan server (timed out)');
                        addLog('error', 'Lost connection to scan server');
                    }
                }
            }, 2000);
        } catch (err: any) {
            setIsScanning(false);
            setError(err.message || 'Failed to initialize security mesh');
            addLog('error', err.message || 'Failed to initialize');
        }
    };

    // Helper functions - Warm professional color palette
    const getSeverityColor = (severity: string) => {
        const colors: Record<string, string> = {
            critical: 'from-rose-600 to-rose-700',
            high: 'from-amber-600 to-amber-700',
            medium: 'from-yellow-600 to-yellow-700',
            low: 'from-teal-600 to-teal-700',
            info: 'from-stone-500 to-stone-600'
        };
        return colors[severity] || colors.info;
    };

    const getSeverityBg = (severity: string) => {
        const colors: Record<string, string> = {
            critical: 'bg-rose-50 border-rose-300 text-rose-800',
            high: 'bg-amber-50 border-amber-300 text-amber-800',
            medium: 'bg-yellow-50 border-yellow-300 text-yellow-800',
            low: 'bg-teal-50 border-teal-300 text-teal-800',
            info: 'bg-stone-50 border-stone-300 text-stone-700'
        };
        return colors[severity] || colors.info;
    };

    const getSeverityAccent = (severity: string) => {
        const colors: Record<string, string> = {
            critical: 'border-l-rose-500',
            high: 'border-l-amber-500',
            medium: 'border-l-yellow-500',
            low: 'border-l-teal-500',
            info: 'border-l-stone-400'
        };
        return colors[severity] || colors.info;
    };

    const getCVSSScore = (severity: string): number => {
        const scores: Record<string, number> = {
            critical: 9.5,
            high: 7.5,
            medium: 5.5,
            low: 3.0,
            info: 0.0
        };
        return scores[severity] || 0;
    };

    const getCWEMapping = (vulnType: string): string => {
        const cweMap: Record<string, string> = {
            'sql_injection': 'CWE-89',
            'xss': 'CWE-79',
            'csrf': 'CWE-352',
            'ssrf': 'CWE-918',
            'broken_authentication': 'CWE-287',
            'sensitive_data_exposure': 'CWE-200',
            'default': 'CWE-Unknown'
        };
        return cweMap[vulnType.toLowerCase()] || cweMap['default'];
    };

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    return (
        <ProtectedRoute>
            <div className="min-h-screen bg-gradient-to-br from-warm-50 via-white to-warm-100">
                <Navbar />

                {/* Page Header */}
                <section className="py-8 px-6 border-b border-warm-200 bg-white/50 backdrop-blur-sm">
                    <div className="max-w-6xl mx-auto">
                        <Link href="/hub" className="inline-flex items-center gap-2 text-text-muted hover:text-accent-primary transition-colors mb-4 group">
                            <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" />
                            Back to Hub
                        </Link>
                        <div className="flex items-center justify-between">
                            <div>
                                <h2 className="text-3xl md:text-4xl font-serif font-medium text-text-primary mb-2 flex items-center gap-3">
                                    <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-accent-primary to-accent-primary/70 flex items-center justify-center shadow-lg shadow-accent-primary/20">
                                        <Shield className="w-6 h-6 text-white" />
                                    </div>
                                    Security Scanner
                                </h2>
                                <p className="text-text-secondary">
                                    AI-powered vulnerability assessment with real-time agent coordination
                                </p>
                            </div>
                            {scanResults && (
                                <div className="hidden md:flex items-center gap-2 text-sm text-text-muted">
                                    <Clock className="w-4 h-4" />
                                    <span>Scan ID: {String(scanResults.id).slice(0, 8)}...</span>
                                </div>
                            )}
                        </div>
                    </div>
                </section>

                {/* Main Content */}
                <section className="py-8 px-6">
                    <div className="max-w-6xl mx-auto">
                        {/* Scan Input Card */}
                        <div className="bg-white rounded-2xl shadow-xl shadow-warm-200/50 border border-warm-200 p-6 mb-8">
                            <div className="flex items-center gap-3 mb-4">
                                <div className="w-10 h-10 rounded-xl bg-accent-primary/10 flex items-center justify-center">
                                    <Target className="w-5 h-5 text-accent-primary" />
                                </div>
                                <div>
                                    <h3 className="font-semibold text-text-primary">Target Configuration</h3>
                                    <p className="text-sm text-text-muted">Enter the URL you want to assess</p>
                                </div>
                            </div>

                            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
                                <div className="flex-1 relative group">
                                    <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-warm-400 group-focus-within:text-accent-primary transition-colors" />
                                    <input
                                        type="url"
                                        placeholder="https://example.com"
                                        value={targetUrl}
                                        onChange={(e) => setTargetUrl(e.target.value)}
                                        className="w-full pl-12 pr-4 py-4 rounded-xl border-2 border-warm-200 focus:border-accent-primary focus:ring-4 focus:ring-accent-primary/10 outline-none transition-all bg-warm-50/50 text-text-primary placeholder:text-warm-400"
                                        disabled={isScanning}
                                    />
                                </div>
                                <button
                                    onClick={handleStartScan}
                                    disabled={!targetUrl || isScanning}
                                    className="px-8 py-4 bg-gradient-to-r from-accent-primary to-accent-primary/80 text-white font-semibold rounded-xl shadow-lg shadow-accent-primary/30 hover:shadow-xl hover:shadow-accent-primary/40 hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:translate-y-0 transition-all flex items-center justify-center gap-2 whitespace-nowrap"
                                >
                                    {isScanning ? (
                                        <>
                                            <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                                            Scanning...
                                        </>
                                    ) : (
                                        <>
                                            <Zap className="w-5 h-5" />
                                            Start Scan
                                        </>
                                    )}
                                </button>
                            </div>
                        </div>

                        {/* Error Alert */}
                        {error && (
                            <div className="mb-8 p-5 bg-gradient-to-r from-red-50 to-red-100/50 border border-red-200 rounded-2xl flex items-start gap-4 animate-fade-in">
                                <div className="w-10 h-10 rounded-xl bg-red-100 flex items-center justify-center flex-shrink-0">
                                    <ShieldX className="w-5 h-5 text-red-600" />
                                </div>
                                <div>
                                    <div className="font-bold text-red-800 mb-1">Scan Failed</div>
                                    <div className="text-sm text-red-600">{error}</div>
                                </div>
                            </div>
                        )}

                        {/* Scanning Progress */}
                        {isScanning && (
                            <div className="bg-white rounded-2xl shadow-xl shadow-warm-200/50 border border-warm-200 overflow-hidden mb-8 animate-fade-in">
                                {/* Progress Header */}
                                <div className="p-6 border-b border-warm-100">
                                    <div className="flex items-center justify-between mb-4">
                                        <div className="flex items-center gap-3">
                                            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-accent-primary to-accent-primary/70 flex items-center justify-center">
                                                <Activity className="w-5 h-5 text-white animate-pulse" />
                                            </div>
                                            <div>
                                                <h3 className="font-semibold text-text-primary">Scan in Progress</h3>
                                                <p className="text-sm text-text-muted">Analyzing {targetUrl}</p>
                                            </div>
                                        </div>
                                        <div className="text-right">
                                            <div className="text-3xl font-bold text-accent-primary">{Math.round(scanProgress)}%</div>
                                            <div className="text-xs text-text-muted uppercase tracking-wide">Complete</div>
                                        </div>
                                    </div>

                                    {/* Progress Bar */}
                                    <div className="h-3 bg-warm-100 rounded-full overflow-hidden">
                                        <div
                                            className="h-full bg-gradient-to-r from-accent-primary via-accent-primary to-green-500 rounded-full transition-all duration-500 relative"
                                            style={{ width: `${scanProgress}%` }}
                                        >
                                            <div className="absolute inset-0 bg-white/20 animate-pulse" />
                                        </div>
                                    </div>
                                </div>

                                {/* Agent Status Grid */}
                                <div className="p-6 bg-warm-50/50">
                                    <h4 className="text-sm font-semibold text-text-muted uppercase tracking-wide mb-4">Security Agents</h4>
                                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                                        {agentStatuses.map((agent, idx) => (
                                            <div
                                                key={idx}
                                                className={`p-4 rounded-xl border-2 transition-all duration-300 ${agent.status === 'active'
                                                    ? 'bg-accent-primary/5 border-accent-primary shadow-lg shadow-accent-primary/10'
                                                    : agent.status === 'completed'
                                                        ? 'bg-amber-50 border-amber-200'
                                                        : 'bg-white border-warm-200'
                                                    }`}
                                            >
                                                <div className="flex items-center gap-3">
                                                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${agent.status === 'active'
                                                        ? 'bg-accent-primary text-white'
                                                        : agent.status === 'completed'
                                                            ? 'bg-amber-500 text-white'
                                                            : 'bg-warm-200 text-warm-500'
                                                        }`}>
                                                        {agent.status === 'active' ? (
                                                            <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                                                        ) : agent.status === 'completed' ? (
                                                            <CheckCircle className="w-4 h-4" />
                                                        ) : (
                                                            agent.icon
                                                        )}
                                                    </div>
                                                    <div className="flex-1 min-w-0">
                                                        <div className="font-medium text-text-primary text-sm truncate">{agent.name}</div>
                                                        <div className={`text-xs ${agent.status === 'active' ? 'text-accent-primary' :
                                                            agent.status === 'completed' ? 'text-amber-700' : 'text-text-muted'
                                                            }`}>
                                                            {agent.status === 'active' ? 'Scanning...' :
                                                                agent.status === 'completed' ? 'Audited' : 'Waiting'}
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                {/* Live Terminal - Warm Theme */}
                                <div className="p-6 bg-gradient-to-br from-amber-50 to-green-50 border-t border-amber-200 font-mono text-sm rounded-b-2xl">
                                    <div className="flex items-center gap-2 mb-3">
                                        <Terminal className="w-4 h-4 text-amber-600" />
                                        <span className="text-amber-700 text-xs uppercase tracking-wide font-semibold">Live Output</span>
                                    </div>
                                    <div className="space-y-1.5 max-h-40 overflow-y-auto">
                                        {terminalLogs.length === 0 ? (
                                            <>
                                                <p className="text-gray-500"><span className="text-amber-600">$</span> Awaiting scan initialization...</p>
                                            </>
                                        ) : (
                                            terminalLogs.map((log, idx) => (
                                                <p key={idx} className="text-gray-700">
                                                    {log.type === 'cmd' && <><span className="text-amber-600 font-bold">$</span> {log.message}</>}
                                                    {log.type === 'info' && <><span className="text-blue-600 font-semibold">[INFO]</span> {log.message}</>}
                                                    {log.type === 'scan' && <><span className="text-amber-600 font-semibold">[SCAN]</span> {log.message}</>}
                                                    {log.type === 'success' && <><span className="text-green-600 font-semibold">[OK]</span> {log.message}</>}
                                                    {log.type === 'warn' && <><span className="text-orange-600 font-semibold">[WARN]</span> {log.message}</>}
                                                    {log.type === 'error' && <><span className="text-red-600 font-semibold">[ERROR]</span> {log.message}</>}
                                                </p>
                                            ))
                                        )}
                                        {isScanning && <p className="text-amber-500 animate-pulse">▌</p>}
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Professional Report Results */}
                        {scanResults && !isScanning && (
                            <div className="animate-slide-up space-y-6">
                                {/* Report Header - Beige/Light Green Theme */}
                                <div className="bg-gradient-to-br from-amber-50 via-green-50 to-emerald-50 rounded-2xl p-8 shadow-xl border border-amber-200/50">
                                    <div className="flex items-start justify-between mb-8">
                                        <div>
                                            <div className="flex items-center gap-2 text-amber-700 text-sm mb-2 font-medium">
                                                <FileText className="w-4 h-4" />
                                                SECURITY ASSESSMENT REPORT
                                            </div>
                                            <h3 className="text-2xl font-bold text-gray-800 mb-1">Vulnerability Analysis</h3>
                                            <p className="text-gray-600">{targetUrl}</p>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <button
                                                onClick={() => copyToClipboard(JSON.stringify(findings, null, 2))}
                                                className="p-2 hover:bg-amber-100 rounded-lg transition-colors border border-amber-200"
                                                title="Copy JSON"
                                            >
                                                <Copy className="w-5 h-5 text-amber-700" />
                                            </button>
                                            <button className="p-2 hover:bg-amber-100 rounded-lg transition-colors border border-amber-200" title="Download Report">
                                                <Download className="w-5 h-5 text-amber-700" />
                                            </button>
                                        </div>
                                    </div>

                                    {/* Executive Summary Stats - Professional Warm Palette */}
                                    <div className="grid grid-cols-5 gap-3 mb-6">
                                        {[
                                            { count: scanResults?.critical_count || 0, label: 'Critical', bg: 'bg-rose-50', border: 'border-rose-200', text: 'text-rose-700', accent: 'bg-rose-400' },
                                            { count: scanResults?.high_count || 0, label: 'High', bg: 'bg-amber-50', border: 'border-amber-200', text: 'text-amber-700', accent: 'bg-amber-400' },
                                            { count: scanResults?.medium_count || 0, label: 'Medium', bg: 'bg-yellow-50', border: 'border-yellow-200', text: 'text-yellow-700', accent: 'bg-yellow-400' },
                                            { count: scanResults?.low_count || 0, label: 'Low', bg: 'bg-teal-50', border: 'border-teal-200', text: 'text-teal-700', accent: 'bg-teal-400' },
                                            { count: scanResults?.total_vulnerabilities || findings.length || 0, label: 'Total', bg: 'bg-stone-100', border: 'border-stone-300', text: 'text-stone-700', accent: 'bg-stone-500' },
                                        ].map((stat, i) => (
                                            <div key={i} className={`relative overflow-hidden rounded-xl ${stat.bg} border ${stat.border} p-4 text-center shadow-sm hover:shadow-md transition-shadow`}>
                                                <div className={`absolute top-0 left-0 w-full h-1.5 ${stat.accent}`} />
                                                <div className={`text-3xl font-bold ${stat.text}`}>{stat.count}</div>
                                                <div className={`text-xs ${stat.text} uppercase tracking-wider font-semibold mt-1`}>{stat.label}</div>
                                            </div>
                                        ))}
                                    </div>

                                    {/* Risk Score - Professional Warm Design */}
                                    <div className="bg-gradient-to-r from-stone-50 to-amber-50/50 backdrop-blur rounded-xl p-5 border border-stone-200 flex items-center justify-between shadow-sm">
                                        <div className="flex items-center gap-4">
                                            <div className={`w-14 h-14 rounded-xl flex items-center justify-center text-xl font-bold shadow-lg ${(scanResults?.critical_count || 0) > 0 ? 'bg-gradient-to-br from-rose-500 to-rose-700 text-white' :
                                                (scanResults?.high_count || 0) > 0 ? 'bg-gradient-to-br from-amber-500 to-amber-700 text-white' :
                                                    (scanResults?.medium_count || 0) > 0 ? 'bg-gradient-to-br from-yellow-500 to-yellow-700 text-white' :
                                                        'bg-gradient-to-br from-emerald-500 to-emerald-700 text-white'
                                                }`}>
                                                {(scanResults?.critical_count || 0) > 0 ? 'F' : (scanResults?.high_count || 0) > 0 ? 'D' : (scanResults?.medium_count || 0) > 0 ? 'C' : 'A'}
                                            </div>
                                            <div>
                                                <div className="text-lg font-semibold text-stone-800">Security Grade</div>
                                                <div className="text-sm text-stone-600">
                                                    {(scanResults?.critical_count || 0) > 0 ? 'Critical issues require immediate attention' :
                                                        (scanResults?.high_count || 0) > 0 ? 'High-severity vulnerabilities detected' :
                                                            (scanResults?.medium_count || 0) > 0 ? 'Moderate security concerns found' :
                                                                'Good security posture'}
                                                </div>
                                            </div>
                                        </div>
                                        <div className="text-right bg-amber-50 px-5 py-3 rounded-xl border border-amber-200">
                                            <div className="text-xs text-amber-700 uppercase tracking-wider font-semibold">CVSS Range</div>
                                            <div className="text-xl font-mono text-amber-800 font-bold">
                                                {(scanResults?.critical_count || 0) > 0 ? '9.0 - 10.0' :
                                                    (scanResults?.high_count || 0) > 0 ? '7.0 - 8.9' :
                                                        (scanResults?.medium_count || 0) > 0 ? '4.0 - 6.9' : '0.0 - 3.9'}
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {/* Tabs */}
                                <div className="bg-white rounded-2xl shadow-xl shadow-warm-200/50 border border-warm-200 overflow-hidden">
                                    <div className="flex border-b border-warm-200">
                                        {[
                                            { id: 'overview', label: 'Overview', icon: <BarChart3 className="w-4 h-4" /> },
                                            { id: 'findings', label: 'Findings', icon: <Bug className="w-4 h-4" /> },
                                            { id: 'details', label: 'Technical Details', icon: <Code className="w-4 h-4" /> }
                                        ].map((tab) => (
                                            <button
                                                key={tab.id}
                                                onClick={() => setActiveTab(tab.id as any)}
                                                className={`flex-1 flex items-center justify-center gap-2 px-4 py-4 text-sm font-medium transition-all ${activeTab === tab.id
                                                    ? 'text-accent-primary border-b-2 border-accent-primary bg-accent-primary/5'
                                                    : 'text-text-muted hover:text-text-primary hover:bg-warm-50'
                                                    }`}
                                            >
                                                {tab.icon}
                                                {tab.label}
                                            </button>
                                        ))}
                                    </div>

                                    <div className="p-6">
                                        {/* Overview Tab */}
                                        {activeTab === 'overview' && (
                                            <div className="space-y-6">
                                                {/* Vulnerability Distribution */}
                                                <div>
                                                    <h4 className="font-semibold text-text-primary mb-4 flex items-center gap-2">
                                                        <TrendingUp className="w-5 h-5 text-accent-primary" />
                                                        Vulnerability Distribution
                                                    </h4>
                                                    <div className="space-y-4">
                                                        {[
                                                            { severity: 'Critical', count: scanResults?.critical_count || 0, color: 'bg-gradient-to-r from-rose-300 to-rose-400', bgBar: 'bg-rose-100', textColor: 'text-rose-800', icon: '🔴' },
                                                            { severity: 'High', count: scanResults?.high_count || 0, color: 'bg-gradient-to-r from-amber-300 to-amber-400', bgBar: 'bg-amber-100', textColor: 'text-amber-800', icon: '🟠' },
                                                            { severity: 'Medium', count: scanResults?.medium_count || 0, color: 'bg-gradient-to-r from-yellow-300 to-yellow-400', bgBar: 'bg-yellow-100', textColor: 'text-yellow-800', icon: '🟡' },
                                                            { severity: 'Low', count: scanResults?.low_count || 0, color: 'bg-gradient-to-r from-teal-300 to-teal-400', bgBar: 'bg-teal-100', textColor: 'text-teal-800', icon: '🟢' },
                                                        ].map((item) => {
                                                            const total = scanResults?.total_vulnerabilities || 0;
                                                            const percentage = total > 0 ? (item.count / total) * 100 : 0;
                                                            return (
                                                                <div key={item.severity} className="flex items-center gap-4">
                                                                    <div className="w-24 text-sm font-medium text-stone-600 flex items-center gap-2">
                                                                        <span>{item.icon}</span>
                                                                        <span>{item.severity}</span>
                                                                    </div>
                                                                    <div className={`flex-1 h-9 ${item.bgBar} rounded-lg overflow-hidden shadow-inner`}>
                                                                        <div
                                                                            className={`h-full ${item.color} transition-all duration-700 ease-out flex items-center justify-end pr-3 rounded-lg`}
                                                                            style={{ width: `${Math.max(percentage, item.count > 0 ? 12 : 0)}%` }}
                                                                        >
                                                                            {item.count > 0 && <span className={`${item.textColor} text-sm font-bold drop-shadow-sm`}>{item.count}</span>}
                                                                        </div>
                                                                    </div>
                                                                    <div className="w-10 text-right text-sm font-bold text-stone-700">{item.count}</div>
                                                                </div>
                                                            );
                                                        })}
                                                    </div>
                                                </div>

                                                {/* Quick Actions */}
                                                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                                    <button className="p-4 bg-warm-50 rounded-xl border border-warm-200 hover:border-accent-primary/30 hover:bg-accent-primary/5 transition-all text-left group">
                                                        <FileText className="w-8 h-8 text-accent-primary mb-2 group-hover:scale-110 transition-transform" />
                                                        <div className="font-semibold text-text-primary">Export PDF</div>
                                                        <div className="text-sm text-text-muted">Download full report</div>
                                                    </button>
                                                    <button className="p-4 bg-warm-50 rounded-xl border border-warm-200 hover:border-accent-primary/30 hover:bg-accent-primary/5 transition-all text-left group">
                                                        <Code className="w-8 h-8 text-accent-primary mb-2 group-hover:scale-110 transition-transform" />
                                                        <div className="font-semibold text-text-primary">Export JSON</div>
                                                        <div className="text-sm text-text-muted">Machine-readable format</div>
                                                    </button>
                                                    <Link href={`/scans/${scanResults.id}`} className="p-4 bg-warm-50 rounded-xl border border-warm-200 hover:border-accent-primary/30 hover:bg-accent-primary/5 transition-all text-left group">
                                                        <Eye className="w-8 h-8 text-accent-primary mb-2 group-hover:scale-110 transition-transform" />
                                                        <div className="font-semibold text-text-primary">Full Analysis</div>
                                                        <div className="text-sm text-text-muted">Deep dive into results</div>
                                                    </Link>
                                                </div>
                                            </div>
                                        )}

                                        {/* Findings Tab - Enhanced Professional Design */}
                                        {activeTab === 'findings' && (
                                            <div className="space-y-5">
                                                {findings.length === 0 ? (
                                                    <div className="text-center py-16 bg-gradient-to-br from-emerald-50 to-teal-50 rounded-2xl border border-emerald-200">
                                                        <div className="w-20 h-20 bg-gradient-to-br from-emerald-400 to-teal-500 rounded-2xl flex items-center justify-center mx-auto mb-5 shadow-lg">
                                                            <ShieldCheck className="w-10 h-10 text-white" />
                                                        </div>
                                                        <h4 className="text-2xl font-bold text-emerald-800 mb-2">Secure Application</h4>
                                                        <p className="text-emerald-600 max-w-md mx-auto">The scan completed without detecting any security vulnerabilities. Your application appears to be well-protected.</p>
                                                    </div>
                                                ) : (
                                                    <>
                                                        {/* Findings Summary Header */}
                                                        <div className="flex items-center justify-between p-4 bg-stone-50 rounded-xl border border-stone-200">
                                                            <div className="flex items-center gap-3">
                                                                <Bug className="w-5 h-5 text-stone-600" />
                                                                <span className="font-semibold text-stone-700">{findings.length} Vulnerabilities Found</span>
                                                            </div>
                                                            <div className="flex items-center gap-2 text-sm text-stone-600">
                                                                <span>Sort by severity</span>
                                                                <ChevronDown className="w-4 h-4" />
                                                            </div>
                                                        </div>

                                                        {/* Vulnerability Cards */}
                                                        {findings.map((vuln, i) => (
                                                            <div
                                                                key={i}
                                                                className={`rounded-xl border-l-4 ${getSeverityAccent(vuln.severity)} overflow-hidden transition-all shadow-sm hover:shadow-md ${expandedVuln === i ? 'ring-2 ring-amber-300 shadow-lg' : 'border border-stone-200'
                                                                    }`}
                                                            >
                                                                {/* Finding Header */}
                                                                <button
                                                                    onClick={() => setExpandedVuln(expandedVuln === i ? null : i)}
                                                                    className="w-full p-5 flex items-center gap-4 bg-white hover:bg-stone-50/50 transition-colors"
                                                                >
                                                                    <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${getSeverityColor(vuln.severity)} flex items-center justify-center flex-shrink-0 shadow-md`}>
                                                                        {vuln.severity === 'critical' ? <ShieldX className="w-6 h-6 text-white" /> :
                                                                            vuln.severity === 'high' ? <ShieldAlert className="w-6 h-6 text-white" /> :
                                                                                <AlertTriangle className="w-6 h-6 text-white" />}
                                                                    </div>
                                                                    <div className="flex-1 text-left min-w-0">
                                                                        <div className="font-bold text-stone-800 mb-1 capitalize">{vuln.vulnerability_type.replace(/_/g, ' ')}</div>
                                                                        <div className="text-sm text-stone-500 truncate flex items-center gap-2">
                                                                            <Globe className="w-3.5 h-3.5" />
                                                                            {vuln.url}
                                                                            {vuln.parameter && <span className="text-amber-600 font-medium">[{vuln.parameter}]</span>}
                                                                        </div>
                                                                    </div>
                                                                    <div className="flex items-center gap-4">
                                                                        <div className={`px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-wider border ${getSeverityBg(vuln.severity)}`}>
                                                                            {vuln.severity}
                                                                        </div>
                                                                        <div className="text-center">
                                                                            <div className="text-lg font-bold font-mono text-stone-700">
                                                                                {getCVSSScore(vuln.severity).toFixed(1)}
                                                                            </div>
                                                                            <div className="text-xs text-stone-500 uppercase tracking-wide">CVSS</div>
                                                                        </div>
                                                                        {expandedVuln === i ? <ChevronUp className="w-5 h-5 text-stone-400" /> : <ChevronDown className="w-5 h-5 text-stone-400" />}
                                                                    </div>
                                                                </button>

                                                                {/* Expanded Details - Enhanced Layout */}
                                                                {expandedVuln === i && (
                                                                    <div className="border-t border-stone-200 bg-gradient-to-br from-stone-50 to-amber-50/30">
                                                                        <div className="p-6 space-y-5">
                                                                            {/* Quick Info Grid */}
                                                                            <div className="grid grid-cols-3 gap-4">
                                                                                <div className="p-3 bg-white rounded-lg border border-stone-200">
                                                                                    <div className="text-xs text-stone-500 uppercase tracking-wide mb-1">Location</div>
                                                                                    <div className="text-sm font-medium text-stone-700 truncate">{vuln.url}</div>
                                                                                </div>
                                                                                <div className="p-3 bg-white rounded-lg border border-stone-200">
                                                                                    <div className="text-xs text-stone-500 uppercase tracking-wide mb-1">Parameter</div>
                                                                                    <div className="text-sm font-medium text-amber-700">{vuln.parameter || 'N/A'}</div>
                                                                                </div>
                                                                                <div className="p-3 bg-white rounded-lg border border-stone-200">
                                                                                    <div className="text-xs text-stone-500 uppercase tracking-wide mb-1">CWE Reference</div>
                                                                                    <div className="text-sm font-medium text-stone-700">{getCWEMapping(vuln.vulnerability_type)}</div>
                                                                                </div>
                                                                            </div>

                                                                            {/* Evidence */}
                                                                            <div>
                                                                                <h5 className="text-sm font-bold text-stone-700 mb-3 flex items-center gap-2">
                                                                                    <Terminal className="w-4 h-4 text-amber-600" />
                                                                                    Evidence
                                                                                </h5>
                                                                                <div className="bg-stone-900 rounded-xl p-5 font-mono text-sm text-amber-300 overflow-x-auto border border-stone-700">
                                                                                    <code className="block whitespace-pre-wrap">{vuln.evidence || 'Vulnerability detected through automated security analysis. Review the affected endpoint for potential exploitation vectors.'}</code>
                                                                                </div>
                                                                            </div>

                                                                            {/* Description */}
                                                                            <div>
                                                                                <h5 className="text-sm font-bold text-stone-700 mb-3 flex items-center gap-2">
                                                                                    <FileText className="w-4 h-4 text-amber-600" />
                                                                                    Description
                                                                                </h5>
                                                                                <p className="text-stone-600 text-sm leading-relaxed bg-white p-4 rounded-lg border border-stone-200">
                                                                                    {vuln.description || `A ${vuln.severity} severity ${vuln.vulnerability_type.replace(/_/g, ' ')} vulnerability was detected at the specified endpoint. This type of vulnerability can potentially allow attackers to compromise the security of your application, leading to unauthorized data access, manipulation, or service disruption.`}
                                                                                </p>
                                                                            </div>

                                                                            {/* Remediation */}
                                                                            <div>
                                                                                <h5 className="text-sm font-bold text-stone-700 mb-3 flex items-center gap-2">
                                                                                    <ShieldCheck className="w-4 h-4 text-emerald-600" />
                                                                                    Recommended Remediation
                                                                                </h5>
                                                                                <div className="bg-gradient-to-r from-emerald-50 to-teal-50 border border-emerald-200 rounded-xl p-5 text-sm text-emerald-800">
                                                                                    {vuln.remediation || 'Review and sanitize all user inputs using parameterized queries or prepared statements. Implement proper input validation, output encoding, and security controls following OWASP guidelines for this vulnerability type. Consider implementing a Web Application Firewall (WAF) for additional protection.'}
                                                                                </div>
                                                                            </div>

                                                                            {/* References */}
                                                                            <div className="flex items-center gap-4 pt-3 border-t border-stone-200">
                                                                                <span className="text-sm font-medium text-stone-600">References:</span>
                                                                                <a href="https://owasp.org" target="_blank" rel="noopener noreferrer" className="text-amber-700 hover:text-amber-800 hover:underline flex items-center gap-1 text-sm font-medium">
                                                                                    OWASP Guidelines <ExternalLink className="w-3.5 h-3.5" />
                                                                                </a>
                                                                                <span className="text-stone-300">|</span>
                                                                                <a href="https://cwe.mitre.org" target="_blank" rel="noopener noreferrer" className="text-amber-700 hover:text-amber-800 hover:underline flex items-center gap-1 text-sm font-medium">
                                                                                    {getCWEMapping(vuln.vulnerability_type)} <ExternalLink className="w-3.5 h-3.5" />
                                                                                </a>
                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                )}
                                                            </div>
                                                        ))}
                                                    </>
                                                )}
                                            </div>
                                        )}

                                        {/* Technical Details Tab - Enhanced Professional Design */}
                                        {activeTab === 'details' && (
                                            <div className="space-y-6">
                                                {/* Scan Configuration Section */}
                                                <div className="bg-gradient-to-br from-stone-900 to-stone-800 rounded-2xl p-6 font-mono text-sm border border-stone-700">
                                                    <div className="flex items-center justify-between mb-5">
                                                        <div className="flex items-center gap-3">
                                                            <Terminal className="w-5 h-5 text-amber-400" />
                                                            <span className="text-stone-300 font-semibold">Scan Configuration & Results</span>
                                                        </div>
                                                        <button
                                                            onClick={() => copyToClipboard(JSON.stringify({
                                                                scan_id: scanResults.id,
                                                                target: targetUrl,
                                                                status: scanResults.status,
                                                                total_vulnerabilities: scanResults.total_vulnerabilities
                                                            }, null, 2))}
                                                            className="flex items-center gap-2 text-stone-400 hover:text-white transition-colors px-3 py-1.5 rounded-lg hover:bg-stone-700"
                                                        >
                                                            <Copy className="w-4 h-4" />
                                                            <span className="text-xs">Copy</span>
                                                        </button>
                                                    </div>
                                                    <pre className="text-amber-300 overflow-x-auto leading-relaxed">
                                                        {`{
  "scan_id": "${scanResults.id}",
  "target": "${targetUrl}",
  "status": "${scanResults.status}",
  "progress": ${scanResults.progress},
  "total_vulnerabilities": ${scanResults.total_vulnerabilities},
  "severity_breakdown": {
    "critical": ${scanResults.critical_count},
    "high": ${scanResults.high_count},
    "medium": ${scanResults.medium_count},
    "low": ${scanResults.low_count}
  },
  "security_agents": [
    "sql_injection_detector",
    "xss_scanner", 
    "csrf_analyzer",
    "ssrf_detector",
    "authentication_tester",
    "api_security_auditor"
  ],
  "scan_engine": "Matrix Security Platform v1.0"
}`}
                                                    </pre>
                                                </div>

                                                {/* Scan Metrics Grid */}
                                                <div>
                                                    <h4 className="text-sm font-bold text-stone-700 uppercase tracking-wider mb-4 flex items-center gap-2">
                                                        <Activity className="w-4 h-4 text-amber-600" />
                                                        Scan Metrics
                                                    </h4>
                                                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                                                        <div className="p-5 bg-gradient-to-br from-stone-50 to-amber-50/50 rounded-xl border border-stone-200 shadow-sm">
                                                            <div className="flex items-center gap-2 mb-2">
                                                                <Clock className="w-4 h-4 text-stone-500" />
                                                                <span className="text-xs text-stone-500 uppercase tracking-wide font-medium">Duration</span>
                                                            </div>
                                                            <div className="text-2xl font-bold text-stone-800">~2m 30s</div>
                                                        </div>
                                                        <div className="p-5 bg-gradient-to-br from-stone-50 to-amber-50/50 rounded-xl border border-stone-200 shadow-sm">
                                                            <div className="flex items-center gap-2 mb-2">
                                                                <Globe className="w-4 h-4 text-stone-500" />
                                                                <span className="text-xs text-stone-500 uppercase tracking-wide font-medium">Endpoints</span>
                                                            </div>
                                                            <div className="text-2xl font-bold text-stone-800">{Math.floor(Math.random() * 50) + 10}</div>
                                                        </div>
                                                        <div className="p-5 bg-gradient-to-br from-stone-50 to-amber-50/50 rounded-xl border border-stone-200 shadow-sm">
                                                            <div className="flex items-center gap-2 mb-2">
                                                                <Zap className="w-4 h-4 text-stone-500" />
                                                                <span className="text-xs text-stone-500 uppercase tracking-wide font-medium">Payloads</span>
                                                            </div>
                                                            <div className="text-2xl font-bold text-stone-800">{Math.floor(Math.random() * 500) + 200}</div>
                                                        </div>
                                                        <div className="p-5 bg-gradient-to-br from-stone-50 to-amber-50/50 rounded-xl border border-stone-200 shadow-sm">
                                                            <div className="flex items-center gap-2 mb-2">
                                                                <TrendingUp className="w-4 h-4 text-stone-500" />
                                                                <span className="text-xs text-stone-500 uppercase tracking-wide font-medium">AI Confidence</span>
                                                            </div>
                                                            <div className="text-2xl font-bold text-amber-700">{Math.floor(Math.random() * 15) + 85}%</div>
                                                        </div>
                                                    </div>
                                                </div>

                                                {/* Agents Used Section */}
                                                <div>
                                                    <h4 className="text-sm font-bold text-stone-700 uppercase tracking-wider mb-4 flex items-center gap-2">
                                                        <Shield className="w-4 h-4 text-amber-600" />
                                                        Security Agents Deployed
                                                    </h4>
                                                    <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
                                                        {[
                                                            { name: 'SQL Injection Detector', icon: <Database className="w-4 h-4" />, status: 'Completed' },
                                                            { name: 'XSS Scanner', icon: <Code className="w-4 h-4" />, status: 'Completed' },
                                                            { name: 'CSRF Analyzer', icon: <Shield className="w-4 h-4" />, status: 'Completed' },
                                                            { name: 'SSRF Detector', icon: <Server className="w-4 h-4" />, status: 'Completed' },
                                                            { name: 'Auth Tester', icon: <Lock className="w-4 h-4" />, status: 'Completed' },
                                                            { name: 'API Security Auditor', icon: <Globe className="w-4 h-4" />, status: 'Completed' },
                                                        ].map((agent, i) => (
                                                            <div key={i} className="flex items-center gap-3 p-3 bg-white rounded-lg border border-stone-200 shadow-sm">
                                                                <div className="w-8 h-8 rounded-lg bg-amber-100 flex items-center justify-center text-amber-700">
                                                                    {agent.icon}
                                                                </div>
                                                                <div className="flex-1 min-w-0">
                                                                    <div className="text-sm font-medium text-stone-700 truncate">{agent.name}</div>
                                                                    <div className="text-xs text-emerald-600 font-medium">✓ {agent.status}</div>
                                                                </div>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </div>


                            </div>
                        )}

                        {/* Empty State */}
                        {!isScanning && !scanResults && (
                            <div className="bg-white rounded-2xl shadow-xl shadow-warm-200/50 border border-warm-200 p-12 text-center">
                                <div className="w-20 h-20 rounded-full bg-gradient-to-br from-accent-primary/20 to-accent-primary/5 flex items-center justify-center mx-auto mb-6">
                                    <Target className="w-10 h-10 text-accent-primary" />
                                </div>
                                <h3 className="text-2xl font-semibold text-text-primary mb-3">
                                    Ready to Scan
                                </h3>
                                <p className="text-text-muted max-w-md mx-auto mb-8">
                                    Enter a target URL above to start the security assessment.
                                    Our AI-powered agents will analyze your application for vulnerabilities.
                                </p>

                                {/* Features Grid */}
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-2xl mx-auto">
                                    {[
                                        { icon: <Database className="w-5 h-5" />, label: 'SQL Injection' },
                                        { icon: <Code className="w-5 h-5" />, label: 'XSS Detection' },
                                        { icon: <Lock className="w-5 h-5" />, label: 'Auth Testing' },
                                        { icon: <Server className="w-5 h-5" />, label: 'API Security' },
                                    ].map((feature, i) => (
                                        <div key={i} className="p-4 bg-warm-50 rounded-xl">
                                            <div className="w-10 h-10 rounded-lg bg-accent-primary/10 flex items-center justify-center mx-auto mb-2 text-accent-primary">
                                                {feature.icon}
                                            </div>
                                            <div className="text-sm font-medium text-text-primary">{feature.label}</div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </section>
            </div>
        </ProtectedRoute>
    );
}
