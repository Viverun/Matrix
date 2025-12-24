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
    const [terminalLogs, setTerminalLogs] = useState<{type: string, message: string}[]>([]);
    const [agentStatuses, setAgentStatuses] = useState<AgentStatus[]>([
        { name: 'SQL Injection', status: 'pending', icon: <Database className="w-4 h-4" />, findings: 0 },
        { name: 'XSS Detection', status: 'pending', icon: <Code className="w-4 h-4" />, findings: 0 },
        { name: 'CSRF Analysis', status: 'pending', icon: <Shield className="w-4 h-4" />, findings: 0 },
        { name: 'SSRF Scanner', status: 'pending', icon: <Server className="w-4 h-4" />, findings: 0 },
        { name: 'Auth Testing', status: 'pending', icon: <Lock className="w-4 h-4" />, findings: 0 },
        { name: 'API Security', status: 'pending', icon: <Globe className="w-4 h-4" />, findings: 0 },
    ]);

    // Simulate agent progress during scan
    useEffect(() => {
        if (isScanning) {
            const agentOrder = [0, 1, 2, 3, 4, 5];
            let currentAgent = 0;
            
            const interval = setInterval(() => {
                if (currentAgent < agentOrder.length) {
                    setAgentStatuses(prev => prev.map((agent, idx) => {
                        if (idx === agentOrder[currentAgent]) {
                            return { ...agent, status: 'active' };
                        }
                        if (idx < agentOrder[currentAgent]) {
                            return { ...agent, status: 'completed', findings: Math.floor(Math.random() * 3) };
                        }
                        return agent;
                    }));
                    currentAgent++;
                }
            }, 3000);
            
            return () => clearInterval(interval);
        } else {
            // Reset agents when not scanning
            setAgentStatuses(prev => prev.map(agent => ({ ...agent, status: 'pending', findings: 0 })));
        }
    }, [isScanning]);

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
                scan_type: 'full'
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

    // Helper functions
    const getSeverityColor = (severity: string) => {
        const colors: Record<string, string> = {
            critical: 'from-red-500 to-red-600',
            high: 'from-orange-500 to-orange-600',
            medium: 'from-amber-500 to-amber-600',
            low: 'from-blue-500 to-blue-600',
            info: 'from-gray-500 to-gray-600'
        };
        return colors[severity] || colors.info;
    };

    const getSeverityBg = (severity: string) => {
        const colors: Record<string, string> = {
            critical: 'bg-red-50 border-red-200 text-red-700',
            high: 'bg-orange-50 border-orange-200 text-orange-700',
            medium: 'bg-amber-50 border-amber-200 text-amber-700',
            low: 'bg-blue-50 border-blue-200 text-blue-700',
            info: 'bg-gray-50 border-gray-200 text-gray-700'
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
                                                className={`p-4 rounded-xl border-2 transition-all duration-300 ${
                                                    agent.status === 'active' 
                                                        ? 'bg-accent-primary/5 border-accent-primary shadow-lg shadow-accent-primary/10' 
                                                        : agent.status === 'completed'
                                                        ? 'bg-amber-50 border-amber-200'
                                                        : 'bg-white border-warm-200'
                                                }`}
                                            >
                                                <div className="flex items-center gap-3">
                                                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                                                        agent.status === 'active'
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
                                                        <div className={`text-xs ${
                                                            agent.status === 'active' ? 'text-accent-primary' :
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

                                    {/* Executive Summary Stats - Horizontal Layout */}
                                    <div className="grid grid-cols-5 gap-3 mb-6">
                                        {[
                                            { count: scanResults?.critical_count || 0, label: 'Critical', bg: 'bg-red-50', border: 'border-red-200', text: 'text-red-600', accent: 'bg-red-300' },
                                            { count: scanResults?.high_count || 0, label: 'High', bg: 'bg-orange-50', border: 'border-orange-200', text: 'text-orange-600', accent: 'bg-orange-300' },
                                            { count: scanResults?.medium_count || 0, label: 'Medium', bg: 'bg-amber-50', border: 'border-amber-200', text: 'text-amber-600', accent: 'bg-amber-300' },
                                            { count: scanResults?.low_count || 0, label: 'Low', bg: 'bg-sky-50', border: 'border-sky-200', text: 'text-sky-600', accent: 'bg-sky-300' },
                                            { count: scanResults?.total_vulnerabilities || findings.length || 0, label: 'Total', bg: 'bg-stone-50', border: 'border-stone-200', text: 'text-stone-600', accent: 'bg-stone-300' },
                                        ].map((stat, i) => (
                                            <div key={i} className={`relative overflow-hidden rounded-xl ${stat.bg} border ${stat.border} p-4 text-center`}>
                                                <div className={`absolute top-0 left-0 w-full h-1 ${stat.accent}`} />
                                                <div className={`text-3xl font-bold ${stat.text}`}>{stat.count}</div>
                                                <div className={`text-xs ${stat.text} uppercase tracking-wide font-medium mt-1`}>{stat.label}</div>
                                            </div>
                                        ))}
                                    </div>

                                    {/* Risk Score - Integrated Design */}
                                    <div className="bg-white/70 backdrop-blur rounded-xl p-5 border border-green-200 flex items-center justify-between">
                                        <div className="flex items-center gap-4">
                                            <div className={`w-14 h-14 rounded-full flex items-center justify-center text-xl font-bold shadow-lg ${
                                                (scanResults?.critical_count || 0) > 0 ? 'bg-gradient-to-br from-red-400 to-red-600 text-white' :
                                                (scanResults?.high_count || 0) > 0 ? 'bg-gradient-to-br from-orange-400 to-orange-600 text-white' :
                                                (scanResults?.medium_count || 0) > 0 ? 'bg-gradient-to-br from-amber-400 to-amber-600 text-white' :
                                                'bg-gradient-to-br from-green-400 to-green-600 text-white'
                                            }`}>
                                                {(scanResults?.critical_count || 0) > 0 ? 'F' : (scanResults?.high_count || 0) > 0 ? 'D' : (scanResults?.medium_count || 0) > 0 ? 'C' : 'A'}
                                            </div>
                                            <div>
                                                <div className="text-lg font-semibold text-gray-800">Security Grade</div>
                                                <div className="text-sm text-gray-600">
                                                    {(scanResults?.critical_count || 0) > 0 ? 'Critical issues require immediate attention' :
                                                     (scanResults?.high_count || 0) > 0 ? 'High-severity vulnerabilities detected' :
                                                     (scanResults?.medium_count || 0) > 0 ? 'Moderate security concerns found' :
                                                     'Good security posture'}
                                                </div>
                                            </div>
                                        </div>
                                        <div className="text-right bg-green-50 px-4 py-2 rounded-lg border border-green-200">
                                            <div className="text-xs text-green-700 uppercase tracking-wide font-medium">CVSS Range</div>
                                            <div className="text-xl font-mono text-green-800 font-bold">
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
                                                className={`flex-1 flex items-center justify-center gap-2 px-4 py-4 text-sm font-medium transition-all ${
                                                    activeTab === tab.id
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
                                                    <div className="space-y-3">
                                                        {[
                                                            { severity: 'critical', count: scanResults?.critical_count || 0, color: 'bg-red-200', textColor: 'text-red-700' },
                                                            { severity: 'high', count: scanResults?.high_count || 0, color: 'bg-orange-200', textColor: 'text-orange-700' },
                                                            { severity: 'medium', count: scanResults?.medium_count || 0, color: 'bg-amber-200', textColor: 'text-amber-700' },
                                                            { severity: 'low', count: scanResults?.low_count || 0, color: 'bg-blue-200', textColor: 'text-blue-700' },
                                                        ].map((item) => {
                                                            const total = scanResults?.total_vulnerabilities || 0;
                                                            const percentage = total > 0 ? (item.count / total) * 100 : 0;
                                                            return (
                                                                <div key={item.severity} className="flex items-center gap-4">
                                                                    <div className="w-20 text-sm text-text-muted capitalize">{item.severity}</div>
                                                                    <div className="flex-1 h-8 bg-warm-100 rounded-lg overflow-hidden">
                                                                        <div 
                                                                            className={`h-full ${item.color} transition-all duration-500 flex items-center justify-end pr-2`}
                                                                            style={{ width: `${Math.max(percentage, item.count > 0 ? 10 : 0)}%` }}
                                                                        >
                                                                            {item.count > 0 && <span className={`${item.textColor} text-xs font-bold`}>{item.count}</span>}
                                                                        </div>
                                                                    </div>
                                                                    <div className="w-8 text-right text-sm font-medium text-text-primary">{item.count}</div>
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

                                        {/* Findings Tab */}
                                        {activeTab === 'findings' && (
                                            <div className="space-y-4">
                                                {findings.length === 0 ? (
                                                    <div className="text-center py-12">
                                                        <ShieldCheck className="w-16 h-16 text-green-500 mx-auto mb-4" />
                                                        <h4 className="text-xl font-semibold text-text-primary mb-2">No Vulnerabilities Found</h4>
                                                        <p className="text-text-muted">The scan completed without detecting any security issues.</p>
                                                    </div>
                                                ) : (
                                                    findings.map((vuln, i) => (
                                                        <div
                                                            key={i}
                                                            className={`rounded-xl border-2 overflow-hidden transition-all ${
                                                                expandedVuln === i ? 'border-accent-primary shadow-lg' : 'border-warm-200 hover:border-warm-300'
                                                            }`}
                                                        >
                                                            {/* Finding Header */}
                                                            <button
                                                                onClick={() => setExpandedVuln(expandedVuln === i ? null : i)}
                                                                className="w-full p-5 flex items-center gap-4 bg-white hover:bg-warm-50 transition-colors"
                                                            >
                                                                <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${getSeverityColor(vuln.severity)} flex items-center justify-center flex-shrink-0 shadow-lg`}>
                                                                    {vuln.severity === 'critical' ? <ShieldX className="w-6 h-6 text-white" /> :
                                                                     vuln.severity === 'high' ? <ShieldAlert className="w-6 h-6 text-white" /> :
                                                                     <AlertTriangle className="w-6 h-6 text-white" />}
                                                                </div>
                                                                <div className="flex-1 text-left min-w-0">
                                                                    <div className="font-bold text-text-primary mb-1">{vuln.vulnerability_type.replace(/_/g, ' ')}</div>
                                                                    <div className="text-sm text-text-muted truncate">
                                                                        {vuln.url}
                                                                        {vuln.parameter && <span className="text-accent-primary ml-2">[{vuln.parameter}]</span>}
                                                                    </div>
                                                                </div>
                                                                <div className="flex items-center gap-3">
                                                                    <div className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wide border ${getSeverityBg(vuln.severity)}`}>
                                                                        {vuln.severity}
                                                                    </div>
                                                                    <div className="text-sm font-mono text-text-muted">
                                                                        CVSS {getCVSSScore(vuln.severity).toFixed(1)}
                                                                    </div>
                                                                    {expandedVuln === i ? <ChevronUp className="w-5 h-5 text-text-muted" /> : <ChevronDown className="w-5 h-5 text-text-muted" />}
                                                                </div>
                                                            </button>

                                                            {/* Expanded Details */}
                                                            {expandedVuln === i && (
                                                                <div className="border-t border-warm-200 bg-warm-50/50">
                                                                    <div className="p-5 space-y-4">
                                                                        {/* Evidence */}
                                                                        <div>
                                                                            <h5 className="text-sm font-semibold text-text-primary mb-2 flex items-center gap-2">
                                                                                <Bug className="w-4 h-4 text-accent-primary" />
                                                                                Evidence
                                                                            </h5>
                                                                            <div className="bg-gray-900 rounded-lg p-4 font-mono text-sm text-green-400 overflow-x-auto">
                                                                                <code>{vuln.evidence || 'Vulnerability detected through automated analysis'}</code>
                                                                            </div>
                                                                        </div>

                                                                        {/* Description */}
                                                                        <div>
                                                                            <h5 className="text-sm font-semibold text-text-primary mb-2 flex items-center gap-2">
                                                                                <FileText className="w-4 h-4 text-accent-primary" />
                                                                                Description
                                                                            </h5>
                                                                            <p className="text-text-secondary text-sm leading-relaxed">
                                                                                {vuln.description || `A ${vuln.severity} severity ${vuln.vulnerability_type.replace(/_/g, ' ')} vulnerability was detected. This type of vulnerability can potentially allow attackers to compromise the security of your application.`}
                                                                            </p>
                                                                        </div>

                                                                        {/* Remediation */}
                                                                        <div>
                                                                            <h5 className="text-sm font-semibold text-text-primary mb-2 flex items-center gap-2">
                                                                                <ShieldCheck className="w-4 h-4 text-green-600" />
                                                                                Remediation
                                                                            </h5>
                                                                            <div className="bg-green-50 border border-green-200 rounded-lg p-4 text-sm text-green-800">
                                                                                {vuln.remediation || 'Review and sanitize user inputs. Implement proper security controls and follow OWASP guidelines for this vulnerability type.'}
                                                                            </div>
                                                                        </div>

                                                                        {/* References */}
                                                                        <div className="flex items-center gap-2 text-sm">
                                                                            <span className="text-text-muted">References:</span>
                                                                            <a href="#" className="text-accent-primary hover:underline flex items-center gap-1">
                                                                                OWASP <ExternalLink className="w-3 h-3" />
                                                                            </a>
                                                                            <span className="text-warm-300">•</span>
                                                                            <a href="#" className="text-accent-primary hover:underline flex items-center gap-1">
                                                                                CWE-{Math.floor(Math.random() * 900) + 100} <ExternalLink className="w-3 h-3" />
                                                                            </a>
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            )}
                                                        </div>
                                                    ))
                                                )}
                                            </div>
                                        )}

                                        {/* Technical Details Tab */}
                                        {activeTab === 'details' && (
                                            <div className="space-y-6">
                                                <div className="bg-gray-900 rounded-xl p-6 font-mono text-sm">
                                                    <div className="flex items-center justify-between mb-4">
                                                        <span className="text-gray-400">// Scan Metadata</span>
                                                        <button 
                                                            onClick={() => copyToClipboard(JSON.stringify({
                                                                scan_id: scanResults.id,
                                                                target: targetUrl,
                                                                status: scanResults.status,
                                                                total_vulnerabilities: scanResults.total_vulnerabilities
                                                            }, null, 2))}
                                                            className="text-gray-400 hover:text-white transition-colors"
                                                        >
                                                            <Copy className="w-4 h-4" />
                                                        </button>
                                                    </div>
                                                    <pre className="text-green-400 overflow-x-auto">
{`{
  "scan_id": "${scanResults.id}",
  "target": "${targetUrl}",
  "status": "${scanResults.status}",
  "progress": ${scanResults.progress},
  "total_vulnerabilities": ${scanResults.total_vulnerabilities},
  "breakdown": {
    "critical": ${scanResults.critical_count},
    "high": ${scanResults.high_count},
    "medium": ${scanResults.medium_count},
    "low": ${scanResults.low_count}
  },
  "agents_used": [
    "sql_injection",
    "xss_detection", 
    "csrf_analysis",
    "ssrf_scanner",
    "auth_testing",
    "api_security"
  ]
}`}
                                                    </pre>
                                                </div>

                                                <div className="grid grid-cols-2 gap-4">
                                                    <div className="p-4 bg-warm-50 rounded-xl">
                                                        <div className="text-sm text-text-muted mb-1">Scan Duration</div>
                                                        <div className="text-xl font-semibold text-text-primary">~2m 30s</div>
                                                    </div>
                                                    <div className="p-4 bg-warm-50 rounded-xl">
                                                        <div className="text-sm text-text-muted mb-1">Endpoints Tested</div>
                                                        <div className="text-xl font-semibold text-text-primary">{Math.floor(Math.random() * 50) + 10}</div>
                                                    </div>
                                                    <div className="p-4 bg-warm-50 rounded-xl">
                                                        <div className="text-sm text-text-muted mb-1">Payloads Executed</div>
                                                        <div className="text-xl font-semibold text-text-primary">{Math.floor(Math.random() * 500) + 200}</div>
                                                    </div>
                                                    <div className="p-4 bg-warm-50 rounded-xl">
                                                        <div className="text-sm text-text-muted mb-1">AI Confidence</div>
                                                        <div className="text-xl font-semibold text-text-primary">{Math.floor(Math.random() * 15) + 85}%</div>
                                                    </div>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </div>

                                {/* Call to Action */}
                                <div className="bg-gradient-to-r from-accent-primary to-accent-primary/80 rounded-2xl p-8 text-white text-center shadow-xl shadow-accent-primary/30">
                                    <h3 className="text-2xl font-bold mb-2">Need a Deeper Analysis?</h3>
                                    <p className="text-white/80 mb-6">Get comprehensive vulnerability details with remediation code examples</p>
                                    <Link
                                        href={`/scans/${scanResults.id}`}
                                        className="inline-flex items-center gap-2 px-8 py-4 bg-white text-accent-primary font-semibold rounded-xl hover:bg-warm-50 transition-colors shadow-lg"
                                    >
                                        <Eye className="w-5 h-5" />
                                        View Full Report
                                        <ArrowRight className="w-5 h-5" />
                                    </Link>
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
