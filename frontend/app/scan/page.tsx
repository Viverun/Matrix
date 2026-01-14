'use client';

import { useState, useEffect } from 'react';
import {
    Target, ArrowLeft, CheckCircle, AlertTriangle, XCircle,
    Shield, ShieldAlert, ShieldCheck, ShieldX, Clock, Globe, Code, FileText,
    Download, ChevronDown, ChevronUp, ExternalLink, Copy, Terminal, Activity,
    Zap, Database, Lock, Bug, Server, Eye
} from 'lucide-react';
import Link from 'next/link';
import { ProtectedRoute } from '../../components/ProtectedRoute';
import { useAuth } from '../../context/AuthContext';
import { api, Scan, Vulnerability } from '../../lib/matrix_api';
import { useRouter, useSearchParams } from 'next/navigation';

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
    const searchParams = useSearchParams();
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

    // WAF Evasion opt-in (default: OFF)
    const [enableWafEvasion, setEnableWafEvasion] = useState(false);
    const [wafEvasionConsent, setWafEvasionConsent] = useState(false);
    const [showWafWarningModal, setShowWafWarningModal] = useState(false);


    // Load scan from URL on page mount
    useEffect(() => {
        const scanId = searchParams.get('id');
        if (scanId) {
            const loadScan = async () => {
                try {
                    const scanData = await api.getScan(Number(scanId));
                    setScanResults(scanData);
                    setTargetUrl(scanData.target_url);
                    setScanProgress(scanData.progress);
                    if (scanData.status === 'completed') {
                        const results = await api.getVulnerabilities(Number(scanId));
                        setFindings(results.items);
                        setAgentStatuses(prev => prev.map(agent => ({ ...agent, status: 'completed' })));
                    }
                } catch (err) {
                    console.error('Failed to load scan from URL:', err);
                }
            };
            loadScan();
        }
    }, [searchParams]);

    // Use real agent status from scan results
    useEffect(() => {
        if (scanResults && scanResults.status !== 'pending') {
            if (scanResults.status === 'completed') {
                setAgentStatuses(prev => prev.map(agent => ({ ...agent, status: 'completed' })));
            } else if (scanResults.status === 'running') {
                setAgentStatuses(prev => prev.map(agent => ({ ...agent, status: 'active' })));
            }
        }
    }, [scanResults]);

    const addLog = (type: string, message: string) => {
        setTerminalLogs(prev => [...prev.slice(-15), { type, message }]);
    };

    const handleStartScan = async () => {
        if (!targetUrl) return;

        setIsScanning(true);
        setScanProgress(0);
        setScanResults(null);
        setFindings([]);
        setError(null);
        setTerminalLogs([]);

        addLog('cmd', 'Initializing security scan...');
        addLog('info', `Target: ${targetUrl}`);

        try {
            const newScan = await api.createScan({
                target_url: targetUrl,
                scan_type: 'FULL',
                enable_waf_evasion: enableWafEvasion,
                waf_evasion_consent: wafEvasionConsent
            });

            addLog('success', `Scan ID: ${newScan.id}`);
            addLog('scan', 'Running reconnaissance...');
            setScanResults(newScan);

            let failures = 0;
            let lastProgress = 0;
            const interval = setInterval(async () => {
                try {
                    const statusUpdate = await api.getScan(newScan.id);
                    failures = 0;

                    setScanProgress(statusUpdate.progress);
                    setScanResults(statusUpdate);

                    if (statusUpdate.progress > lastProgress) {
                        if (statusUpdate.progress >= 10 && lastProgress < 10) {
                            addLog('info', 'Resolving DNS and establishing connection...');
                        }
                        if (statusUpdate.progress >= 15 && lastProgress < 15) {
                            addLog('success', 'Target analysis complete - discovered endpoints');
                            addLog('scan', 'Deploying security agents...');
                        }
                        if (statusUpdate.progress >= 25 && lastProgress < 25) {
                            addLog('info', 'SQL Injection Agent: Testing input parameters...');
                        }
                        if (statusUpdate.progress >= 40 && lastProgress < 40) {
                            addLog('info', 'XSS Agent: Scanning for reflected/stored XSS vectors...');
                        }
                        if (statusUpdate.progress >= 55 && lastProgress < 55) {
                            addLog('info', 'CSRF Agent: Analyzing form submissions and tokens...');
                        }
                        if (statusUpdate.progress >= 70 && lastProgress < 70) {
                            addLog('info', 'SSRF Agent: Testing server-side request forgery paths...');
                        }
                        if (statusUpdate.progress >= 80 && lastProgress < 80) {
                            addLog('scan', 'Auth Agent: Checking authentication mechanisms...');
                        }
                        if (statusUpdate.progress >= 88 && lastProgress < 88) {
                            addLog('info', 'API Security Agent: Validating endpoints and headers...');
                        }
                        if (statusUpdate.progress >= 94 && lastProgress < 94) {
                            addLog('scan', 'AI Analysis: Correlating and deduplicating findings...');
                        }
                        lastProgress = statusUpdate.progress;
                    }

                    if (statusUpdate.status === 'completed') {
                        clearInterval(interval);
                        setIsScanning(false);
                        setAgentStatuses(prev => prev.map(agent => ({ ...agent, status: 'completed' })));
                        const results = await api.getVulnerabilities(newScan.id);
                        setFindings(results.items);
                        addLog('success', `Complete. ${results.total} vulnerabilities found.`);
                        router.push(`/scan?id=${newScan.id}`, { scroll: false });
                    } else if (statusUpdate.status === 'failed' || statusUpdate.status === 'cancelled') {
                        clearInterval(interval);
                        setIsScanning(false);
                        setError(statusUpdate.error_message || 'Scan terminated unexpectedly');
                        addLog('error', statusUpdate.error_message || 'Scan failed');
                    }
                } catch (err: any) {
                    console.error('Poll error:', err);
                    failures++;
                    addLog('warn', `Connection failed (${failures}/3)`);
                    if (failures >= 3) {
                        clearInterval(interval);
                        setIsScanning(false);
                        setError('Lost connection to scan server');
                        addLog('error', 'Connection timeout');
                    }
                }
            }, 2000);
        } catch (err: any) {
            setIsScanning(false);
            setError(err.message || 'Failed to initialize scan');
            addLog('error', err.message || 'Initialization failed');
        }
    };

    // Helper functions - Professional severity styling
    const getSeverityClass = (severity: string) => {
        const classes: Record<string, string> = {
            critical: 'border-[#dc2626] text-[#dc2626]',
            high: 'border-[#ea580c] text-[#ea580c]',
            medium: 'border-[#ca8a04] text-[#ca8a04]',
            low: 'border-[#6b7280] text-[#6b7280]',
            info: 'border-[#9ca3af] text-[#9ca3af]'
        };
        return classes[severity] || classes.info;
    };

    const getSeverityBorder = (severity: string) => {
        const colors: Record<string, string> = {
            critical: 'border-l-[#dc2626]',
            high: 'border-l-[#ea580c]',
            medium: 'border-l-[#ca8a04]',
            low: 'border-l-[#6b7280]',
            info: 'border-l-[#9ca3af]'
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

    const getCVSSVector = (severity: string): string => {
        const vectors: Record<string, string> = {
            critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            high: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N',
            medium: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N',
            low: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N',
            info: 'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N'
        };
        return vectors[severity] || vectors.info;
    };

    const getCWEMapping = (vulnType: string): string => {
        const cweMap: Record<string, string> = {
            'sql_injection': 'CWE-89',
            'xss': 'CWE-79',
            'csrf': 'CWE-352',
            'ssrf': 'CWE-918',
            'broken_authentication': 'CWE-287',
            'sensitive_data_exposure': 'CWE-200',
            'command_injection': 'CWE-78',
            'path_traversal': 'CWE-22',
            'default': 'CWE-Unknown'
        };
        return cweMap[vulnType.toLowerCase()] || cweMap['default'];
    };

    const getRiskPosture = () => {
        if ((scanResults?.critical_count || 0) > 0) return { level: 'CRITICAL', class: 'risk-critical' };
        if ((scanResults?.high_count || 0) > 0) return { level: 'ELEVATED', class: 'risk-elevated' };
        if ((scanResults?.medium_count || 0) > 0) return { level: 'MODERATE', class: 'risk-moderate' };
        return { level: 'LOW', class: 'risk-low' };
    };

    const getExposureSummary = () => {
        const critical = scanResults?.critical_count || 0;
        const high = scanResults?.high_count || 0;
        const total = scanResults?.total_vulnerabilities || 0;

        if (critical > 0) {
            return `${critical} critical exposure${critical > 1 ? 's' : ''} requiring immediate remediation. ${total} total findings.`;
        }
        if (high > 0) {
            return `${high} high-severity finding${high > 1 ? 's' : ''} detected. ${total} total findings require attention.`;
        }
        if (total > 0) {
            return `${total} finding${total > 1 ? 's' : ''} identified. Review recommended.`;
        }
        return 'No security vulnerabilities detected in this assessment.';
    };

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    return (
        <ProtectedRoute>
            {/* Security scope wrapper for professional report styling */}
            <div className="security-scope min-h-screen">
                <Navbar />

                {/* Page Header - Minimal */}
                <section className="py-6 px-6 border-b border-gray-200 bg-white">
                    <div className="max-w-6xl mx-auto">
                        <Link href="/hub" className="inline-flex items-center gap-2 text-gray-500 hover:text-gray-900 text-sm mb-4">
                            <ArrowLeft className="w-4 h-4" />
                            Back to Hub
                        </Link>
                        <div className="flex items-center justify-between">
                            <div>
                                <h1 className="text-xl font-semibold text-gray-900 tracking-tight">
                                    Security Assessment
                                </h1>
                                <p className="text-sm text-gray-500 mt-1">
                                    Vulnerability analysis and risk assessment
                                </p>
                            </div>
                            {scanResults && (
                                <div className="text-xs text-gray-400 font-mono">
                                    ID: {scanResults.id}
                                </div>
                            )}
                        </div>
                    </div>
                </section>

                {/* Main Content */}
                <section className="py-6 px-6">
                    <div className="max-w-6xl mx-auto">
                        {/* Scan Input */}
                        <div className="bg-white rounded-md border border-gray-200 p-5 mb-6">
                            <div className="flex items-center gap-3 mb-4">
                                <Target className="w-5 h-5 text-gray-400" />
                                <div>
                                    <h2 className="text-sm font-medium text-gray-900">Target Configuration</h2>
                                    <p className="text-xs text-gray-500">Enter the URL to assess</p>
                                </div>
                            </div>

                            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
                                <div className="flex-1 relative">
                                    <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                                    <input
                                        type="url"
                                        placeholder="https://example.com"
                                        value={targetUrl}
                                        onChange={(e) => setTargetUrl(e.target.value)}
                                        onKeyDown={(e) => { if (e.key === 'Enter' && targetUrl && !isScanning) handleStartScan(); }}
                                        className="w-full pl-10 pr-4 py-3 rounded-md border border-gray-200 focus:border-gray-400 focus:ring-2 focus:ring-gray-100 outline-none text-sm text-gray-900 placeholder:text-gray-400 bg-gray-50"
                                        disabled={isScanning}
                                    />
                                </div>
                                <button
                                    onClick={handleStartScan}
                                    disabled={!targetUrl || isScanning}
                                    className="px-6 py-3 bg-emerald-700 text-white font-medium rounded-md text-sm hover:bg-emerald-800 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 whitespace-nowrap shadow-md"
                                >
                                    {isScanning ? (
                                        <>
                                            <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                                            Scanning...
                                        </>
                                    ) : (
                                        <>
                                            <Zap className="w-4 h-4" />
                                            Scan
                                        </>
                                    )}
                                </button>
                            </div>

                            {/* Advanced Options - WAF Evasion */}
                            <div className="mt-4 pt-4 border-t border-gray-100">
                                <div className="flex items-center gap-3">
                                    <span className="text-xs text-gray-400">
                                        <AlertTriangle className="w-3 h-3 inline mr-1" />
                                        WAF Evasion
                                    </span>
                                    <button
                                        type="button"
                                        onClick={() => {
                                            if (!enableWafEvasion) {
                                                setShowWafWarningModal(true);
                                            } else {
                                                setEnableWafEvasion(false);
                                                setWafEvasionConsent(false);
                                            }
                                        }}
                                        disabled={isScanning}
                                        className={`px-2.5 py-0.5 text-xs font-medium rounded transition-colors ${enableWafEvasion
                                            ? 'bg-amber-100 text-amber-700 border border-amber-300'
                                            : 'bg-gray-100 text-gray-500 border border-gray-200 hover:bg-gray-200'
                                            } disabled:opacity-50`}
                                    >
                                        {enableWafEvasion ? '✓ Activated' : 'Activate'}
                                    </button>
                                </div>
                            </div>
                        </div>

                        {/* Error Alert */}
                        {error && (
                            <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-md flex items-start gap-3">
                                <XCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
                                <div>
                                    <div className="font-medium text-red-900 text-sm">Scan Failed</div>
                                    <div className="text-xs text-red-700 mt-1">{error}</div>
                                </div>
                            </div>
                        )}

                        {/* Scanning Progress */}
                        {isScanning && (
                            <div className="bg-white rounded-md border border-gray-200 overflow-hidden mb-6">
                                <div className="p-5 border-b border-gray-100">
                                    <div className="flex items-center justify-between mb-4">
                                        <div className="flex items-center gap-3">
                                            <Activity className="w-5 h-5 text-gray-900 animate-pulse" />
                                            <div>
                                                <h3 className="text-sm font-medium text-gray-900">Scan in Progress</h3>
                                                <p className="text-xs text-gray-500">{targetUrl}</p>
                                            </div>
                                        </div>
                                        <div className="text-right">
                                            <div className="text-2xl font-bold text-gray-900 font-mono">{Math.round(scanProgress)}%</div>
                                        </div>
                                    </div>

                                    {/* Progress Bar */}
                                    <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                                        <div
                                            className="h-full bg-gray-900 rounded-full transition-all duration-500"
                                            style={{ width: `${scanProgress}%` }}
                                        />
                                    </div>
                                </div>

                                {/* Agent Status Grid - Animated Cards */}
                                <div className="p-6 bg-gradient-to-br from-amber-50/50 to-green-50/50">
                                    <h4 className="text-sm font-semibold text-gray-600 uppercase tracking-wide mb-4">Security Agents</h4>
                                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                                        {agentStatuses.map((agent, idx) => (
                                            <div
                                                key={idx}
                                                className={`p-4 rounded-xl border-2 transition-all duration-300 ${agent.status === 'active'
                                                    ? 'bg-gray-100 border-gray-400 shadow-lg shadow-gray-200/50'
                                                    : agent.status === 'completed'
                                                        ? 'bg-amber-50 border-amber-300'
                                                        : 'bg-white border-gray-200'
                                                    }`}
                                            >
                                                <div className="flex items-center gap-3">
                                                    <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${agent.status === 'active'
                                                        ? 'bg-gray-600 text-white'
                                                        : agent.status === 'completed'
                                                            ? 'bg-amber-500 text-white'
                                                            : 'bg-gray-200 text-gray-500'
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
                                                        <div className="font-medium text-gray-800 text-sm truncate">{agent.name}</div>
                                                        <div className={`text-xs font-medium ${agent.status === 'active' ? 'text-gray-600' :
                                                            agent.status === 'completed' ? 'text-amber-700' : 'text-gray-400'
                                                            }`}>
                                                            {agent.status === 'active' ? 'Scanning...' :
                                                                agent.status === 'completed' ? 'Complete' : 'Queued'}
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                {/* Terminal Output - Warm Beige Theme with Border */}
                                <div className="p-5 bg-gradient-to-br from-amber-50 to-green-50 border-t-2 border-amber-300 font-mono text-sm rounded-b-md">
                                    <div className="flex items-center gap-2 mb-3">
                                        <Terminal className="w-4 h-4 text-amber-600" />
                                        <span className="text-amber-700 text-xs uppercase tracking-wide font-semibold">Live Output</span>
                                    </div>
                                    <div className="space-y-1.5 max-h-40 overflow-y-auto">
                                        {terminalLogs.length === 0 ? (
                                            <p className="text-gray-500"><span className="text-amber-600">$</span> Awaiting scan initialization...</p>
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

                        {/* ========================================
                            PROFESSIONAL SECURITY REPORT RESULTS
                            ======================================== */}
                        {scanResults && !isScanning && (
                            <div className="space-y-6">
                                {/* Report Header - Executive Summary */}
                                <header className="bg-white rounded-md border border-gray-200 p-6">
                                    <div className="flex items-start justify-between mb-6">
                                        <div>
                                            <div className="flex items-center gap-2 text-xs text-gray-500 uppercase tracking-widest mb-2">
                                                <FileText className="w-3.5 h-3.5" />
                                                Security Assessment Report
                                            </div>
                                            <h2 className="report-title text-xl font-semibold text-gray-900 mb-1">
                                                Vulnerability Analysis
                                            </h2>
                                            <p className="text-sm text-gray-600 font-mono">{targetUrl}</p>
                                        </div>
                                        <div className="flex items-center gap-2 no-print">
                                            <button
                                                onClick={() => copyToClipboard(JSON.stringify(findings, null, 2))}
                                                className="p-2 hover:bg-gray-100 rounded-md border border-gray-200 text-gray-500 hover:text-gray-700"
                                                title="Copy JSON"
                                            >
                                                <Copy className="w-4 h-4" />
                                            </button>
                                            <button
                                                onClick={() => router.push(`/scans/${scanResults.id}`)}
                                                className="p-2 hover:bg-gray-100 rounded-md border border-gray-200 text-gray-500 hover:text-gray-700"
                                                title="Download Report"
                                            >
                                                <Download className="w-4 h-4" />
                                            </button>
                                        </div>
                                    </div>

                                    {/* Risk Posture Statement */}
                                    <div className="p-4 bg-gray-50 rounded-md border border-gray-200 mb-6">
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <span className="text-xs text-gray-500 uppercase tracking-wide">Risk Posture:</span>
                                                <span className={`ml-2 font-semibold ${getRiskPosture().class}`}>
                                                    {getRiskPosture().level}
                                                </span>
                                            </div>
                                            <div className="text-xs text-gray-500">
                                                {new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}
                                            </div>
                                        </div>
                                        <p className="text-sm text-gray-700 mt-2">
                                            {getExposureSummary()}
                                        </p>
                                    </div>

                                    {/* Severity Distribution - Compact Table */}
                                    <div className="overflow-x-auto">
                                        <table className="w-full">
                                            <thead>
                                                <tr>
                                                    <th className="text-left">Severity</th>
                                                    <th className="text-center w-20">Count</th>
                                                    <th className="text-left">Distribution</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {[
                                                    { severity: 'Critical', count: scanResults?.critical_count || 0, color: '#dc2626' },
                                                    { severity: 'High', count: scanResults?.high_count || 0, color: '#ea580c' },
                                                    { severity: 'Medium', count: scanResults?.medium_count || 0, color: '#ca8a04' },
                                                    { severity: 'Low', count: scanResults?.low_count || 0, color: '#6b7280' },
                                                ].map((item) => {
                                                    const total = scanResults?.total_vulnerabilities || 1;
                                                    const percentage = (item.count / total) * 100;
                                                    return (
                                                        <tr key={item.severity}>
                                                            <td className="font-medium">{item.severity}</td>
                                                            <td className="text-center font-mono">{item.count}</td>
                                                            <td>
                                                                <div className="flex items-center gap-2">
                                                                    <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden">
                                                                        <div
                                                                            className="h-full rounded-full"
                                                                            style={{
                                                                                width: `${Math.max(percentage, item.count > 0 ? 5 : 0)}%`,
                                                                                backgroundColor: item.color
                                                                            }}
                                                                        />
                                                                    </div>
                                                                    <span className="text-xs text-gray-500 w-10">
                                                                        {percentage.toFixed(0)}%
                                                                    </span>
                                                                </div>
                                                            </td>
                                                        </tr>
                                                    );
                                                })}
                                            </tbody>
                                        </table>
                                    </div>
                                </header>

                                {/* Tabs */}
                                <div className="bg-white rounded-md border border-gray-200 overflow-hidden">
                                    <div className="flex border-b border-gray-200">
                                        {[
                                            { id: 'findings', label: 'Findings', count: findings.length },
                                            { id: 'overview', label: 'Overview' },
                                            { id: 'details', label: 'Technical Details' }
                                        ].map((tab) => (
                                            <button
                                                key={tab.id}
                                                onClick={() => setActiveTab(tab.id as any)}
                                                className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 -mb-px ${activeTab === tab.id
                                                    ? 'border-gray-900 text-gray-900'
                                                    : 'border-transparent text-gray-500 hover:text-gray-700'
                                                    }`}
                                            >
                                                {tab.label}
                                                {tab.count !== undefined && (
                                                    <span className="text-xs bg-gray-100 px-1.5 py-0.5 rounded">
                                                        {tab.count}
                                                    </span>
                                                )}
                                            </button>
                                        ))}
                                    </div>

                                    <div className="p-6">
                                        {/* Findings Tab - TABLE BASED */}
                                        {activeTab === 'findings' && (
                                            <div>
                                                {findings.length === 0 ? (
                                                    <div className="text-center py-12">
                                                        <ShieldCheck className="w-12 h-12 text-green-500 mx-auto mb-4" />
                                                        <h4 className="text-lg font-medium text-gray-900 mb-2">No Vulnerabilities Detected</h4>
                                                        <p className="text-sm text-gray-500 max-w-md mx-auto">
                                                            The scan completed without detecting any security vulnerabilities.
                                                        </p>
                                                    </div>
                                                ) : (
                                                    <div className="overflow-x-auto border border-gray-200 rounded-md">
                                                        <table className="w-full">
                                                            <thead>
                                                                <tr>
                                                                    <th className="w-8">#</th>
                                                                    <th className="text-left">Vulnerability</th>
                                                                    <th className="text-left w-24">Severity</th>
                                                                    <th className="text-left w-16">CVSS</th>
                                                                    <th className="text-left">Location</th>
                                                                    <th className="w-10"></th>
                                                                </tr>
                                                            </thead>
                                                            <tbody>
                                                                {findings.map((vuln, i) => (
                                                                    <>
                                                                        <tr
                                                                            key={i}
                                                                            className={`cursor-pointer ${expandedVuln === i ? 'bg-gray-50' : ''}`}
                                                                            onClick={() => setExpandedVuln(expandedVuln === i ? null : i)}
                                                                        >
                                                                            <td className="text-center font-mono text-gray-400">{i + 1}</td>
                                                                            <td>
                                                                                <div className="font-medium text-gray-900 capitalize">
                                                                                    {vuln.vulnerability_type.replace(/_/g, ' ')}
                                                                                </div>
                                                                                <div className="text-xs text-gray-500 mt-0.5">
                                                                                    {getCWEMapping(vuln.vulnerability_type)}
                                                                                </div>
                                                                            </td>
                                                                            <td>
                                                                                <span className={`inline-block px-2 py-0.5 text-xs font-semibold uppercase tracking-wide rounded border ${getSeverityClass(vuln.severity)}`}>
                                                                                    {vuln.severity}
                                                                                </span>
                                                                            </td>
                                                                            <td className="font-mono">
                                                                                {getCVSSScore(vuln.severity).toFixed(1)}
                                                                            </td>
                                                                            <td className="font-mono text-xs text-gray-600 max-w-xs truncate">
                                                                                {vuln.url}
                                                                                {vuln.parameter && (
                                                                                    <span className="text-gray-400 ml-1">[{vuln.parameter}]</span>
                                                                                )}
                                                                            </td>
                                                                            <td>
                                                                                {expandedVuln === i ? (
                                                                                    <ChevronUp className="w-4 h-4 text-gray-400" />
                                                                                ) : (
                                                                                    <ChevronDown className="w-4 h-4 text-gray-400" />
                                                                                )}
                                                                            </td>
                                                                        </tr>
                                                                        {expandedVuln === i && (
                                                                            <tr>
                                                                                <td colSpan={6} className="p-0">
                                                                                    <div className={`p-5 bg-gray-50 border-l-4 ${getSeverityBorder(vuln.severity)}`}>
                                                                                        {/* CVSS Vector */}
                                                                                        <div className="mb-4 p-3 bg-white rounded border border-gray-200">
                                                                                            <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">CVSS Vector</div>
                                                                                            <code className="text-xs text-gray-700 font-mono">
                                                                                                {getCVSSVector(vuln.severity)}
                                                                                            </code>
                                                                                        </div>

                                                                                        {/* Evidence */}
                                                                                        <div className="mb-4">
                                                                                            <h5 className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Evidence</h5>
                                                                                            <pre className="p-3 bg-gray-900 rounded text-xs text-green-400 font-mono overflow-x-auto">
                                                                                                {vuln.evidence || 'Vulnerability detected through automated security analysis.'}
                                                                                            </pre>
                                                                                        </div>

                                                                                        {/* Description */}
                                                                                        <div className="mb-4">
                                                                                            <h5 className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Description</h5>
                                                                                            <p className="text-sm text-gray-700 leading-relaxed">
                                                                                                {vuln.description || `A ${vuln.severity} severity ${vuln.vulnerability_type.replace(/_/g, ' ')} vulnerability was detected. This type of vulnerability can allow attackers to compromise application security.`}
                                                                                            </p>
                                                                                        </div>

                                                                                        {/* Remediation */}
                                                                                        <div className="mb-4">
                                                                                            <h5 className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Remediation</h5>
                                                                                            <p className="text-sm text-gray-700 leading-relaxed p-3 bg-green-50 border border-green-200 rounded">
                                                                                                {vuln.remediation || 'Review and sanitize all user inputs. Implement proper input validation and output encoding following OWASP guidelines.'}
                                                                                            </p>
                                                                                        </div>

                                                                                        {/* References */}
                                                                                        <div className="flex items-center gap-4 text-xs">
                                                                                            <span className="text-gray-500">References:</span>
                                                                                            <a href="https://owasp.org" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline flex items-center gap-1">
                                                                                                OWASP <ExternalLink className="w-3 h-3" />
                                                                                            </a>
                                                                                            <a href={`https://cwe.mitre.org/data/definitions/${getCWEMapping(vuln.vulnerability_type).split('-')[1]}.html`} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline flex items-center gap-1">
                                                                                                {getCWEMapping(vuln.vulnerability_type)} <ExternalLink className="w-3 h-3" />
                                                                                            </a>
                                                                                        </div>
                                                                                    </div>
                                                                                </td>
                                                                            </tr>
                                                                        )}
                                                                    </>
                                                                ))}
                                                            </tbody>
                                                        </table>
                                                    </div>
                                                )}
                                            </div>
                                        )}

                                        {/* Overview Tab */}
                                        {activeTab === 'overview' && (
                                            <div className="space-y-6">
                                                {/* Quick Actions */}
                                                <div>
                                                    <h4 className="section-header">Actions</h4>
                                                    <div className="grid grid-cols-3 gap-4">
                                                        <button
                                                            onClick={() => router.push(`/scans/${scanResults.id}`)}
                                                            className="p-4 bg-gray-50 rounded-md border border-gray-200 hover:border-gray-300 text-left"
                                                        >
                                                            <FileText className="w-5 h-5 text-gray-600 mb-2" />
                                                            <div className="text-sm font-medium text-gray-900">Export PDF</div>
                                                            <div className="text-xs text-gray-500">Download report</div>
                                                        </button>
                                                        <button
                                                            onClick={() => {
                                                                const exportData = {
                                                                    scan: scanResults,
                                                                    findings: findings,
                                                                    exportedAt: new Date().toISOString(),
                                                                    version: '1.0'
                                                                };
                                                                const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
                                                                const url = URL.createObjectURL(blob);
                                                                const a = document.createElement('a');
                                                                a.href = url;
                                                                a.download = `Matrix_Scan_${scanResults.id}_${new Date().toISOString().split('T')[0]}.json`;
                                                                a.click();
                                                                URL.revokeObjectURL(url);
                                                            }}
                                                            className="p-4 bg-gray-50 rounded-md border border-gray-200 hover:border-gray-300 text-left"
                                                        >
                                                            <Code className="w-5 h-5 text-gray-600 mb-2" />
                                                            <div className="text-sm font-medium text-gray-900">Export JSON</div>
                                                            <div className="text-xs text-gray-500">Machine-readable</div>
                                                        </button>
                                                        <Link
                                                            href={`/scans/${scanResults.id}`}
                                                            className="p-4 bg-gray-50 rounded-md border border-gray-200 hover:border-gray-300 text-left"
                                                        >
                                                            <Eye className="w-5 h-5 text-gray-600 mb-2" />
                                                            <div className="text-sm font-medium text-gray-900">Full Analysis</div>
                                                            <div className="text-xs text-gray-500">Detailed view</div>
                                                        </Link>
                                                    </div>
                                                </div>

                                                {/* Scan Metrics */}
                                                <div>
                                                    <h4 className="section-header">Scan Metrics</h4>
                                                    <div className="grid grid-cols-4 gap-4">
                                                        {[
                                                            { label: 'Total Findings', value: scanResults?.total_vulnerabilities || 0 },
                                                            { label: 'Critical', value: scanResults?.critical_count || 0 },
                                                            { label: 'High', value: scanResults?.high_count || 0 },
                                                            { label: 'Medium + Low', value: (scanResults?.medium_count || 0) + (scanResults?.low_count || 0) },
                                                        ].map((metric, i) => (
                                                            <div key={i} className="p-4 bg-gray-50 rounded-md border border-gray-200">
                                                                <div className="text-2xl font-bold text-gray-900 font-mono">{metric.value}</div>
                                                                <div className="text-xs text-gray-500 mt-1">{metric.label}</div>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            </div>
                                        )}

                                        {/* Technical Details Tab */}
                                        {activeTab === 'details' && (
                                            <div className="space-y-6">
                                                {/* Scan Configuration */}
                                                <div>
                                                    <h4 className="section-header">Scan Configuration</h4>
                                                    <div className="bg-gray-900 rounded-md p-4 font-mono text-xs">
                                                        <div className="flex items-center justify-between mb-3">
                                                            <span className="text-gray-400">Configuration & Results</span>
                                                            <button
                                                                onClick={() => copyToClipboard(JSON.stringify({
                                                                    scan_id: scanResults.id,
                                                                    target: targetUrl,
                                                                    status: scanResults.status,
                                                                    total_vulnerabilities: scanResults.total_vulnerabilities,
                                                                    severity_breakdown: {
                                                                        critical: scanResults.critical_count,
                                                                        high: scanResults.high_count,
                                                                        medium: scanResults.medium_count,
                                                                        low: scanResults.low_count
                                                                    }
                                                                }, null, 2))}
                                                                className="text-gray-500 hover:text-white flex items-center gap-1"
                                                            >
                                                                <Copy className="w-3 h-3" />
                                                                Copy
                                                            </button>
                                                        </div>
                                                        <pre className="text-green-400 overflow-x-auto">
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
  "scan_engine": "Matrix Security Platform v1.0"
}`}
                                                        </pre>
                                                    </div>
                                                </div>

                                                {/* Security Agents */}
                                                <div>
                                                    <h4 className="section-header">Security Agents Deployed</h4>
                                                    <div className="grid grid-cols-3 gap-3">
                                                        {[
                                                            { name: 'SQL Injection Detector', icon: <Database className="w-4 h-4" /> },
                                                            { name: 'XSS Scanner', icon: <Code className="w-4 h-4" /> },
                                                            { name: 'CSRF Analyzer', icon: <Shield className="w-4 h-4" /> },
                                                            { name: 'SSRF Detector', icon: <Server className="w-4 h-4" /> },
                                                            { name: 'Auth Tester', icon: <Lock className="w-4 h-4" /> },
                                                            { name: 'API Security Auditor', icon: <Globe className="w-4 h-4" /> },
                                                        ].map((agent, i) => (
                                                            <div key={i} className="flex items-center gap-3 p-3 bg-gray-50 rounded-md border border-gray-200">
                                                                <div className="text-gray-500">{agent.icon}</div>
                                                                <div className="flex-1 min-w-0">
                                                                    <div className="text-sm font-medium text-gray-900 truncate">{agent.name}</div>
                                                                    <div className="text-xs text-green-600">✓ Completed</div>
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
                            <div className="bg-white rounded-md border border-gray-200 p-12 text-center">
                                <Target className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                                <h3 className="text-lg font-medium text-gray-900 mb-2">Ready to Scan</h3>
                                <p className="text-sm text-gray-500 max-w-md mx-auto mb-6">
                                    Enter a target URL above to start the security assessment.
                                </p>

                                {/* Features Grid - Minimal */}
                                <div className="grid grid-cols-4 gap-3 max-w-2xl mx-auto">
                                    {[
                                        { icon: <Database className="w-4 h-4" />, label: 'SQL Injection' },
                                        { icon: <Code className="w-4 h-4" />, label: 'XSS Detection' },
                                        { icon: <Shield className="w-4 h-4" />, label: 'CSRF Analysis' },
                                        { icon: <Server className="w-4 h-4" />, label: 'SSRF Scanner' },
                                    ].map((feature, i) => (
                                        <div key={i} className="p-3 bg-gray-50 rounded-md text-center">
                                            <div className="text-gray-400 flex justify-center mb-1">{feature.icon}</div>
                                            <div className="text-xs text-gray-600">{feature.label}</div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </section>
            </div>

            {/* WAF Evasion Warning Modal */}
            {showWafWarningModal && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
                    <div className="bg-white rounded-lg shadow-2xl max-w-md w-full overflow-hidden">
                        {/* Header */}
                        <div className="bg-amber-50 border-b border-amber-200 p-4">
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 bg-amber-500 rounded-full flex items-center justify-center">
                                    <ShieldAlert className="w-5 h-5 text-white" />
                                </div>
                                <div>
                                    <h3 className="font-semibold text-gray-900">Advanced WAF Evasion</h3>
                                    <p className="text-xs text-amber-700">Authorization Required</p>
                                </div>
                            </div>
                        </div>

                        {/* Content */}
                        <div className="p-5">
                            <div className="bg-red-50 border border-red-200 rounded-md p-3 mb-4">
                                <p className="text-sm text-red-800 font-medium mb-2">⚠️ Warning: Potential Risks</p>
                                <ul className="text-xs text-red-700 space-y-1">
                                    <li>• May trigger security alerts on target systems</li>
                                    <li>• Could be flagged as malicious by WAFs and ISPs</li>
                                    <li>• May violate Terms of Service of target systems</li>
                                    <li>• Use only on systems you own or have written authorization</li>
                                </ul>
                            </div>

                            <div className="bg-gray-50 border border-gray-200 rounded-md p-3 mb-4">
                                <p className="text-sm text-gray-800 font-medium mb-2">Terms of Use</p>
                                <p className="text-xs text-gray-600 leading-relaxed">
                                    By enabling this feature, you confirm that you have explicit written
                                    authorization to perform advanced security testing on the target system.
                                    You accept full responsibility for any consequences.
                                </p>
                            </div>

                            <label className="flex items-start gap-3 cursor-pointer">
                                <input
                                    type="checkbox"
                                    checked={wafEvasionConsent}
                                    onChange={(e) => setWafEvasionConsent(e.target.checked)}
                                    className="mt-0.5 w-4 h-4 text-amber-600 border-gray-300 rounded focus:ring-amber-500"
                                />
                                <span className="text-sm text-gray-700">
                                    I acknowledge the risks and confirm I have authorization to test this target
                                </span>
                            </label>
                        </div>

                        {/* Footer */}
                        <div className="flex gap-3 p-4 bg-gray-50 border-t border-gray-200">
                            <button
                                onClick={() => {
                                    setShowWafWarningModal(false);
                                    setWafEvasionConsent(false);
                                }}
                                className="flex-1 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={() => {
                                    if (wafEvasionConsent) {
                                        setEnableWafEvasion(true);
                                        setShowWafWarningModal(false);
                                    }
                                }}
                                disabled={!wafEvasionConsent}
                                className="flex-1 px-4 py-2 text-sm font-medium text-white bg-amber-600 rounded-md hover:bg-amber-700 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                Enable WAF Evasion
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </ProtectedRoute>
    );
}
