'use client';

import React, { useState, useRef, useEffect } from 'react';
import {
    Github,
    Send,
    MessageSquare,
    Code,
    Terminal,
    AlertTriangle,
    ArrowLeft,
    Search,
    Cpu,
    Lock,
    FileCode,
    BarChart3
} from 'lucide-react';
import Link from 'next/link';
import Image from 'next/image';
import { SpiderWeb } from '../../components/SpiderWeb';
import { Navbar } from '../../components/Navbar';
import { useAuth } from '../../context/AuthContext';
import { api, Scan, Vulnerability } from '../../lib/matrix_api';
import { useRouter, useSearchParams } from 'next/navigation';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

import { Suspense } from 'react';

function RepoAnalysisContent() {
    const { isAuthenticated } = useAuth();
    const router = useRouter();
    const [repoUrl, setRepoUrl] = useState('');
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [isAuditDone, setIsAuditDone] = useState(false);
    const [auditLogs, setAuditLogs] = useState<string[]>([]);
    const [messages, setMessages] = useState([
        { role: 'assistant', content: 'Ready to analyze your repository. Paste a GitHub URL to begin the deep security audit.' }
    ]);
    const [input, setInput] = useState('');
    const [progress, setProgress] = useState(0);
    const [stats, setStats] = useState({ high: 0, secrets: 0, files: 0 });
    const [vulnerableFiles, setVulnerableFiles] = useState<{ file: string, issues: number, severity: string }[]>([]);
    const [scannedFiles, setScannedFiles] = useState<string[]>([]);
    const [scanId, setScanId] = useState<number | null>(null);

    const [isThinking, setIsThinking] = useState(false);
    const chatEndRef = useRef<HTMLDivElement>(null);
    const logsEndRef = useRef<HTMLDivElement>(null);
    const searchParams = useSearchParams();
    const urlParam = searchParams.get('url');
    const scanIdParam = searchParams.get('scan_id');

    useEffect(() => {
        if (urlParam) {
            setRepoUrl(urlParam);
        }
        if (scanIdParam) {
            restoreScanContext(parseInt(scanIdParam));
        }
    }, [urlParam, scanIdParam]);

    const processFindings = (findings: Vulnerability[]) => {
        const critical = findings.filter(f => f.severity === 'critical').length;
        const high = findings.filter(f => f.severity === 'high').length;
        const secrets = findings.filter(f => f.vulnerability_type === 'secret_exposure').length;

        // Update Stats State
        setStats({
            files: findings.length > 0 ? Array.from(new Set(findings.map(f => f.file_path))).length : 0,
            high: high + critical,
            secrets: secrets
        });

        // Calculate Top Vulnerable Files
        const fileCountMap: Record<string, { issues: number, severity: string }> = {};
        findings.forEach(f => {
            // Categorize findings without file_path based on vulnerability type
            let path = f.file_path;
            if (!path) {
                const vulnType = f.vulnerability_type?.toLowerCase() || '';
                if (vulnType.includes('header') || vulnType.includes('cors') || vulnType.includes('csp')) {
                    path = 'HTTP Security Headers';
                } else if (vulnType.includes('ssl') || vulnType.includes('tls') || vulnType.includes('certificate')) {
                    path = 'TLS/SSL Configuration';
                } else if (vulnType.includes('cookie')) {
                    path = 'Cookie Security Policy';
                } else if (vulnType.includes('auth') || vulnType.includes('session')) {
                    path = 'Authentication/Session Config';
                } else {
                    path = 'Infrastructure/Config';
                }
            }
            const sev = (f.severity || 'info').toLowerCase();
            if (!fileCountMap[path]) {
                fileCountMap[path] = { issues: 0, severity: sev };
            }
            fileCountMap[path].issues += 1;
            // Keep the highest severity
            const severityOrder = { 'critical': 3, 'high': 2, 'medium': 1, 'low': 0, 'info': 0 };
            const currentHighest = (fileCountMap[path].severity || 'info').toLowerCase();
            if (severityOrder[sev as keyof typeof severityOrder] > severityOrder[currentHighest as keyof typeof severityOrder]) {
                fileCountMap[path].severity = sev;
            }
        });

        const sortedFiles = Object.entries(fileCountMap)
            .map(([file, data]) => ({ file, ...data }))
            .sort((a, b) => b.issues - a.issues)
            .slice(0, 3);

        setVulnerableFiles(sortedFiles);

        // Construct summary message
        const summary = `Audit complete! I found ${findings.length} issues in total.\n` +
            `- Critical: ${critical}\n` +
            `- High: ${high}\n` +
            `- Secrets: ${secrets}\n\n` +
            `You can ask me about specific findings or remediation steps.`;

        return summary;
    };

    const restoreScanContext = async (id: number) => {
        try {
            setIsAnalyzing(true);
            const scanData = await api.getScan(id);
            setScanId(id);
            setRepoUrl(scanData.target_url);

            if (scanData.status === 'completed') {
                const vulnResponse = await api.getVulnerabilities(id);
                const findings = vulnResponse.items;
                const summary = processFindings(findings);

                setAuditLogs([
                    '[SYSTEM] Restoring previous analysis session...',
                    `[INFO] Target: ${scanData.target_url}`,
                    '[SUCCESS] Analysis state recovered.'
                ]);
                setMessages([
                    { role: 'assistant', content: summary }
                ]);
                setScannedFiles(scanData.scanned_files || []);
                setProgress(100);
                setIsAuditDone(true);
                setIsAnalyzing(false);
            } else if (scanData.status === 'running') {
                // Not standard for "back" button but good for robustness
                setAuditLogs(['[SYSTEM] Re-attaching to active scan session...']);
                startPolling(id);
            } else {
                setIsAnalyzing(false);
            }
        } catch (e) {
            console.error("Restore error", e);
            setIsAnalyzing(false);
        }
    };

    const startPolling = (id: number) => {
        let lastProgress = 0;
        let lastFileCount = 0;
        let milestones = [10, 25, 40, 60, 75, 90];
        let milestonesReached = new Set<number>();

        const interval = setInterval(async () => {
            try {
                const statusUpdate = await api.getScan(id);
                setProgress(statusUpdate.progress);

                // Detailed logging based on progress milestones
                const currentProgress = statusUpdate.progress;

                // Log agents being activated
                if (currentProgress >= 5 && currentProgress < 15 && lastProgress < 5) {
                    setAuditLogs(prev => [
                        ...prev,
                        '[SYSTEM] Activating security agents...',
                        `[AGENT] GitHub Security Scanner - ARMED`,
                        `[AGENT] API Security Analyzer - ARMED`,
                        `[AGENT] XSS Detection Engine - ARMED`,
                        '[INFO] Beginning reconnaissance phase...'
                    ]);
                }

                // Log repository structure analysis
                if (currentProgress >= 15 && currentProgress < 25 && lastProgress < 15) {
                    setAuditLogs(prev => [
                        ...prev,
                        '[SCAN] Analyzing repository structure...',
                        '[SCAN] Mapping file dependencies...',
                        '[SCAN] Prioritizing critical assets...'
                    ]);
                }

                // Log progress milestones
                milestones.forEach(milestone => {
                    if (currentProgress >= milestone && !milestonesReached.has(milestone)) {
                        milestonesReached.add(milestone);
                        if (milestone <= 25) {
                            setAuditLogs(prev => [...prev, `[PROGRESS] Reconnaissance ${milestone}% complete`]);
                        } else if (milestone <= 60) {
                            setAuditLogs(prev => [...prev, `[PROGRESS] Secret scanning ${milestone}% complete`]);
                        } else {
                            setAuditLogs(prev => [...prev, `[PROGRESS] Vulnerability analysis ${milestone}% complete`]);
                        }
                    }
                });

                // Update scanned files real-time during polling
                if (statusUpdate.scanned_files && statusUpdate.scanned_files.length > 0) {
                    const currentFileCount = statusUpdate.scanned_files.length;

                    // Log new files being scanned
                    if (currentFileCount > lastFileCount) {
                        const newFiles = statusUpdate.scanned_files.slice(lastFileCount, currentFileCount);
                        newFiles.slice(0, 3).forEach(file => {
                            const fileName = file.split('/').pop() || file;
                            setAuditLogs(prev => [...prev, `[AUDIT] Scanning ${fileName}...`]);
                        });

                        if (newFiles.length > 3) {
                            setAuditLogs(prev => [...prev, `[AUDIT] + ${newFiles.length - 3} more files queued`]);
                        }

                        lastFileCount = currentFileCount;
                    }

                    setScannedFiles(statusUpdate.scanned_files);
                }

                // Log deep analysis phase
                if (currentProgress >= 70 && currentProgress < 85 && lastProgress < 70) {
                    setAuditLogs(prev => [
                        ...prev,
                        '[ANALYZE] Running deep code analysis...',
                        '[ANALYZE] Cross-referencing vulnerability database...',
                        '[ANALYZE] Calculating CVSS scores...'
                    ]);
                }

                // Log finalization
                if (currentProgress >= 90 && lastProgress < 90) {
                    setAuditLogs(prev => [
                        ...prev,
                        '[FINALIZE] Aggregating findings...',
                        '[FINALIZE] Generating security report...'
                    ]);
                }

                lastProgress = currentProgress;

                if (statusUpdate.status === 'completed') {
                    clearInterval(interval);
                    setIsAnalyzing(false);
                    setIsAuditDone(true);
                    setAuditLogs(prev => [
                        ...prev,
                        '[SUCCESS] ✓ Analysis completed successfully',
                        `[RESULT] Scanned ${statusUpdate.scanned_files?.length || 0} source files`,
                        '[SYSTEM] Fetching vulnerability details...'
                    ]);

                    const vulnResponse = await api.getVulnerabilities(id);
                    const summary = processFindings(vulnResponse.items);
                    setScannedFiles(statusUpdate.scanned_files || []);

                    setAuditLogs(prev => [
                        ...prev,
                        `[RESULT] Found ${vulnResponse.total} security findings`,
                        '[SYSTEM] Report ready for review'
                    ]);

                    setMessages(prevMsg => [...prevMsg, {
                        role: 'assistant',
                        content: summary
                    }]);
                } else if (statusUpdate.status === 'failed' || statusUpdate.status === 'cancelled') {
                    clearInterval(interval);
                    setIsAnalyzing(false);
                    setAuditLogs(prev => [...prev, `[ERROR] ✗ Scan failed: ${statusUpdate.error_message || 'Unknown error'}`]);
                    setMessages(prevMsg => [...prevMsg, {
                        role: 'assistant',
                        content: `Analysis failed: ${statusUpdate.error_message}. Please check the URL and try again.`
                    }]);
                }
            } catch (e) {
                console.error("Poll error", e);
            }
        }, 2000);
    };


    const scrollToBottom = () => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    };

    const scrollLogsToBottom = () => {
        logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    };

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    useEffect(() => {
        scrollLogsToBottom();
    }, [auditLogs]);

    const handleAnalyze = async () => {
        if (!repoUrl) return;

        // Check authentication before allowing analysis
        if (!isAuthenticated) {
            router.push('/login?message=You need to be authenticated to analyze repositories');
            return;
        }
        setIsAnalyzing(true);
        setIsAuditDone(false);
        setProgress(0);
        setAuditLogs([
            `[SYSTEM] Initializing Matrix SAST Engine...`,
            `[SYSTEM] Authenticating with GitHub API...`,
            `[INFO] Target: ${repoUrl}`,
            `[SYSTEM] Preparing security mesh...`
        ]);
        setMessages([
            { role: 'assistant', content: `Analyzing ${repoUrl}. I'm scanning for secrets and vulnerabilities.` }
        ]);

        try {
            // 1. Create Scan
            const scan = await api.createScan({
                target_url: repoUrl,
                scan_type: 'github_sast',
                agents_enabled: ['github_security', 'api_security', 'xss']
            });
            setScanId(scan.id);
            setAuditLogs(prev => [
                ...prev,
                `[INFO] Scan job created (ID: ${scan.id})`,
                `[QUEUE] Task dispatched to worker mesh...`,
                `[WAIT] Initializing scan execution...`
            ]);

            // 2. Poll for Status
            startPolling(scan.id);

        } catch (error: any) {
            setIsAnalyzing(false);
            setAuditLogs(prev => [...prev, `[ERROR] Failed to start scan: ${error.message}`]);
            setMessages(prevMsg => [...prevMsg, {
                role: 'assistant',
                content: `Could not start analysis: ${error.message}`
            }]);
        }
    };

    const handleSendMessage = async () => {
        if (!input.trim()) return;

        const userMessage = input.trim();
        const newMessages = [...messages, { role: 'user', content: userMessage }];
        setMessages(newMessages);
        setInput('');
        setIsThinking(true);

        try {
            const chatResponse = await api.chat(userMessage, scanId || undefined);
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: chatResponse.response
            }]);
        } catch (error: any) {
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: `I encountered an error while processing your request: ${error.message}`
            }]);
        } finally {
            setIsThinking(false);
        }
    };

    const handleKeyPress = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter') {
            handleSendMessage();
        }
    };

    return (
        <div className="min-h-screen bg-bg-primary">
            <Navbar />

            <main className="max-w-[1600px] mx-auto px-6 py-8 grid lg:grid-cols-2 gap-8 min-h-[calc(100vh-80px)]">
                {/* LEFT PANEL */}
                <div className="flex flex-col gap-6 h-full overflow-hidden">
                    <div className="space-y-2">
                        <Link href="/hub" className="inline-flex items-center gap-2 text-text-muted hover:text-accent-primary transition-colors mb-2">
                            <ArrowLeft className="w-4 h-4" />
                            Back to Hub
                        </Link>
                        <h2 className="text-4xl font-serif font-medium text-text-primary">Repository Analysis</h2>
                        <p className="text-text-secondary">Deep code audit and secret detection powered by Matrix SAST Agents.</p>
                    </div>

                    {/* Repository Input */}
                    <div className="glass-card p-6">
                        <label className="block text-sm font-medium text-text-primary mb-3">GitHub Repository URL</label>
                        <div className="flex gap-4">
                            <div className="flex-1 relative">
                                <Github className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-text-muted" />
                                <input
                                    type="text"
                                    placeholder="https://github.com/username/repository"
                                    className="input-glass pl-12 w-full"
                                    value={repoUrl}
                                    onChange={(e) => setRepoUrl(e.target.value)}
                                    disabled={isAnalyzing}
                                />
                            </div>
                            <button
                                onClick={handleAnalyze}
                                disabled={isAnalyzing || !repoUrl}
                                className="btn-primary flex items-center gap-2 whitespace-nowrap"
                            >
                                {isAnalyzing ? 'Analyzing...' : 'Audit Code'}
                                {!isAnalyzing && <Search className="w-4 h-4" />}
                            </button>
                        </div>
                        {(isAnalyzing || isAuditDone) && (
                            <div className="mt-4 space-y-2">
                                <div className="flex justify-between text-xs text-text-muted">
                                    <span>{isAuditDone ? 'Analysis Complete' : 'Analyzing source files...'}</span>
                                    <span>{progress}%</span>
                                </div>
                                <div className="progress-bar">
                                    <div className="progress-bar-fill" style={{ width: `${progress}%` }} />
                                </div>
                            </div>
                        )}
                    </div>

                    <div className="flex-1 min-0">
                        {!isAuditDone ? (
                            /* PHASE 1: LOGS VIEW */
                            <div className={`glass-card h-full flex flex-col p-6 animate-fade-in`}>
                                <div className="flex items-center gap-2 mb-4">
                                    <Terminal className="w-4 h-4 text-accent-primary" />
                                    <span className="text-sm font-bold uppercase tracking-widest text-text-primary">Analysis Engine Log</span>
                                </div>
                                <div className="flex-1 bg-[#E8E2D9] rounded-xl p-4 font-mono text-xs overflow-y-auto space-y-1 shadow-inner border border-warm-200/30">
                                    {auditLogs.length > 0 ? (
                                        auditLogs.map((log, i) => (
                                            <div key={i} className="text-[#333333] border-b border-black/5 pb-1 last:border-0">
                                                <span className="opacity-30 inline-block w-4 mr-2">{i + 1}</span>
                                                {log}
                                            </div>
                                        ))
                                    ) : (
                                        <div className="text-[#333333]/60 animate-pulse italic">Awaiting target initialization...</div>
                                    )}
                                    <div ref={logsEndRef} />
                                </div>
                            </div>
                        ) : (
                            /* PHASE 2: SUMMARY VIEW */
                            <div className="h-full flex flex-col gap-6 animate-slide-up">
                                <div className="grid grid-cols-2 gap-4">
                                    <div className="glass-card p-6 border-l-4 border-l-red-500">
                                        <div className="flex items-center gap-2 mb-2 text-red-500">
                                            <AlertTriangle className="w-5 h-5" />
                                            <span className="text-2xl font-serif font-bold">{stats.high.toString().padStart(2, '0')}</span>
                                        </div>
                                        <div className="text-xs uppercase font-bold tracking-widest text-text-muted">High Severity</div>
                                    </div>
                                    <div className="glass-card p-6 border-l-4 border-l-accent-gold">
                                        <div className="flex items-center gap-2 mb-2 text-accent-gold">
                                            <Lock className="w-5 h-5" />
                                            <span className="text-2xl font-serif font-bold">{stats.secrets.toString().padStart(2, '0')}</span>
                                        </div>
                                        <div className="text-xs uppercase font-bold tracking-widest text-text-muted">Secrets Exposed</div>
                                    </div>
                                </div>

                                <div className="glass-card flex-1 p-6 space-y-4">
                                    <div className="flex items-center justify-between mb-4">
                                        <h3 className="font-serif font-medium text-lg text-text-primary">Top Vulnerable Files</h3>
                                        <BarChart3 className="w-4 h-4 text-text-muted" />
                                    </div>
                                    <div className="space-y-3">
                                        {vulnerableFiles.length > 0 ? (
                                            vulnerableFiles.map((item, i) => (
                                                <div key={i} className="flex items-center justify-between p-3 bg-warm-50 rounded-lg border border-warm-200">
                                                    <div className="flex items-center gap-3">
                                                        <FileCode className="w-4 h-4 text-accent-primary" />
                                                        <span className="text-xs font-mono text-text-primary truncate max-w-[200px]">{item.file}</span>
                                                    </div>
                                                    <span className={`text-[10px] font-bold uppercase tracking-tighter px-2 py-0.5 rounded ${item.severity === 'critical' || item.severity === 'high' ? 'bg-red-100 text-red-600' : 'bg-orange-100 text-orange-600'
                                                        }`}>
                                                        {item.issues} Issues
                                                    </span>
                                                </div>
                                            ))
                                        ) : (
                                            <div className="text-center py-8 text-text-muted text-xs italic">
                                                No specific file vulnerabilities detected.
                                            </div>
                                        )}
                                    </div>
                                    <button
                                        onClick={() => router.push(`/scans/${scanId}`)}
                                        className="w-full mt-4 btn-secondary py-3 text-xs uppercase tracking-widest font-bold"
                                    >
                                        View Full Source Report
                                    </button>
                                </div>

                                {scannedFiles.length > 0 && (
                                    <div className="glass-card p-6 space-y-4 max-h-[300px] flex flex-col">
                                        <div className="flex items-center justify-between mb-4">
                                            <h3 className="font-serif font-medium text-lg text-text-primary">Scanned Repository Files</h3>
                                            <FileCode className="w-4 h-4 text-text-muted" />
                                        </div>
                                        <div className="flex-1 overflow-y-auto space-y-2 pr-2 scrollbar-thin">
                                            {scannedFiles.map((file, i) => (
                                                <div key={i} className="flex items-center gap-3 p-2 hover:bg-warm-50 rounded transition-colors border-b border-warm-100 last:border-0">
                                                    <span className="text-[10px] opacity-30 font-mono">{String(i + 1).padStart(2, '0')}</span>
                                                    <span className="text-[11px] font-mono text-text-muted truncate">{file}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>

                {/* RIGHT PANEL - Fixed Static Image */}
                <div className="hidden lg:flex flex-col h-full overflow-hidden pt-4">
                    {/* Added 'animate-none' to override any global slide-up animations on the card */}
                    <div className="flex-1 relative glass-card flex flex-col overflow-hidden bg-white/40 shadow-card animate-none">

                        {/* Decorative Content - Permanently Static Until Analysis */}
                        {!isAuditDone && (
                            <div className={`absolute inset-0 flex flex-col items-center justify-center p-6 ${isAnalyzing ? 'opacity-30 blur-sm' : 'opacity-100'}`}>
                                <div className="relative w-full h-full rounded-[2.5rem] overflow-hidden shadow-card border border-warm-200/50 bg-[#F5F1EB]">
                                    <Image
                                        src="/repo-visual.jpg"
                                        alt="Code Vulnerability Visualization"
                                        fill
                                        className="object-cover"
                                        style={{ objectPosition: 'center' }}
                                        priority
                                    />

                                    {/* Overlays */}
                                    <div className="absolute top-10 left-10 p-5 glass-card border-accent-primary/20 bg-white/60 backdrop-blur-sm">
                                        <Code className="w-6 h-6 text-accent-primary mb-2" />
                                        <div className="text-[10px] font-bold uppercase tracking-widest text-text-muted">SAST Mode</div>
                                        <div className="text-lg font-serif text-text-primary">Advanced Logic Audit</div>
                                    </div>
                                    <div className="absolute bottom-10 right-10 p-5 glass-card border-accent-gold/20 bg-white/60 backdrop-blur-sm">
                                        <Lock className="w-6 h-6 text-accent-gold mb-2" />
                                        <div className="text-[10px] font-bold uppercase tracking-widest text-text-muted">Secret Guard</div>
                                        <div className="text-lg font-serif text-text-primary">Zero Trust Compliance</div>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Analysis Status Overlay */}
                        {isAnalyzing && (
                            <div className="absolute inset-0 flex flex-col z-20 bg-white/10 backdrop-blur-[2px]">
                                <div className="flex-1 flex flex-col items-center justify-center p-8">
                                    <div className="flex flex-col items-center gap-4 p-8 glass-card border-accent-primary animate-pulse w-full max-w-sm">
                                        <div className="w-12 h-12 border-4 border-accent-primary border-t-transparent rounded-full animate-spin" />
                                        <div className="text-xl font-serif text-text-primary">Auditing Assets...</div>
                                        <div className="text-xs font-bold uppercase tracking-widest text-accent-primary">{progress}%</div>
                                    </div>
                                </div>

                                {scannedFiles.length > 0 && (
                                    <div className="p-6 bg-white/80 backdrop-blur-md border-t border-warm-200 animate-slide-up h-[40%] flex flex-col">
                                        <div className="flex items-center justify-between mb-4">
                                            <div className="flex items-center gap-2">
                                                <FileCode className="w-4 h-4 text-accent-primary" />
                                                <h3 className="font-serif font-medium text-text-primary">Live Audit Manifest</h3>
                                            </div>
                                            <span className="text-[10px] uppercase font-bold tracking-widest text-text-muted">{scannedFiles.length} files queued</span>
                                        </div>
                                        <div className="flex-1 overflow-y-auto space-y-2 pr-2 scrollbar-thin">
                                            {scannedFiles.map((file, i) => (
                                                <div key={i} className="flex items-center gap-3 p-2 hover:bg-warm-50 rounded transition-colors border-b border-warm-100 last:border-0 bg-white/50">
                                                    <span className="text-[10px] opacity-30 font-mono">{String(i + 1).padStart(2, '0')}</span>
                                                    <span className="text-[11px] font-mono text-text-muted truncate">{file}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Security Expert Chat */}
                        <div className={`absolute inset-0 flex flex-col ${isAuditDone ? 'opacity-100' : 'opacity-0 pointer-events-none'}`}>
                            <div className="p-5 border-b border-warm-200 bg-white/90 backdrop-blur-md flex items-center justify-between shadow-sm">
                                <div className="flex items-center gap-2">
                                    <MessageSquare className="w-4 h-4 text-accent-primary" />
                                    <span className="font-medium text-text-primary">Security Expert Chat</span>
                                </div>
                                <div className="flex items-center gap-2 text-[10px] text-text-muted uppercase tracking-wider">
                                    <span className="w-2 h-2 rounded-full bg-green-500" />
                                    SAST Live Session
                                </div>
                            </div>

                            <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-matrix-pattern">
                                {messages.map((msg, i) => (
                                    <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                                        <div className={`max-w-[85%] p-4 rounded-r-none ${msg.role === 'user'
                                            ? 'bg-accent-primary text-white ml-12 rounded-2xl rounded-tr-none shadow-md'
                                            : 'bg-white border border-warm-200 text-text-primary mr-12 rounded-2xl rounded-tl-none shadow-sm'
                                            }`}>
                                            <div className="flex items-center gap-2 mb-1">
                                                {msg.role === 'assistant' ? (
                                                    <Cpu className="w-3 h-3 opacity-70" />
                                                ) : (
                                                    <SpiderWeb className="w-3 h-3 opacity-70" />
                                                )}
                                                <span className="text-[10px] uppercase font-bold tracking-widest opacity-60">
                                                    {msg.role === 'assistant' ? 'Matrix AI' : 'Security Lead'}
                                                </span>
                                            </div>
                                            {msg.role === 'assistant' ? (
                                                <div className="prose prose-sm max-w-none prose-pre:bg-gray-900 prose-pre:text-gray-100 prose-code:text-accent-primary prose-headings:text-black prose-p:text-black prose-li:text-black prose-strong:text-black">
                                                    <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                                        {msg.content}
                                                    </ReactMarkdown>
                                                </div>
                                            ) : (
                                                <p className="text-sm leading-relaxed">{msg.content}</p>
                                            )}
                                        </div>
                                    </div>
                                ))}
                                {isThinking && (
                                    <div className="flex justify-start">
                                        <div className="bg-white border border-warm-200 text-text-primary mr-12 rounded-2xl rounded-tl-none shadow-sm p-4">
                                            <div className="flex items-center gap-2 mb-1">
                                                <Cpu className="w-3 h-3 opacity-70 animate-pulse" />
                                                <span className="text-[10px] uppercase font-bold tracking-widest opacity-60">Matrix AI</span>
                                            </div>
                                            <div className="flex gap-1 mt-1">
                                                <span className="w-1.5 h-1.5 rounded-full bg-accent-primary/40 animate-bounce [animation-delay:-0.3s]" />
                                                <span className="w-1.5 h-1.5 rounded-full bg-accent-primary/40 animate-bounce [animation-delay:-0.15s]" />
                                                <span className="w-1.5 h-1.5 rounded-full bg-accent-primary/40 animate-bounce" />
                                            </div>
                                        </div>
                                    </div>
                                )}
                                <div ref={chatEndRef} />
                            </div>

                            <div className="p-4 bg-white/80 backdrop-blur-md border-t border-warm-200">
                                <div className="relative">
                                    <input
                                        type="text"
                                        placeholder="Ask about specific code vulnerabilities..."
                                        className="input-glass pr-12 w-full"
                                        value={input}
                                        onChange={(e) => setInput(e.target.value)}
                                        onKeyPress={handleKeyPress}
                                    />
                                    <button
                                        onClick={handleSendMessage}
                                        className="absolute right-2 top-1/2 -translate-y-1/2 p-2 text-accent-primary hover:text-accent-primary/80 transition-colors"
                                    >
                                        <Send className="w-5 h-5" />
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="mt-6 grid grid-cols-3 gap-4">
                        <div className="glass-card p-6 text-center">
                            <div className="text-3xl font-serif text-accent-primary font-light">{isAuditDone ? (scannedFiles.length || '~') : '0'}</div>
                            <div className="text-[10px] text-text-muted uppercase tracking-tighter">Files Scanned</div>
                        </div>
                        <div className="glass-card p-6 text-center">
                            <div className="text-3xl font-serif text-red-500 font-light">{isAuditDone ? stats.high : '0'}</div>
                            <div className="text-[10px] text-text-muted uppercase tracking-tighter">High Severity</div>
                        </div>
                        <div className="glass-card p-6 text-center">
                            <div className="text-3xl font-serif text-accent-gold font-light">{isAuditDone ? stats.secrets : '0'}</div>
                            <div className="text-[10px] text-text-muted uppercase tracking-tighter">Credentials</div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
}

export default function RepoAnalysisPage() {
    return (
        <Suspense fallback={
            <div className="min-h-screen bg-bg-primary flex items-center justify-center">
                <div className="text-center animate-pulse">
                    <Cpu className="w-12 h-12 text-accent-primary mx-auto mb-4" />
                    <p className="text-text-muted font-serif">Loading Matrix SAST Engine...</p>
                </div>
            </div>
        }>
            <RepoAnalysisContent />
        </Suspense>
    );
}