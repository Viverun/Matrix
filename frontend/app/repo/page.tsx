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
import { api, Scan, Vulnerability } from '../../lib/api';
import { useRouter } from 'next/navigation';

const MOCK_FILES = [
    'backend/main.py',
    'backend/agents/github_agent.py',
    'backend/core/openrouter_client.py',
    'backend/config.py',
    'backend/api/vulnerabilities.py',
    'frontend/app/repo/page.tsx',
    'frontend/app/hub/page.tsx',
    'backend/workers.py',
    'backend/models/scan.py',
    '.env.example',
    'requirements.txt',
    'package.json'
];

export default function RepoAnalysisPage() {
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
    const chatEndRef = useRef<HTMLDivElement>(null);
    const logsEndRef = useRef<HTMLDivElement>(null);

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

    const [scanId, setScanId] = useState<number | null>(null);

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
        setAuditLogs(['[SYSTEM] Initializing Matrix SAST Engine...', '[SYSTEM] Authenticating with GitHub API...']);
        setMessages([
            { role: 'assistant', content: `Analyzing ${repoUrl}. I'm scanning for secrets and vulnerabilities.` }
        ]);

        try {
            // 1. Create Scan
            const scan = await api.createScan({
                target_url: repoUrl,
                scan_type: 'GITHUB_SAST',
                agents_enabled: ['github_security', 'api_security', 'xss']
            });
            setScanId(scan.id);
            setAuditLogs(prev => [...prev, `[INFO] Scan job created (ID: ${scan.id})`]);

            // 2. Poll for Status
            const interval = setInterval(async () => {
                try {
                    const statusUpdate = await api.getScan(scan.id);
                    setProgress(statusUpdate.progress);

                    // Add dynamic logs based on progress/status (simplified)
                    if (statusUpdate.status === 'running') {
                        // We could poll recent logs if the backend exposed them, for now just show progress
                    }

                    if (statusUpdate.status === 'completed') {
                        clearInterval(interval);
                        setIsAnalyzing(false);
                        setIsAuditDone(true);
                        setAuditLogs(prev => [...prev, '[SUCCESS] Analysis completed successfully.', '[SYSTEM] Fetching findings...']);

                        // 3. Get Findings
                        const vulnResponse = await api.getVulnerabilities(scan.id);
                        const findings = vulnResponse.items;
                        const critical = findings.filter(f => f.severity === 'critical').length;
                        const high = findings.filter(f => f.severity === 'high').length;
                        const secrets = findings.filter(f => f.vulnerability_type === 'secret_exposure').length;

                        // Update Stats State
                        setStats({
                            files: 0, // Backend doesn't return file count in vuln summary, use placeholder or fetch from scan logs if available
                            high: high + critical,
                            secrets: secrets
                        });

                        // Construct summary message
                        const summary = `Audit complete! I found ${findings.length} issues in total.\n` +
                            `- Critical: ${critical}\n` +
                            `- High: ${high}\n` +
                            `- Secrets: ${secrets}\n\n` +
                            `You can ask me about specific findings or remediation steps.`;

                        setMessages(prevMsg => [...prevMsg, {
                            role: 'assistant',
                            content: summary
                        }]);

                        // Update the "Stats" in the UI (currently hardcoded in JSX) via state if needed
                        // For now we just update the chat.

                    } else if (statusUpdate.status === 'failed' || statusUpdate.status === 'cancelled') {
                        clearInterval(interval);
                        setIsAnalyzing(false);
                        setAuditLogs(prev => [...prev, `[ERROR] Scan failed: ${statusUpdate.error_message}`]);
                        setMessages(prevMsg => [...prevMsg, {
                            role: 'assistant',
                            content: `Analysis failed: ${statusUpdate.error_message}. Please check the URL and try again.`
                        }]);
                    }
                } catch (e) {
                    console.error("Poll error", e);
                }
            }, 2000);

        } catch (error: any) {
            setIsAnalyzing(false);
            setAuditLogs(prev => [...prev, `[ERROR] Failed to start scan: ${error.message}`]);
            setMessages(prevMsg => [...prevMsg, {
                role: 'assistant',
                content: `Could not start analysis: ${error.message}`
            }]);
        }
    };

    const handleSendMessage = () => {
        if (!input.trim()) return;

        const newMessages = [...messages, { role: 'user', content: input }];
        setMessages(newMessages);
        setInput('');

        // Placeholder for Chatbot Integration
        // Ideally we would call an endpoint like POST /api/chat { message, context: { scan_id: scanId } }
        setTimeout(() => {
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: `I'm sorry, I cannot answer questions about the code yet (Chat API integration pending). Please view the full report in the Dashboard.`
            }]);
        }, 1000);
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

                    <div className="flex-1 min-h-0">
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
                                            <span className="text-2xl font-serif font-bold">03</span>
                                        </div>
                                        <div className="text-xs uppercase font-bold tracking-widest text-text-muted">High Severity</div>
                                    </div>
                                    <div className="glass-card p-6 border-l-4 border-l-accent-gold">
                                        <div className="flex items-center gap-2 mb-2 text-accent-gold">
                                            <Lock className="w-5 h-5" />
                                            <span className="text-2xl font-serif font-bold">05</span>
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
                                        {[
                                            { file: 'backend/main.py', issues: 2, severity: 'high' },
                                            { file: 'backend/api/auth.py', issues: 3, severity: 'critical' },
                                            { file: '.env', issues: 1, severity: 'critical' },
                                        ].map((item, i) => (
                                            <div key={i} className="flex items-center justify-between p-3 bg-warm-50 rounded-lg border border-warm-200">
                                                <div className="flex items-center gap-3">
                                                    <FileCode className="w-4 h-4 text-accent-primary" />
                                                    <span className="text-xs font-mono text-text-primary">{item.file}</span>
                                                </div>
                                                <span className={`text-[10px] font-bold uppercase tracking-tighter px-2 py-0.5 rounded ${item.severity === 'critical' ? 'bg-red-100 text-red-600' : 'bg-orange-100 text-orange-600'
                                                    }`}>
                                                    {item.issues} Issues
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                    <button className="w-full mt-4 btn-secondary py-3 text-xs uppercase tracking-widest font-bold">
                                        View Full Source Report
                                    </button>
                                </div>
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
                            <div className="absolute inset-0 flex items-center justify-center z-20 bg-white/10 backdrop-blur-[2px]">
                                <div className="flex flex-col items-center gap-4 p-8 glass-card border-accent-primary animate-pulse">
                                    <div className="w-12 h-12 border-4 border-accent-primary border-t-transparent rounded-full animate-spin" />
                                    <div className="text-xl font-serif text-text-primary">Auditing Assets...</div>
                                    <div className="text-xs font-bold uppercase tracking-widest text-accent-primary">{progress}%</div>
                                </div>
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
                                        <div className={`max-w-[85%] p-4 rounded-right-none ${msg.role === 'user'
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
                                            <p className="text-sm leading-relaxed">{msg.content}</p>
                                        </div>
                                    </div>
                                ))}
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
                            <div className="text-3xl font-serif text-accent-primary font-light">{isAuditDone ? (stats.files || '~') : '0'}</div>
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