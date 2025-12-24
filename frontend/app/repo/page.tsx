'use client';

import { useState, useRef, useEffect } from 'react';
import {
    Shield,
    Github,
    Send,
    MessageSquare,
    Code,
    Terminal,
    AlertTriangle,
    CheckCircle,
    XCircle,
    ArrowLeft,
    Search,
    Cpu,
    Lock
} from 'lucide-react';
import Link from 'next/link';
import Image from 'next/image';

export default function RepoAnalysisPage() {
    const [repoUrl, setRepoUrl] = useState('');
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [messages, setMessages] = useState([
        { role: 'assistant', content: 'Ready to analyze your repository. Paste a GitHub URL to begin the deep security audit.' }
    ]);
    const [input, setInput] = useState('');
    const [progress, setProgress] = useState(0);
    const chatEndRef = useRef<HTMLDivElement>(null);

    const scrollToBottom = () => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    };

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    const handleAnalyze = async () => {
        if (!repoUrl) return;
        setIsAnalyzing(true);
        setProgress(0);

        setMessages(prev => [...prev, {
            role: 'assistant',
            content: `Initiating deep analysis of ${repoUrl}. Accessing GitHub API and preparing SAST agents...`
        }]);

        // Simulate progress
        const interval = setInterval(() => {
            setProgress(prev => {
                if (prev >= 100) {
                    clearInterval(interval);
                    setIsAnalyzing(false);
                    setMessages(prevMsg => [...prevMsg, {
                        role: 'assistant',
                        content: 'Analysis complete. I found 3 high-severity issues and 5 secrets exposed. You can ask me details about specific files or vulnerabilities.'
                    }]);
                    return 100;
                }
                return prev + 5;
            });
        }, 300);
    };

    const handleSendMessage = (e: React.FormEvent) => {
        e.preventDefault();
        if (!input.trim()) return;

        const newMessages = [...messages, { role: 'user', content: input }];
        setMessages(newMessages);
        setInput('');

        // Simulate AI response
        setTimeout(() => {
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: `Analyzing your query about "${input}"... Based on the repository source code, this pattern is often associated with improper input validation in your API handlers.`
            }]);
        }, 1000);
    };

    return (
        <div className="min-h-screen bg-bg-primary">
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
                        <Link href="/" className="text-text-secondary hover:text-accent-primary transition-colors font-medium">About</Link>
                        <Link href="/hub" className="text-text-secondary hover:text-accent-primary transition-colors font-medium">Features</Link>
                        <Link href="/scan" className="text-text-secondary hover:text-accent-primary transition-colors font-medium">Scan</Link>
                        <Link href="/repo" className="text-accent-primary font-medium">Repository</Link>
                        <Link href="/dashboard" className="text-text-secondary hover:text-accent-primary transition-colors font-medium">Dashboard</Link>
                    </nav>

                    <div className="flex items-center gap-4">
                        <Link href="/scan" className="btn-primary">Get Started</Link>
                    </div>
                </div>
            </header>

            <main className="max-w-[1600px] mx-auto p-6 grid lg:grid-cols-2 gap-8 min-h-[calc(100-80px)]">
                {/* Left Side: Analysis & Chat */}
                <div className="flex flex-col gap-6">
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
                        {isAnalyzing && (
                            <div className="mt-4 space-y-2">
                                <div className="flex justify-between text-xs text-text-muted">
                                    <span>Scanning source files...</span>
                                    <span>{progress}%</span>
                                </div>
                                <div className="progress-bar">
                                    <div className="progress-bar-fill" style={{ width: `${progress}%` }} />
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Chat Interface */}
                    <div className="glass-card flex-1 flex flex-col overflow-hidden min-h-[500px]">
                        <div className="p-4 border-b border-warm-200 bg-warm-50/50 flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <MessageSquare className="w-4 h-4 text-accent-primary" />
                                <span className="font-medium text-text-primary">Security Expert Chat</span>
                            </div>
                            <div className="flex items-center gap-2 text-[10px] text-text-muted uppercase tracking-wider">
                                <span className="w-2 h-2 rounded-full bg-green-500" />
                                AI Optimized
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
                                                <Shield className="w-3 h-3 opacity-70" />
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

                        <form onSubmit={handleSendMessage} className="p-4 bg-warm-50/30 border-t border-warm-200">
                            <div className="relative">
                                <input
                                    type="text"
                                    placeholder="Ask about specific code vulnerabilities..."
                                    className="input-glass pr-12 w-full"
                                    value={input}
                                    onChange={(e) => setInput(e.target.value)}
                                />
                                <button
                                    type="submit"
                                    className="absolute right-2 top-1/2 -translate-y-1/2 p-2 text-accent-primary hover:text-accent-primary/80 transition-colors"
                                >
                                    <Send className="w-5 h-5" />
                                </button>
                            </div>
                        </form>
                    </div>
                </div>

                {/* Right Side: Decorative Image & Analysis Summary */}
                <div className="hidden lg:flex flex-col gap-6">
                    <div className="glass-card flex-1 relative overflow-hidden flex items-center justify-center p-12 bg-[#F5F1EB]">
                        <Image
                            src="/repo-visual.jpg"
                            alt="Code Vunlerability Visualization"
                            width={800}
                            height={600}
                            className="object-contain drop-shadow-2xl animate-float"
                        />
                        {/* Overlay accents */}
                        <div className="absolute top-12 left-12 p-6 glass-card border-accent-primary/20 animate-slide-up">
                            <Code className="w-8 h-8 text-accent-primary mb-2" />
                            <div className="text-xs font-bold uppercase tracking-widest text-text-muted">SAST Mode</div>
                            <div className="text-xl font-serif text-text-primary">Advanced Logic Audit</div>
                        </div>
                        <div className="absolute bottom-12 right-12 p-6 glass-card border-accent-gold/20 animate-slide-up delay-200">
                            <Lock className="w-8 h-8 text-accent-gold mb-2" />
                            <div className="text-xs font-bold uppercase tracking-widest text-text-muted">Secret Guard</div>
                            <div className="text-xl font-serif text-text-primary">Zero Trust Compliance</div>
                        </div>
                    </div>

                    <div className="grid grid-cols-3 gap-4">
                        <div className="glass-card p-6 text-center">
                            <div className="text-3xl font-serif text-accent-primary font-light">12k+</div>
                            <div className="text-xs text-text-muted uppercase tracking-tighter">Lines Audited</div>
                        </div>
                        <div className="glass-card p-6 text-center">
                            <div className="text-3xl font-serif text-red-500 font-light">08</div>
                            <div className="text-xs text-text-muted uppercase tracking-tighter">Critical Flaws</div>
                        </div>
                        <div className="glass-card p-6 text-center">
                            <div className="text-3xl font-serif text-accent-gold font-light">100%</div>
                            <div className="text-xs text-text-muted uppercase tracking-tighter">AI Coverage</div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
}
