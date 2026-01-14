'use client';

import { useState, useEffect, useRef } from 'react';
import {
    MessageSquare, Send, X, Bot, User, Trash2,
    ChevronDown, ChevronUp, Sparkles, Terminal,
    ShieldAlert, ShieldCheck, Zap, ArrowRight, BookOpen
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import rehypeSanitize from 'rehype-sanitize';
import { api } from '../lib/matrix_api';

interface Message {
    role: 'user' | 'assistant';
    content: string;
    timestamp: Date;
}

interface ChatbotProps {
    scanResults?: string; // Serialized scan context
    scanId?: number;
    isOpen: boolean;
    onClose: () => void;
}

export function Chatbot({ scanResults, scanId, isOpen, onClose }: ChatbotProps) {
    const [messages, setMessages] = useState<Message[]>([]);
    const [input, setInput] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [suggestedQuestions, setSuggestedQuestions] = useState<string[]>([
        "What are the most critical issues?",
        "How do I fix the exposed secrets?",
        "Show me exploit scenarios"
    ]);
    const scrollRef = useRef<HTMLDivElement>(null);

    // Auto-scroll to bottom
    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [messages, isLoading]);

    const handleSendMessage = async (msg: string) => {
        if (!msg.trim() || isLoading) return;

        const userMsg: Message = {
            role: 'user',
            content: msg,
            timestamp: new Date()
        };

        setMessages(prev => [...prev, userMsg]);
        setInput('');
        setIsLoading(true);

        try {
            const response = await api.chat(msg, scanId);

            const aiMsg: Message = {
                role: 'assistant',
                content: response.response,
                timestamp: new Date()
            };

            setMessages(prev => [...prev, aiMsg]);
            setSuggestedQuestions(response.suggested_questions);
        } catch (error) {
            const errorMsg: Message = {
                role: 'assistant',
                content: "I encountered an error while processing your request. Please ensure the API is reachable and try again.",
                timestamp: new Date()
            };
            setMessages(prev => [...prev, errorMsg]);
        } finally {
            setIsLoading(false);
        }
    };

    const handleReset = async () => {
        try {
            await api.resetChat();
            setMessages([]);
            setSuggestedQuestions([
                "What are the most critical issues?",
                "How do I fix the exposed secrets?",
                "Show me exploit scenarios"
            ]);
        } catch (error) {
            console.error("Failed to reset chat:", error);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="fixed bottom-6 right-6 w-96 max-w-[calc(100vw-3rem)] h-[600px] max-h-[calc(100vh-8rem)] bg-white rounded-2xl shadow-2xl border border-warm-200 flex flex-col z-50 animate-slide-up overflow-hidden backdrop-blur-xl bg-white/90">
            {/* Header */}
            <div className="p-4 border-b border-warm-200 bg-gradient-to-r from-accent-primary to-accent-primary/80 text-white flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-white/20 backdrop-blur-md flex items-center justify-center">
                        <Bot className="w-6 h-6 text-white" />
                    </div>
                    <div>
                        <h3 className="font-bold text-sm tracking-tight">MATRIX AI MENTOR</h3>
                        <div className="flex items-center gap-1.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
                            <span className="text-[10px] text-white/80 font-medium uppercase tracking-wider">Security Engine Online</span>
                        </div>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={handleReset}
                        className="p-2 hover:bg-white/10 rounded-lg transition-colors text-white/80 hover:text-white"
                        title="Reset Conversation"
                    >
                        <Trash2 className="w-4 h-4" />
                    </button>
                    <button
                        onClick={onClose}
                        className="p-2 hover:bg-white/10 rounded-lg transition-colors"
                    >
                        <X className="w-5 h-5" />
                    </button>
                </div>
            </div>

            {/* Chat Body */}
            <div
                ref={scrollRef}
                className="flex-1 overflow-y-auto p-4 space-y-6 bg-warm-50/30 scroll-smooth"
            >
                {messages.length === 0 && (
                    <div className="flex flex-col items-center justify-center h-full text-center space-y-4 px-6 animate-fade-in">
                        <div className="w-16 h-16 rounded-2xl bg-accent-primary/10 flex items-center justify-center mb-2">
                            <Sparkles className="w-8 h-8 text-accent-primary" />
                        </div>
                        <div>
                            <h4 className="font-bold text-text-primary">I am your Security Mentor</h4>
                            <p className="text-sm text-text-muted mt-2">
                                I've analyzed your scan results. Ask me about specific vulnerabilities, exploit scenarios, or request code fixes.
                            </p>
                        </div>
                        <div className="w-full space-y-2 pt-4">
                            <p className="text-[10px] text-text-muted font-bold uppercase tracking-widest text-left ml-1">Quick Starts</p>
                            {suggestedQuestions.map((q, i) => (
                                <button
                                    key={i}
                                    onClick={() => handleSendMessage(q)}
                                    className="w-full text-left p-3 text-sm bg-white border border-warm-200 rounded-xl hover:border-accent-primary/40 hover:bg-accent-primary/5 transition-all text-text-secondary flex items-center gap-3 group"
                                >
                                    <div className="w-2 h-2 rounded-full bg-accent-primary/30 group-hover:bg-accent-primary transition-colors" />
                                    {q}
                                </button>
                            ))}
                        </div>
                    </div>
                )}

                {messages.map((msg, idx) => (
                    <div
                        key={idx}
                        className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'} animate-fade-in`}
                    >
                        <div className={`flex gap-3 max-w-[85%] ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
                            <div className={`w-8 h-8 rounded-lg flex-shrink-0 flex items-center justify-center ${msg.role === 'user' ? 'bg-warm-200 shadow-sm' : 'bg-accent-primary shadow-lg shadow-accent-primary/20'
                                }`}>
                                {msg.role === 'user' ? <User className="w-4 h-4 text-warm-600" /> : <Bot className="w-4 h-4 text-white" />}
                            </div>
                            <div className={`p-4 rounded-2xl text-sm leading-relaxed ${msg.role === 'user'
                                ? 'bg-white border border-warm-200 text-text-primary rounded-tr-none shadow-sm'
                                : 'bg-white border border-warm-200 text-text-primary rounded-tl-none shadow-md shadow-warm-100'
                                }`}>
                                <div className="prose prose-sm max-w-none prose-pre:bg-gray-900 prose-pre:text-green-400 prose-code:text-accent-primary prose-code:bg-accent-primary/5 prose-code:px-1 prose-code:rounded">
                                    <ReactMarkdown rehypePlugins={[rehypeSanitize]}>{msg.content}</ReactMarkdown>
                                </div>
                                <div className={`text-[10px] mt-2 opacity-30 ${msg.role === 'user' ? 'text-right' : ''}`}>
                                    {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                </div>
                            </div>
                        </div>
                    </div>
                ))}

                {isLoading && (
                    <div className="flex justify-start animate-fade-in">
                        <div className="flex gap-3">
                            <div className="w-8 h-8 rounded-lg bg-accent-primary flex items-center justify-center shadow-lg shadow-accent-primary/20">
                                <Bot className="w-4 h-4 text-white animate-pulse" />
                            </div>
                            <div className="bg-white border border-warm-200 p-4 rounded-2xl rounded-tl-none shadow-md shadow-warm-100">
                                <div className="flex gap-1.5">
                                    <div className="w-1.5 h-1.5 bg-accent-primary rounded-full animate-bounce" style={{ animationDelay: '0s' }} />
                                    <div className="w-1.5 h-1.5 bg-accent-primary rounded-full animate-bounce" style={{ animationDelay: '0.2s' }} />
                                    <div className="w-1.5 h-1.5 bg-accent-primary rounded-full animate-bounce" style={{ animationDelay: '0.4s' }} />
                                </div>
                            </div>
                        </div>
                    </div>
                )}
            </div>

            {/* Input Area */}
            <div className="p-4 bg-white border-t border-warm-200">
                {messages.length > 0 && suggestedQuestions.length > 0 && (
                    <div className="flex gap-2 overflow-x-auto pb-3 no-scrollbar mb-1">
                        {suggestedQuestions.map((q, i) => (
                            <button
                                key={i}
                                onClick={() => handleSendMessage(q)}
                                className="whitespace-nowrap px-3 py-1.5 text-xs bg-warm-50 text-text-secondary border border-warm-200 rounded-full hover:bg-accent-primary/5 hover:border-accent-primary/30 hover:text-accent-primary transition-all flex items-center gap-2 group"
                            >
                                <Zap className="w-3 h-3 text-accent-primary" />
                                {q}
                            </button>
                        ))}
                    </div>
                )}
                <div className="relative flex items-center">
                    <input
                        type="text"
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyPress={(e) => e.key === 'Enter' && handleSendMessage(input)}
                        placeholder="Ask your security mentor..."
                        className="w-full pl-4 pr-12 py-3.5 bg-warm-50/50 border-2 border-warm-200 rounded-xl focus:border-accent-primary focus:ring-4 focus:ring-accent-primary/5 outline-none transition-all text-sm placeholder:text-warm-400"
                        disabled={isLoading}
                    />
                    <button
                        onClick={() => handleSendMessage(input)}
                        disabled={!input.trim() || isLoading}
                        className="absolute right-2 p-2.5 bg-accent-primary text-white rounded-lg shadow-lg shadow-accent-primary/20 hover:scale-105 active:scale-95 disabled:opacity-50 disabled:hover:scale-100 transition-all"
                    >
                        <Send className="w-4 h-4" />
                    </button>
                </div>
                <div className="text-[10px] text-center text-warm-400 mt-2 font-medium uppercase tracking-[0.2em]">
                    Powered by Matrix Intelligence
                </div>
            </div>
        </div>
    );
}
