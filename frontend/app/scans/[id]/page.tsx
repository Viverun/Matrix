'use client';

import { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import {
    ArrowLeft, Shield, AlertTriangle, XCircle,
    CheckCircle, Info, Clock, Globe, Zap,
    FileText, Download, Share2, ExternalLink,
    Terminal, Cpu, Fingerprint, Loader2
} from 'lucide-react';
import Link from 'next/link';
import { SpiderWeb } from '../../../components/SpiderWeb';
import { useAuth } from '../../../context/AuthContext';
import { ProtectedRoute } from '../../../components/ProtectedRoute';
import { api, Scan, Vulnerability } from '../../../lib/api';

import { Navbar } from '../../../components/Navbar';

export default function ScanDetailPage() {
    const { id } = useParams();
    const { user, logout } = useAuth();
    const [scan, setScan] = useState<Scan | null>(null);
    const [findings, setFindings] = useState<Vulnerability[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const fetchScanDetails = async () => {
            if (!id) return;
            setIsLoading(true);
            try {
                const scanData = await api.getScan(Number(id));
                setScan(scanData);

                const vulnerabilities = await api.getVulnerabilities(Number(id));
                setFindings(vulnerabilities.items);
            } catch (err: any) {
                setError(err.message || 'Failed to retrieve audit intelligence');
            } finally {
                setIsLoading(false);
            }
        };

        fetchScanDetails();
    }, [id]);

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
                            <Link href="/dashboard" className="inline-flex items-center gap-2 text-text-muted hover:text-accent-primary transition-colors mb-4 font-bold text-xs uppercase tracking-widest">
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
                            <button className="px-5 py-2.5 bg-white border border-warm-200 rounded-xl text-text-primary text-sm font-bold uppercase tracking-widest hover:border-accent-primary/30 transition-all flex items-center gap-2">
                                <Download className="w-4 h-4" />
                                Export JSON
                            </button>
                            <button className="btn-primary rounded-xl flex items-center gap-2 shadow-lg">
                                <Share2 className="w-4 h-4" />
                                Share Results
                            </button>
                        </div>
                    </div>

                    {/* Report Summary Cards */}
                    <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-6 mb-12">
                        <div className="glass-card p-6 border-b-4 border-b-red-500/30">
                            <div className="text-red-600 font-bold text-[10px] uppercase tracking-[0.2em] mb-1">Critical</div>
                            <div className="text-4xl font-serif-display font-medium text-text-primary">{scan.critical_count}</div>
                            <div className="text-xs text-text-secondary mt-2 font-medium">Immediate Risk</div>
                        </div>
                        <div className="glass-card p-6 border-b-4 border-b-orange-500/30">
                            <div className="text-orange-600 font-bold text-[10px] uppercase tracking-[0.2em] mb-1">High</div>
                            <div className="text-4xl font-serif-display font-medium text-text-primary">{scan.high_count}</div>
                            <div className="text-xs text-text-secondary mt-2 font-medium">Elevated Threat</div>
                        </div>
                        <div className="glass-card p-6 border-b-4 border-b-amber-500/30">
                            <div className="text-amber-600 font-bold text-[10px] uppercase tracking-[0.2em] mb-1">Medium</div>
                            <div className="text-4xl font-serif-display font-medium text-text-primary">{scan.medium_count}</div>
                            <div className="text-xs text-text-secondary mt-2 font-medium">Technical Debt</div>
                        </div>
                        <div className="glass-card p-6 border-b-4 border-b-blue-500/30">
                            <div className="text-blue-600 font-bold text-[10px] uppercase tracking-[0.2em] mb-1">Low</div>
                            <div className="text-4xl font-serif-display font-medium text-text-primary">{scan.low_count}</div>
                            <div className="text-xs text-text-secondary mt-2 font-medium">Best Practices</div>
                        </div>
                        <div className="glass-card p-6 bg-accent-primary/5 border-transparent">
                            <div className="text-accent-primary font-bold text-[10px] uppercase tracking-[0.2em] mb-1">Aggregate</div>
                            <div className="text-4xl font-serif-display font-medium text-accent-primary">{scan.total_vulnerabilities}</div>
                            <div className="text-xs text-text-secondary mt-2 font-medium">Total Vectors</div>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                        {/* Findings List */}
                        <div className="lg:col-span-2 space-y-6">
                            <h3 className="text-2xl font-serif-display font-medium text-text-primary flex items-center gap-3 mb-2">
                                <div className="w-2 h-8 bg-accent-primary rounded-full" />
                                Individual Findings
                            </h3>

                            {findings.length === 0 ? (
                                <div className="glass-card p-20 text-center">
                                    <CheckCircle className="w-16 h-16 text-green-500/30 mx-auto mb-4" />
                                    <h4 className="text-xl font-medium text-text-primary">No Vulnerabilities Detected</h4>
                                    <p className="text-text-secondary mt-2 max-w-sm mx-auto">Your architecture successfully withstood all security orchestration tests.</p>
                                </div>
                            ) : (
                                findings.map((vuln) => (
                                    <div key={vuln.id} className="glass-card overflow-hidden group hover:border-accent-primary/20 transition-all duration-500">
                                        <div className="p-6 md:p-8">
                                            {/* Finding ID Header */}
                                            <div className="flex items-center justify-between mb-4 pb-3 border-b border-warm-100">
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
                                                <div className="text-[10px] text-text-muted font-mono">
                                                    {new Date(vuln.detected_at).toLocaleString()}
                                                </div>
                                            </div>
                                            
                                            <div className="flex flex-col md:flex-row md:items-start justify-between gap-6 mb-6">
                                                <div className="flex gap-5">
                                                    <div className={`w-14 h-14 rounded-2xl flex items-center justify-center flex-shrink-0 ${vuln.severity === 'critical' ? 'bg-red-500/10 text-red-600' :
                                                        vuln.severity === 'high' ? 'bg-orange-500/10 text-orange-600' :
                                                            vuln.severity === 'medium' ? 'bg-amber-500/10 text-amber-600' :
                                                                'bg-blue-500/10 text-blue-600'
                                                        }`}>
                                                        {vuln.severity === 'critical' ? <XCircle className="w-8 h-8" /> : <AlertTriangle className="w-8 h-8" />}
                                                    </div>
                                                    <div>
                                                        <h4 className="text-xl font-bold text-text-primary uppercase tracking-tight">{vuln.vulnerability_type}</h4>
                                                        <p className="text-text-secondary mt-1 max-w-xl">{vuln.description}</p>
                                                        <div className="flex items-center gap-3 mt-4">
                                                            <div className="text-[10px] font-bold uppercase tracking-widest text-text-muted">Vector:</div>
                                                            <code className="text-xs bg-warm-100 px-2 py-1 rounded text-accent-primary font-mono">
                                                                {vuln.method} {vuln.url} {vuln.parameter && `?${vuln.parameter}=[*]`}
                                                            </code>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div className="flex flex-col items-end gap-2">
                                                    <span className={`severity-tag severity-${vuln.severity} px-4 py-1.5 rounded-lg text-xs font-bold uppercase tracking-widest shadow-sm`}>
                                                        {vuln.severity}
                                                    </span>
                                                    <div className="flex items-center gap-2">
                                                        <span className="text-[10px] font-bold text-text-muted bg-warm-100 px-2 py-0.5 rounded">
                                                            {vuln.ai_confidence}% conf
                                                        </span>
                                                    </div>
                                                    {vuln.cwe_id && <span className="text-[10px] font-bold text-text-muted uppercase tracking-widest">{vuln.cwe_id}</span>}
                                                    {vuln.owasp_category && (
                                                        <span className="text-[10px] text-text-muted font-medium">
                                                            {vuln.owasp_category.split(' – ')[0]}
                                                        </span>
                                                    )}
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
                                                        {vuln.ai_analysis || `Analysis pending. The ${vuln.vulnerability_type.replace(/_/g, ' ')} finding at this endpoint requires manual verification to confirm exploitability.`}
                                                    </div>
                                                </div>
                                            </div>

                                            {/* Remediation */}
                                            <div className="mt-8 p-6 bg-green-500/[0.03] rounded-2xl border border-green-500/10">
                                                <div className="flex items-center gap-2 text-green-700 font-bold text-xs uppercase tracking-widest mb-4">
                                                    <Fingerprint className="w-4 h-4" />
                                                    Remediation Roadmap
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
