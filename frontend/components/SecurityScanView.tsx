'use client';

import React from 'react';
import {
    CheckCircle, XCircle, AlertTriangle,
    Terminal, Cpu, Globe, Clock,
    ExternalLink, Fingerprint, EyeOff, AlertCircle,
    Shield
} from 'lucide-react';
import { Scan, Vulnerability } from '@/lib/matrix_api';

interface SecurityScanViewProps {
    scan: Scan;
    findings: Vulnerability[];
    activeTab: 'active' | 'suppressed';
    terminalLines: string[];
}

export function SecurityScanView({ scan, findings, activeTab, terminalLines }: SecurityScanViewProps) {
    const counts = {
        critical: findings.filter(f => !f.is_suppressed && f.severity === 'critical').length,
        high: findings.filter(f => !f.is_suppressed && f.severity === 'high').length,
        medium: findings.filter(f => !f.is_suppressed && f.severity === 'medium').length,
        low: findings.filter(f => !f.is_suppressed && f.severity === 'low').length,
        suppressed: findings.filter(f => f.is_suppressed).length
    };

    const filteredFindings = findings.filter(f =>
        activeTab === 'active' ? !f.is_suppressed : f.is_suppressed
    );

    return (
        <div className="space-y-12 animate-fade-in">
            {/* Security Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-6">
                {[
                    { label: 'Critical', count: counts.critical, color: 'text-red-600', border: 'border-b-red-500' },
                    { label: 'High', count: counts.high, color: 'text-orange-600', border: 'border-b-orange-500' },
                    { label: 'Medium', count: counts.medium, color: 'text-amber-600', border: 'border-b-amber-500' },
                    { label: 'Low', count: counts.low, color: 'text-blue-600', border: 'border-b-blue-500' },
                    { label: 'Suppressed', count: counts.suppressed, color: 'text-accent-primary', border: 'border-b-accent-primary' }
                ].map((item, i) => (
                    <div key={i} className={`glass-card p-6 border-b-4 ${item.border}/30`}>
                        <div className={`${item.color} font-bold text-[10px] uppercase tracking-[0.2em] mb-1`}>{item.label}</div>
                        <div className="text-4xl font-serif-display font-medium text-text-primary">{item.count}</div>
                    </div>
                ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Findings List */}
                <div className="lg:col-span-2 space-y-6">
                    <h3 className="text-2xl font-serif-display font-medium text-text-primary flex items-center gap-3 mb-4">
                        <Shield className="w-6 h-6 text-accent-primary" />
                        Infrastructure Security Findings
                    </h3>

                    {filteredFindings.length === 0 ? (
                        <div className="glass-card p-20 text-center">
                            <CheckCircle className="w-16 h-16 text-green-500/30 mx-auto mb-4" />
                            <h4 className="text-xl font-medium text-text-primary">
                                {activeTab === 'active' ? 'Target Secured' : 'No Suppressed Findings'}
                            </h4>
                            <p className="text-text-secondary mt-2 max-w-sm mx-auto italic">
                                {activeTab === 'active'
                                    ? 'All dynamic security tests passed without intercepting a successful attack vector.'
                                    : 'No findings were diverted from the primary report.'}
                            </p>
                        </div>
                    ) : (
                        filteredFindings.map((vuln) => (
                            <div key={vuln.id} className="glass-card overflow-hidden group hover:border-accent-primary/20 transition-all duration-500">
                                <div className="p-8">
                                    <div className="flex items-center justify-between mb-6 pb-3 border-b border-warm-100">
                                        <div className="flex items-center gap-3">
                                            <span className="text-[10px] font-mono font-bold text-accent-primary bg-accent-primary/10 px-2 py-1 rounded">
                                                SEC-{String(scan.id).padStart(3, '0')}-{String(vuln.id).padStart(4, '0')}
                                            </span>
                                        </div>
                                        <span className={`severity-tag severity-${vuln.severity} px-4 py-1.5 rounded-lg text-xs font-bold uppercase tracking-widest shadow-sm`}>
                                            {vuln.severity}
                                        </span>
                                    </div>

                                    <div className="flex gap-6 mb-8">
                                        <div className={`w-14 h-14 rounded-2xl flex items-center justify-center flex-shrink-0 bg-accent-primary/5 text-accent-primary`}>
                                            <Globe className="w-8 h-8" />
                                        </div>
                                        <div>
                                            <h4 className="text-xl font-bold text-text-primary uppercase tracking-tight">
                                                {vuln.vulnerability_type.replace(/_/g, ' ')}
                                            </h4>
                                            <p className="text-text-secondary mt-1 max-w-xl">{vuln.description}</p>
                                            <div className="mt-4 flex items-center gap-2">
                                                <code className="text-[11px] bg-warm-100 px-2 py-1 rounded text-accent-primary font-mono shadow-sm">
                                                    {vuln.method} {vuln.url}
                                                </code>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 bg-matrix-pattern/5 p-6 rounded-2xl border border-warm-100 italic">
                                        <div className="space-y-3">
                                            <div className="text-[10px] font-bold uppercase tracking-widest text-text-muted flex items-center gap-2">
                                                <Terminal className="w-4 h-4" /> Technical Context
                                            </div>
                                            <pre className="text-[11px] font-mono p-4 bg-white/80 border border-warm-200 rounded-xl overflow-x-auto text-text-primary h-[120px] shadow-inner">
                                                {vuln.evidence || 'No direct evidence payload captured.'}
                                            </pre>
                                        </div>
                                        <div className="space-y-3">
                                            <div className="text-[10px] font-bold uppercase tracking-widest text-text-muted flex items-center gap-2">
                                                <Cpu className="w-4 h-4" /> Security Audit
                                            </div>
                                            <div className="text-sm text-text-secondary leading-relaxed h-[120px] overflow-y-auto pr-2">
                                                {vuln.ai_analysis || 'Dynamic analysis completed. Automated validation required to confirm reachability.'}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ))
                    )}
                </div>

                {/* Sidebar: Live Terminal & Legend */}
                <div className="space-y-8">
                    {terminalLines.length > 0 && (
                        <div className="glass-card p-6">
                            <h3 className="text-lg font-serif-display font-medium text-text-primary mb-6 flex items-center gap-2">
                                <Terminal className="w-5 h-5" />
                                Live Intelligence
                            </h3>
                            <div className="bg-gray-950 rounded-xl p-4 font-mono text-xs max-h-64 overflow-y-auto space-y-1 shadow-2xl border border-white/5">
                                {terminalLines.map((line, i) => (
                                    <div key={i} className="text-green-400/80">
                                        <span className="opacity-40 mr-2">{'>'}</span>{line}
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    <div className="glass-card p-8">
                        <h3 className="text-lg font-serif-display font-medium text-text-primary mb-6">Security Context</h3>
                        <div className="space-y-4">
                            {[
                                { label: 'Auth Stack', val: 'E2EE JWT' },
                                { label: 'Env Proxy', val: 'Isolated Mesh' },
                                { label: 'Compliance', val: 'SOC2/GDPR' }
                            ].map((spec, i) => (
                                <div key={i} className="flex justify-between items-center py-2 border-b border-warm-100 last:border-0">
                                    <span className="text-xs text-text-muted uppercase font-bold tracking-widest">{spec.label}</span>
                                    <span className="text-xs font-bold text-text-primary">{spec.val}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
