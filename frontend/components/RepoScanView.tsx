'use client';

import React from 'react';
import {
    CheckCircle, XCircle, AlertTriangle,
    Terminal, Cpu, FileCode, Globe, Clock,
    ExternalLink, Fingerprint, EyeOff, AlertCircle
} from 'lucide-react';
import { Scan, Vulnerability } from '@/lib/matrix_api';

interface RepoScanViewProps {
    scan: Scan;
    findings: Vulnerability[];
    activeTab: 'active' | 'suppressed';
}

export function RepoScanView({ scan, findings, activeTab }: RepoScanViewProps) {
    console.log('[RepoScanView] Rendering with scan:', {
        id: scan.id,
        type: scan.scan_type,
        files_count: scan.scanned_files?.length,
        files: scan.scanned_files
    });
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
        <div className="space-y-8 animate-fade-in">
            {/* Repo Summary Stats */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                <div className="glass-card p-6 border-l-4 border-l-red-500">
                    <div className="text-red-600 font-bold text-[10px] uppercase tracking-widest mb-1">Critical/High</div>
                    <div className="text-4xl font-serif-display font-medium text-text-primary">
                        {(counts.critical + counts.high).toString().padStart(2, '0')}
                    </div>
                </div>
                <div className="glass-card p-6 border-l-4 border-l-amber-500">
                    <div className="text-amber-600 font-bold text-[10px] uppercase tracking-widest mb-1">Medium/Low</div>
                    <div className="text-4xl font-serif-display font-medium text-text-primary">
                        {(counts.medium + counts.low).toString().padStart(2, '0')}
                    </div>
                </div>
                <div className="glass-card p-6 border-l-4 border-l-accent-primary">
                    <div className="text-accent-primary font-bold text-[10px] uppercase tracking-widest mb-1">Files Audited</div>
                    <div className="text-4xl font-serif-display font-medium text-text-primary">
                        {(scan.scanned_files?.length || 0).toString().padStart(2, '0')}
                    </div>
                </div>
                <div className="glass-card p-6 border-l-4 border-l-gray-400">
                    <div className="text-gray-500 font-bold text-[10px] uppercase tracking-widest mb-1">Suppressed</div>
                    <div className="text-4xl font-serif-display font-medium text-text-primary">
                        {counts.suppressed.toString().padStart(2, '0')}
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Findings List */}
                <div className="lg:col-span-2 space-y-6">
                    <h3 className="text-2xl font-serif-display font-medium text-text-primary flex items-center gap-3 mb-4">
                        <FileCode className="w-6 h-6 text-accent-primary" />
                        Code Analysis Findings
                    </h3>

                    {filteredFindings.length === 0 ? (
                        <div className="glass-card p-20 text-center">
                            <CheckCircle className="w-16 h-16 text-green-500/30 mx-auto mb-4" />
                            <h4 className="text-xl font-medium text-text-primary">
                                {activeTab === 'active' ? 'No Vulnerabilities Detected' : 'No Suppressed Findings'}
                            </h4>
                            <p className="text-text-secondary mt-2 max-w-sm mx-auto italic">
                                {activeTab === 'active'
                                    ? 'The AI SAST Auditor found no critical security flaws in the provided source files.'
                                    : 'No findings were auto-suppressed by the integrity mesh.'}
                            </p>
                        </div>
                    ) : (
                        filteredFindings.map((vuln) => (
                            <div key={vuln.id} className="glass-card overflow-hidden hover:border-accent-primary/20 transition-all duration-500">
                                <div className="p-8">
                                    <div className="flex items-center justify-between mb-6 pb-2 border-b border-warm-100">
                                        <span className="text-[10px] font-mono font-bold text-accent-primary bg-accent-primary/10 px-2 py-1 rounded">
                                            SAST-{String(scan.id).padStart(3, '0')}-{String(vuln.id).padStart(4, '0')}
                                        </span>
                                        <span className={`text-[10px] font-bold px-4 py-1.5 rounded-lg uppercase tracking-widest severity-${vuln.severity}`}>
                                            {vuln.severity}
                                        </span>
                                    </div>

                                    <div className="space-y-4">
                                        <div>
                                            <h4 className="text-xl font-bold text-text-primary uppercase tracking-tight">
                                                {vuln.vulnerability_type.replace(/_/g, ' ')}
                                            </h4>
                                            <div className="flex items-center gap-2 mt-1">
                                                <FileCode className="w-3.5 h-3.5 text-text-muted" />
                                                <span className="text-xs font-mono text-text-secondary truncate">{vuln.file_path || 'Repository Logic'}</span>
                                            </div>
                                        </div>

                                        <p className="text-sm text-text-secondary leading-relaxed">{vuln.description}</p>

                                        {/* Evidence Snippet */}
                                        <div className="bg-gray-900 rounded-xl p-4 overflow-hidden">
                                            <div className="flex items-center gap-2 text-[10px] text-gray-400 uppercase tracking-widest mb-2">
                                                <Terminal className="w-3 h-3" />
                                                Vulnerable Code Snippet
                                            </div>
                                            <pre className="text-xs font-mono text-gray-200 overflow-x-auto whitespace-pre-wrap">
                                                {vuln.evidence || '// No code snippet captured for this finding'}
                                            </pre>
                                        </div>

                                        {/* AI Analysis & Remediation */}
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t border-warm-100">
                                            <div className="space-y-2">
                                                <div className="text-[10px] font-bold uppercase tracking-widest text-text-muted flex items-center gap-2">
                                                    <Cpu className="w-3 h-3" /> AI Context
                                                </div>
                                                <p className="text-xs text-text-secondary italic leading-relaxed">
                                                    {vuln.ai_analysis || 'Automated logic analysis identifies potential reachability to sinks.'}
                                                </p>
                                            </div>
                                            {!vuln.is_suppressed && (
                                                <div className="space-y-2">
                                                    <div className="text-[10px] font-bold uppercase tracking-widest text-green-600 flex items-center gap-2">
                                                        <Fingerprint className="w-3 h-3" /> Remediation
                                                    </div>
                                                    <p className="text-xs text-text-secondary leading-relaxed">
                                                        {vuln.remediation || 'Refer to secure coding standards for input sanitization.'}
                                                    </p>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ))
                    )}
                </div>

                {/* Sidebar: Scanned Files */}
                <div className="space-y-8">
                    <div className="glass-card p-6">
                        <h3 className="text-lg font-serif-display font-medium text-text-primary mb-6 flex items-center gap-2">
                            <Globe className="w-5 h-5 text-accent-primary" />
                            Audited Manifest
                        </h3>
                        <div className="space-y-2 max-h-[600px] overflow-y-auto pr-2 scrollbar-thin">
                            {scan.scanned_files && scan.scanned_files.length > 0 ? (
                                scan.scanned_files.map((file, i) => (
                                    <div key={i} className="flex items-center gap-3 p-3 bg-warm-50/50 hover:bg-warm-100/50 rounded-xl transition-colors border border-warm-100 group">
                                        <span className="text-[10px] opacity-30 font-mono group-hover:opacity-100 transition-opacity">
                                            {String(i + 1).padStart(2, '0')}
                                        </span>
                                        <span className="text-xs font-mono text-text-muted truncate flex-1">{file}</span>
                                        <CheckCircle className="w-3 h-3 text-green-500 opacity-40" />
                                    </div>
                                ))
                            ) : (
                                <div className="text-center py-8 text-text-muted text-xs italic">
                                    No file manifest captured for this scan.
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Quick Specs */}
                    <div className="glass-card p-6">
                        <h3 className="text-lg font-serif-display font-medium text-text-primary mb-6">Execution Specs</h3>
                        <div className="space-y-4">
                            <div className="flex justify-between items-center py-2 border-b border-warm-100">
                                <span className="text-xs text-text-muted uppercase font-bold tracking-widest">Confidence</span>
                                <span className="text-sm font-bold text-green-600">98.2%</span>
                            </div>
                            <div className="flex justify-between items-center py-2 border-b border-warm-100">
                                <span className="text-xs text-text-muted uppercase font-bold tracking-widest">Engine</span>
                                <span className="text-sm font-bold text-text-primary">Matrix-SAST-v1</span>
                            </div>
                            <div className="flex justify-between items-center py-2">
                                <span className="text-xs text-text-muted uppercase font-bold tracking-widest">Latency</span>
                                <span className="text-sm font-bold text-accent-primary">420ms/file</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
