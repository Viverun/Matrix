'use client';

import { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Shield,
    Clock,
    Database,
    FileCode,
    Table,
    Download,
    ChevronRight,
    CheckCircle,
    AlertTriangle,
    Info,
    Cpu,
    Hash,
    ArrowLeft,
    ExternalLink,
    RefreshCw,
    Eye,
    X,
    Activity,
    Fingerprint,
    Monitor,
    Box,
    Zap
} from 'lucide-react';
import Link from 'next/link';
import { api } from '../../../lib/matrix_api';
import { Navbar } from '@/components/Navbar';

interface TimelineEvent {
    event_id: string;
    timestamp: string;
    event_type: string;
    source_module: string;
    description: string;
    vulnerability_id?: number;
}

interface Artifact {
    artifact_evidence_id: string;
    name: string;
    artifact_type: string;
    sha256_hash: string;
    collection_time: string;
    metadata?: any;
    raw_data?: string;
}

interface ForensicSummary {
    evidence_id: string;
    integrity_status: string;
    scan_hash: string;
    environment_metadata: any;
    hash_manifest: Record<string, string>;
    created_at: string;
}

interface DeepReport {
    header: {
        evidence_id: string;
        target: string;
        status: string;
        generated_at: string;
        integrity_hash: string;
    };
    executive_summary: {
        total_findings: number;
        critical_issues: number;
        high_issues: number;
        risk_posture: string;
        summary_statement: string;
    };
    vulnerability_landscape: {
        severity_distribution: Record<string, number>;
        key_findings: any[];
    };
    compliance_check: {
        owasp_top_10_coverage: string[];
        frameworks: string[];
    };
    evidence_integrity: {
        status: string;
        artifact_count: number;
        timeline_events: number;
    };
}

export default function ForensicDetailPage() {
    const { id } = useParams();
    const apiBase = process.env.NEXT_PUBLIC_API_URL || '';
    const apiPath = (path: string) => `${apiBase}${path}`;
    const [activeTab, setActiveTab] = useState<'timeline' | 'artifacts' | 'integrity' | 'report'>('timeline');
    const [selectedArtifact, setSelectedArtifact] = useState<any | null>(null);
    const [summary, setSummary] = useState<ForensicSummary | null>(null);
    const [deepReport, setDeepReport] = useState<DeepReport | null>(null);
    const [events, setEvents] = useState<TimelineEvent[]>([]);
    const [artifacts, setArtifacts] = useState<Artifact[]>([]);
    const [loading, setLoading] = useState(true);
    const [selfHealing, setSelfHealing] = useState<string | null>(null); // artifact_id if healing
    const [reportingIssue, setReportingIssue] = useState<string | null>(null); // artifact_id if reporting
    const [healingResult, setHealingResult] = useState<any>(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [sumRes, timeRes, artRes, reportRes] = await Promise.all([
                    fetch(apiPath(`/api/forensics/${id}/`)),
                    fetch(apiPath(`/api/forensics/${id}/timeline/`)),
                    fetch(apiPath(`/api/forensics/${id}/artifacts/`)),
                    fetch(apiPath(`/api/forensics/${id}/report/`))
                ]);

                if (sumRes.ok) setSummary(await sumRes.json());
                if (timeRes.ok) setEvents(await timeRes.json());
                if (artRes.ok) setArtifacts(await artRes.json());
                if (reportRes.ok) setDeepReport(await reportRes.json());
            } catch (error) {
                console.error('Failed to fetch forensic data:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [id]);

    const handleDownload = (url: string) => {
        const link = document.createElement('a');
        link.href = apiPath(url);
        link.setAttribute('download', '');
        document.body.appendChild(link);
        link.click();
        link.remove();
    };

    const handleDownloadBundle = () => {
        handleDownload(`/api/forensics/${id}/export/bundle/`);
    };

    const handleDownloadArtifact = (artId: string) => {
        handleDownload(`/api/forensics/${id}/artifacts/${artId}/download/`);
    };

    const handleReportIssue = async (artId: string) => {
        setReportingIssue(artId);
        try {
            const scanIdStr = typeof id === 'string' ? id : (Array.isArray(id) ? id[0] : '');
            const data = await api.reportIssue(scanIdStr, artId);

            // Update artifact status in local state to avoid full re-fetch
            setArtifacts(prev => prev.map(art =>
                art.artifact_evidence_id === artId
                    ? { ...art, metadata: { ...art.metadata, status: 'reported', issue_url: data.issue_url, issue_number: data.issue_number } }
                    : art
            ));

            if (selectedArtifact?.artifact_evidence_id === artId) {
                setSelectedArtifact({
                    ...selectedArtifact,
                    metadata: { ...selectedArtifact.metadata, status: 'reported', issue_url: data.issue_url, issue_number: data.issue_number }
                });
            }
        } catch (error: any) {
            console.error('Report issue error:', error);
            alert(`Reporting failed: ${error.message || 'Unknown error'}`);
        } finally {
            setReportingIssue(null);
        }
    };

    const handleSelfHeal = async (artId: string) => {
        setSelfHealing(artId);
        setHealingResult(null);
        try {
            // Use the API singleton to get automatic CSRF protection
            const scanIdStr = typeof id === 'string' ? id : (Array.isArray(id) ? id[0] : '');
            const data = await api.selfHealArtifact(scanIdStr, artId);
            setHealingResult(data);

            // Update artifact status to fixed
            setArtifacts(prev => prev.map(art =>
                art.artifact_evidence_id === artId
                    ? { ...art, metadata: { ...art.metadata, status: 'fixed', pr_url: data.pr_url } }
                    : art
            ));

            if (selectedArtifact?.artifact_evidence_id === artId) {
                setSelectedArtifact({
                    ...selectedArtifact,
                    metadata: { ...selectedArtifact.metadata, status: 'fixed', pr_url: data.pr_url }
                });
            }
        } catch (error: any) {
            console.error('Self-healing error:', error);
            alert(`Self-healing failed: ${error.message || 'Unknown error'}`);
        } finally {
            setSelfHealing(null);
        }
    };

    // Helper function to parse and format event descriptions
    const formatEventDescription = (description: string): string => {
        if (!description) return '';

        try {
            // Check if description is JSON
            if (description.trim().startsWith('{')) {
                const parsed = JSON.parse(description);

                // Extract the actual description from common JSON structures
                if (parsed.description) {
                    return parsed.description;
                }
                if (parsed.title) {
                    return parsed.title;
                }
                if (parsed.reasoning) {
                    return parsed.reasoning;
                }

                // If it's a vulnerability object, format it nicely
                if (parsed.file && parsed.type && parsed.severity) {
                    return `${parsed.severity} ${parsed.type} in ${parsed.file}${parsed.line ? ` at line ${parsed.line}` : ''}`;
                }
            }
        } catch (e) {
            // If parsing fails, return the original description
        }

        return description;
    };

    if (loading) return (
        <div className="min-h-screen bg-warm-50/30 flex items-center justify-center">
            <div className="text-center">
                <div className="w-16 h-16 border-4 border-accent-primary/20 border-t-accent-primary rounded-full animate-spin mx-auto mb-4" />
                <p className="text-text-muted font-medium">Reconstructing Timeline...</p>
            </div>
        </div>
    );

    return (
        <div className="min-h-screen bg-warm-50/30">
            <Navbar />

            <main className="max-w-7xl mx-auto px-6 py-8">
                {/* Breadcrumbs */}
                <Link href="/forensics" className="inline-flex items-center gap-2 text-text-muted hover:text-accent-primary transition-colors mb-8 font-medium">
                    <ArrowLeft className="w-4 h-4" /> Back to Records
                </Link>

                {/* Top Summary Bar */}
                <div className="glass-card p-8 mb-8 relative overflow-hidden">
                    <div className="absolute top-0 right-0 p-8 opacity-10">
                        <Shield className="w-32 h-32 text-accent-primary" />
                    </div>

                    <div className="relative z-10">
                        <div className="flex flex-wrap items-center gap-4 mb-6">
                            <h1 className="text-3xl font-serif font-bold text-text-primary">
                                Evidence: <span className="text-accent-primary font-mono">{summary?.evidence_id}</span>
                            </h1>
                            <span className="px-3 py-1 rounded-full bg-green-100 text-green-700 text-xs font-bold uppercase tracking-wider border border-green-200">
                                {summary?.integrity_status}
                            </span>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-lg bg-warm-100 flex items-center justify-center text-text-muted">
                                    <Clock className="w-5 h-5" />
                                </div>
                                <div>
                                    <div className="text-[10px] text-text-muted font-bold uppercase tracking-widest">Case Opened</div>
                                    <div className="text-sm font-semibold text-text-primary">{summary ? new Date(summary.created_at).toLocaleString() : 'N/A'}</div>
                                </div>
                            </div>
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-lg bg-warm-100 flex items-center justify-center text-text-muted">
                                    <Fingerprint className="w-5 h-5" />
                                </div>
                                <div className="max-w-[150px]">
                                    <div className="text-[10px] text-text-muted font-bold uppercase tracking-widest">Global Hash</div>
                                    <div className="text-xs font-mono font-medium truncate text-text-primary">{summary?.scan_hash}</div>
                                </div>
                            </div>
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-lg bg-warm-100 flex items-center justify-center text-text-muted">
                                    <Monitor className="w-5 h-5" />
                                </div>
                                <div>
                                    <div className="text-[10px] text-text-muted font-bold uppercase tracking-widest">Source OS</div>
                                    <div className="text-sm font-semibold text-text-primary">{summary?.environment_metadata?.os || 'Linux'}</div>
                                </div>
                            </div>
                            <div className="flex items-center gap-3">
                                <button
                                    onClick={handleDownloadBundle}
                                    className="w-full py-3 rounded-xl bg-accent-primary text-white font-bold text-sm shadow-lg hover:shadow-xl transition-all flex items-center justify-center gap-2"
                                >
                                    <Download className="w-4 h-4" /> Export Bundle
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Tabs */}
                <div className="flex items-center gap-2 bg-warm-100/50 p-1 rounded-2xl w-fit mb-8 border border-warm-200">
                    {[
                        { id: 'timeline', label: 'Event Timeline', icon: Activity },
                        { id: 'report', label: 'Forensic Report', icon: Shield },
                        { id: 'artifacts', label: 'Collected Artifacts', icon: Box },
                        { id: 'integrity', label: 'Hash Manifest', icon: Hash }
                    ].map((tab) => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id as any)}
                            className={`px-6 py-2.5 rounded-xl text-sm font-bold flex items-center gap-2 transition-all ${activeTab === tab.id
                                ? 'bg-white text-accent-primary shadow-sm border border-warm-200'
                                : 'text-text-muted hover:text-text-primary'
                                }`}
                        >
                            <tab.icon className="w-4 h-4" />
                            {tab.label}
                        </button>
                    ))}
                </div>

                {/* Tab Content */}
                <AnimatePresence mode="wait">
                    {activeTab === 'report' && deepReport && (
                        <motion.div
                            key="report"
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -10 }}
                            className="space-y-8"
                        >
                            {/* Executive Summary Card */}
                            <div className="glass-card overflow-hidden">
                                <div className="bg-accent-primary p-6 text-white">
                                    <div className="flex items-center justify-between mb-4">
                                        <h2 className="text-xl font-bold flex items-center gap-2">
                                            <Shield className="w-5 h-5" /> Executive Forensic Summary
                                        </h2>
                                        <span className={`px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-widest ${deepReport.executive_summary.risk_posture === 'CRITICAL' ? 'bg-white text-red-600' :
                                            deepReport.executive_summary.risk_posture === 'HIGH' ? 'bg-white text-orange-600' :
                                                'bg-white text-green-600'
                                            }`}>
                                            Risk Posture: {deepReport.executive_summary.risk_posture}
                                        </span>
                                    </div>
                                    <p className="text-white/90 text-sm leading-relaxed max-w-3xl font-medium">
                                        {deepReport.executive_summary.summary_statement}
                                    </p>
                                </div>
                                <div className="grid grid-cols-1 md:grid-cols-3 divide-x divide-warm-100 bg-white">
                                    <div className="p-6 text-center">
                                        <div className="text-3xl font-bold text-text-primary mb-1">{deepReport.executive_summary.total_findings}</div>
                                        <div className="text-[10px] text-text-muted font-bold uppercase tracking-widest">Total Findings</div>
                                    </div>
                                    <div className="p-6 text-center">
                                        <div className="text-3xl font-bold text-red-600 mb-1">{deepReport.executive_summary.critical_issues}</div>
                                        <div className="text-[10px] text-text-muted font-bold uppercase tracking-widest">Critical Risks</div>
                                    </div>
                                    <div className="p-6 text-center">
                                        <div className="text-3xl font-bold text-accent-primary mb-1">{deepReport.evidence_integrity.artifact_count}</div>
                                        <div className="text-[10px] text-text-muted font-bold uppercase tracking-widest">Evidence Artifacts</div>
                                    </div>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                                {/* Key Findings */}
                                <div className="space-y-4">
                                    <h3 className="text-lg font-serif font-bold text-text-primary flex items-center gap-2">
                                        <AlertTriangle className="w-5 h-5 text-accent-primary" /> Key Security Observations
                                    </h3>
                                    <div className="space-y-4">
                                        {deepReport.vulnerability_landscape.key_findings.map((finding) => (
                                            <div key={finding.id} className="glass-card p-5 border-l-4 border-l-accent-primary">
                                                <div className="flex items-center justify-between mb-2">
                                                    <h4 className="font-bold text-text-primary">{finding.title}</h4>
                                                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${finding.severity === 'CRITICAL' ? 'bg-red-100 text-red-700' :
                                                        finding.severity === 'HIGH' ? 'bg-orange-100 text-orange-700' :
                                                            'bg-blue-100 text-blue-700'
                                                        }`}>
                                                        {finding.severity}
                                                    </span>
                                                </div>
                                                <p className="text-sm text-text-muted mb-3 line-clamp-2">{finding.root_cause}</p>
                                                <div className="flex items-center gap-4">
                                                    <span className="text-[10px] font-bold text-text-muted uppercase tracking-widest">OWASP: {finding.owasp}</span>
                                                    <span className="text-[10px] font-bold text-text-muted uppercase tracking-widest">CWE: {finding.cwe}</span>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                {/* Compliance & Governance */}
                                <div className="space-y-6">
                                    <div className="space-y-4">
                                        <h3 className="text-lg font-serif font-bold text-text-primary flex items-center gap-2">
                                            <CheckCircle className="w-5 h-5 text-green-600" /> Compliance Frameworks
                                        </h3>
                                        <div className="glass-card p-6 bg-blue-50/30 border-blue-100">
                                            <div className="flex flex-wrap gap-2 mb-6">
                                                {deepReport.compliance_check.frameworks.map(fw => (
                                                    <span key={fw} className="px-3 py-1 bg-blue-100 text-blue-700 rounded-lg text-xs font-bold uppercase">
                                                        {fw}
                                                    </span>
                                                ))}
                                            </div>
                                            <h4 className="text-xs font-bold text-text-muted uppercase tracking-widest mb-4">Coverage Analysis (OWASP Top 10)</h4>
                                            <div className="space-y-2">
                                                {deepReport.compliance_check.owasp_top_10_coverage.map(cat => (
                                                    <div key={cat} className="flex items-center gap-3 text-sm text-text-primary font-medium py-2 border-b border-blue-100/50 last:border-0">
                                                        <div className="w-2 h-2 rounded-full bg-blue-500" />
                                                        {cat}
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    </div>

                                    <div className="space-y-4">
                                        <h3 className="text-lg font-serif font-bold text-text-primary flex items-center gap-2">
                                            <Fingerprint className="w-5 h-5 text-text-muted" /> Integrity Audit
                                        </h3>
                                        <div className="glass-card p-6 bg-warm-100/30">
                                            <div className="flex justify-between items-center mb-4">
                                                <div className="text-sm font-bold text-text-primary">Session Hash Integrity</div>
                                                <span className="px-2 py-0.5 bg-green-100 text-green-700 text-[10px] font-bold rounded uppercase tracking-widest">VERIFIED</span>
                                            </div>
                                            <code className="text-[10px] font-mono break-all text-text-muted block p-3 bg-white rounded-xl border border-warm-200">
                                                SHA-256: {deepReport.header.integrity_hash}
                                            </code>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </motion.div>
                    )}
                    {activeTab === 'timeline' && (
                        <motion.div
                            key="timeline"
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -10 }}
                            className="space-y-4"
                        >
                            <div className="relative pl-8 border-l-2 border-dashed border-warm-300 ml-4 py-4 space-y-12">
                                {events.map((event, idx) => (
                                    <div key={event.event_id} className="relative group">
                                        {/* Tick Mark */}
                                        <div className="absolute -left-[41px] top-0 w-5 h-5 rounded-full bg-white border-4 border-accent-primary z-10 group-hover:scale-125 transition-transform" />

                                        <div className="glass-card p-6 inline-block min-w-[300px] max-w-2xl">
                                            <div className="flex items-center justify-between gap-4 mb-2">
                                                <span className="text-[10px] font-mono text-accent-primary bg-accent-primary/5 px-2 py-0.5 rounded uppercase font-bold">
                                                    {event.event_type}
                                                </span>
                                                <span className="text-xs text-text-muted font-medium">
                                                    {new Date(event.timestamp).toLocaleTimeString()}
                                                </span>
                                            </div>
                                            <h4 className="text-base font-bold text-text-primary mb-2">{formatEventDescription(event.description)}</h4>
                                            <div className="flex items-center gap-4 mt-4 pt-4 border-t border-warm-100">
                                                <div className="flex items-center gap-1.5 text-[10px] text-text-muted font-bold uppercase">
                                                    <Cpu className="w-3 h-3" />
                                                    {event.source_module}
                                                </div>
                                                <div className="flex items-center gap-1.5 text-[10px] text-text-muted font-bold uppercase">
                                                    <Hash className="w-3 h-3" />
                                                    {event.event_id}
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </motion.div>
                    )}

                    {activeTab === 'artifacts' && (
                        <motion.div
                            key="artifacts"
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -10 }}
                            className="grid grid-cols-1 md:grid-cols-2 gap-6"
                        >
                            {artifacts.length === 0 ? (
                                <div className="col-span-2 glass-card p-12 text-center text-text-muted">
                                    No artifacts were collected during this session.
                                </div>
                            ) : (
                                artifacts.map((art) => (
                                    <div key={art.artifact_evidence_id} className="glass-card p-6 flex items-start gap-4 group">
                                        <div className="w-12 h-12 rounded-xl bg-accent-primary/5 flex items-center justify-center text-accent-primary group-hover:bg-accent-primary group-hover:text-white transition-colors">
                                            <FileCode className="w-6 h-6" />
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <h4 className="text-lg font-bold text-text-primary mb-1 truncate">{art.name}</h4>
                                            <div className="flex items-center gap-3 text-xs text-text-muted mb-4 uppercase font-bold tracking-wider">
                                                <span>{art.artifact_type}</span>
                                                <span className="w-1 h-1 rounded-full bg-warm-300" />
                                                <span>{new Date(art.collection_time).toLocaleDateString()}</span>
                                            </div>
                                            <div className="bg-warm-100/50 p-2 rounded-lg flex items-center justify-between gap-3">
                                                <code className="text-[10px] font-mono truncate text-text-secondary">{art.sha256_hash}</code>
                                                <div className="flex items-center gap-1">
                                                    <button
                                                        onClick={() => setSelectedArtifact(art)}
                                                        className="p-1 hover:text-accent-primary transition-colors"
                                                        title="View Details"
                                                    >
                                                        <Eye className="w-4 h-4" />
                                                    </button>
                                                    <button
                                                        onClick={() => handleDownloadArtifact(art.artifact_evidence_id)}
                                                        className="p-1 hover:text-accent-primary transition-colors"
                                                        title="Download"
                                                    >
                                                        <Download className="w-4 h-4" />
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                ))
                            )}
                        </motion.div>
                    )}

                    {activeTab === 'integrity' && (
                        <motion.div
                            key="integrity"
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -10 }}
                            className="glass-card overflow-hidden"
                        >
                            <div className="bg-text-primary p-4 flex items-center justify-between">
                                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                                    <Fingerprint className="w-4 h-4" /> SHA-256 Hash Manifest
                                </h3>
                                <div className="text-[10px] font-mono text-white/50">READ-ONLY AUDIT LOG</div>
                            </div>
                            <table className="w-full text-left border-collapse">
                                <thead>
                                    <tr className="border-b border-warm-200">
                                        <th className="px-6 py-4 text-[10px] font-bold text-text-muted uppercase tracking-wider">Evidence ID</th>
                                        <th className="px-6 py-4 text-[10px] font-bold text-text-muted uppercase tracking-wider">SHA-256 Cryptographic Signature</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-warm-100">
                                    {summary?.hash_manifest && Object.entries(summary.hash_manifest).map(([key, value]) => (
                                        <tr key={key} className="hover:bg-warm-50/50 transition-colors">
                                            <td className="px-6 py-4">
                                                <span className="text-sm font-mono font-bold text-text-primary">{key}</span>
                                            </td>
                                            <td className="px-6 py-4">
                                                <span className="text-xs font-mono text-text-muted break-all">{value}</span>
                                            </td>
                                        </tr>
                                    ))}
                                    {(!summary?.hash_manifest || Object.keys(summary.hash_manifest).length === 0) && (
                                        <tr>
                                            <td colSpan={2} className="px-6 py-8 text-center text-text-muted italic">No manifest entries recorded for this case.</td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </motion.div>
                    )}
                </AnimatePresence>
            </main>
            {/* Artifact Detail Modal */}
            <AnimatePresence>
                {selectedArtifact && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm"
                        onClick={() => {
                            setSelectedArtifact(null);
                            setHealingResult(null);
                        }}
                    >
                        <motion.div
                            initial={{ scale: 0.95, opacity: 0 }}
                            animate={{ scale: 1, opacity: 1 }}
                            exit={{ scale: 0.95, opacity: 0 }}
                            className="bg-white rounded-3xl shadow-2xl w-full max-w-4xl max-h-[85vh] overflow-hidden flex flex-col"
                            onClick={(e: React.MouseEvent) => e.stopPropagation()}
                        >
                            {/* Modal Header */}
                            <div className="p-6 border-b border-warm-100 flex items-center justify-between bg-warm-50/50">
                                <div>
                                    <h3 className="text-xl font-bold text-text-primary">{selectedArtifact.name}</h3>
                                    <p className="text-sm text-text-muted mt-1 uppercase tracking-wider font-bold">
                                        {selectedArtifact.artifact_type} • {selectedArtifact.artifact_evidence_id}
                                    </p>
                                </div>
                                <button
                                    onClick={() => {
                                        setSelectedArtifact(null);
                                        setHealingResult(null);
                                    }}
                                    className="p-2 hover:bg-warm-200 rounded-full transition-colors"
                                >
                                    <X className="w-6 h-6 text-text-secondary" />
                                </button>
                            </div>

                            {/* Modal Body */}
                            <div className="p-8 overflow-y-auto space-y-8 flex-1">
                                {/* AI Reasoning Section (If available) */}
                                {selectedArtifact.metadata?.ai_reasoning || selectedArtifact.metadata?.ai_analysis ? (
                                    <div className="space-y-6">
                                        <div className="space-y-3">
                                            <div className="flex items-center gap-2 text-accent-primary">
                                                <Cpu className="w-5 h-5" />
                                                <h4 className="text-lg font-bold">Forensic Evidence Analysis</h4>
                                            </div>
                                            <div className="bg-accent-primary/5 border border-accent-primary/10 rounded-2xl p-6 text-text-primary leading-relaxed whitespace-pre-wrap">
                                                {(() => {
                                                    const rawReasoning = selectedArtifact.metadata?.ai_reasoning || selectedArtifact.metadata?.ai_analysis;
                                                    if (!rawReasoning) return null;
                                                    try {
                                                        // Attempt to parse if it's a JSON string from SAST
                                                        const parsed = typeof rawReasoning === 'string' && rawReasoning.startsWith('{') ? JSON.parse(rawReasoning) : null;
                                                        if (parsed && (parsed.description || parsed.reasoning)) {
                                                            return parsed.description || parsed.reasoning;
                                                        }
                                                    } catch (e) {
                                                        // Fallback to raw string
                                                    }
                                                    return rawReasoning;
                                                })()}
                                            </div>
                                        </div>

                                        {/* New High-Level Forensic Sections */}
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                            {/* Root Cause & Business Impact */}
                                            <div className="space-y-4">
                                                {selectedArtifact.metadata?.root_cause && selectedArtifact.metadata.root_cause.trim() !== "" && (
                                                    <div className="p-5 bg-warm-50 rounded-2xl border border-warm-200">
                                                        <h5 className="text-xs font-bold text-text-muted uppercase tracking-widest mb-2 flex items-center gap-2">
                                                            <Activity className="w-3.5 h-3.5" /> Root Cause Analysis
                                                        </h5>
                                                        <p className="text-sm text-text-primary leading-relaxed font-medium">
                                                            {selectedArtifact.metadata.root_cause}
                                                        </p>
                                                    </div>
                                                )}
                                                {selectedArtifact.metadata?.business_impact && selectedArtifact.metadata.business_impact.trim() !== "" && (
                                                    <div className="p-5 bg-red-50/50 rounded-2xl border border-red-100">
                                                        <h5 className="text-xs font-bold text-red-600 uppercase tracking-widest mb-2 flex items-center gap-2">
                                                            <AlertTriangle className="w-3.5 h-3.5" /> Business & Risk Impact
                                                        </h5>
                                                        <p className="text-sm text-text-primary leading-relaxed font-medium">
                                                            {selectedArtifact.metadata.business_impact}
                                                        </p>
                                                    </div>
                                                )}
                                            </div>

                                            {/* Compliance & Governance */}
                                            <div className="space-y-4">
                                                {selectedArtifact.metadata?.compliance_mapping && Object.keys(selectedArtifact.metadata.compliance_mapping).length > 0 && (
                                                    <div className="p-5 bg-blue-50/50 rounded-2xl border border-blue-100 h-full">
                                                        <h5 className="text-xs font-bold text-blue-600 uppercase tracking-widest mb-3 flex items-center gap-2">
                                                            <Shield className="w-3.5 h-3.5" /> Compliance Framework Mapping
                                                        </h5>
                                                        <div className="space-y-2">
                                                            {Object.entries(selectedArtifact.metadata.compliance_mapping).map(([key, value]) => (
                                                                <div key={key} className="flex justify-between items-center text-xs py-1.5 border-b border-blue-100/50 last:border-0">
                                                                    <span className="text-blue-700 font-bold uppercase">{key}</span>
                                                                    <span className="font-mono text-blue-900 bg-white px-2 py-0.5 rounded shadow-sm border border-blue-100">{value as string}</span>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        </div>

                                        {/* Remediation Section */}
                                        {selectedArtifact.metadata?.remediation && (
                                            <div className="space-y-3">
                                                <div className="flex items-center gap-2 text-green-600">
                                                    <CheckCircle className="w-5 h-5" />
                                                    <h4 className="text-lg font-bold">Security Remediation Plan</h4>
                                                </div>
                                                <div className="bg-green-50/50 border border-green-100 rounded-2xl p-6 text-text-primary leading-relaxed">
                                                    <div className="text-sm font-medium mb-4">
                                                        {typeof selectedArtifact.metadata.remediation === 'string'
                                                            ? selectedArtifact.metadata.remediation
                                                            : selectedArtifact.metadata.remediation?.short_term}
                                                    </div>
                                                    {selectedArtifact.metadata.remediation?.long_term && (
                                                        <div className="mt-4 pt-4 border-t border-green-100">
                                                            <div className="text-[10px] font-bold text-green-700 uppercase mb-2 tracking-widest">Strategic Path Forward</div>
                                                            <div className="text-sm font-medium">{selectedArtifact.metadata.remediation.long_term}</div>
                                                        </div>
                                                    )}
                                                    {selectedArtifact.metadata.remediation_code && (
                                                        <div className="mt-4 bg-gray-900 rounded-xl p-4 overflow-x-auto">
                                                            <div className="text-[10px] font-bold text-gray-500 uppercase mb-2">Technical Implementation</div>
                                                            <pre className="text-xs font-mono text-gray-300">
                                                                <code>{selectedArtifact.metadata.remediation_code}</code>
                                                            </pre>
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                ) : null}

                                {/* Metadata Grid */}
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div className="space-y-3">
                                        <h4 className="text-sm font-bold text-text-muted uppercase tracking-wider flex items-center gap-2">
                                            <Info className="w-4 h-4" /> Evidence Context
                                        </h4>
                                        <div className="space-y-2">
                                            {selectedArtifact.metadata?.url && (
                                                <div className="flex justify-between text-sm py-2 border-b border-warm-100">
                                                    <span className="text-text-muted">Target URL</span>
                                                    <span className="font-mono text-text-primary truncate ml-4 font-bold">{selectedArtifact.metadata.url}</span>
                                                </div>
                                            )}
                                            {selectedArtifact.metadata?.severity && (
                                                <div className="flex justify-between text-sm py-2 border-b border-warm-100">
                                                    <span className="text-text-muted">Impact Severity</span>
                                                    <span className={`font-bold ${selectedArtifact.metadata.severity === 'CRITICAL' ? 'text-red-600' :
                                                        selectedArtifact.metadata.severity === 'HIGH' ? 'text-orange-600' :
                                                            'text-blue-600'
                                                        }`}>{selectedArtifact.metadata.severity}</span>
                                                </div>
                                            )}
                                            <div className="flex justify-between text-sm py-2 border-b border-warm-100">
                                                <span className="text-text-muted">Captured At</span>
                                                <span className="text-text-primary font-bold">
                                                    {new Date(selectedArtifact.collection_time).toLocaleString()}
                                                </span>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="space-y-3">
                                        <h4 className="text-sm font-bold text-text-muted uppercase tracking-wider flex items-center gap-2">
                                            <Shield className="w-4 h-4" /> Integrity Verification
                                        </h4>
                                        <div className="p-4 bg-warm-50 rounded-2xl border border-warm-200">
                                            <div className="flex items-center gap-2 text-green-600 mb-2">
                                                <CheckCircle className="w-4 h-4" />
                                                <span className="text-xs font-bold uppercase tracking-wide">Signature Valid</span>
                                            </div>
                                            <code className="text-[10px] break-all text-text-muted block font-mono">
                                                SHA-256: {selectedArtifact.sha256_hash}
                                            </code>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Modal Footer */}
                            <div className="p-6 bg-warm-50/50 border-t border-warm-100 flex flex-col gap-4">
                                {selectedArtifact.metadata?.status === 'reported' && (
                                    <div className="p-4 bg-indigo-50 border border-indigo-200 rounded-2xl flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            <div className="w-8 h-8 bg-indigo-100 rounded-full flex items-center justify-center text-indigo-600">
                                                <FileCode className="w-5 h-5" />
                                            </div>
                                            <div>
                                                <p className="text-sm font-bold text-indigo-800">Issue Reported to GitHub</p>
                                                <p className="text-xs text-indigo-600">Issue #{selectedArtifact.metadata.issue_number}</p>
                                            </div>
                                        </div>
                                        <a
                                            href={selectedArtifact.metadata.issue_url}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="px-4 py-2 bg-indigo-600 text-white text-xs font-bold rounded-lg hover:bg-indigo-700 transition-colors flex items-center gap-2"
                                        >
                                            View Issue <ExternalLink className="w-3 h-3" />
                                        </a>
                                    </div>
                                )}

                                {(healingResult || selectedArtifact.metadata?.status === 'fixed') && (
                                    <div className="p-4 bg-green-50 border border-green-200 rounded-2xl flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            <div className="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center text-green-600">
                                                <CheckCircle className="w-5 h-5" />
                                            </div>
                                            <div>
                                                <p className="text-sm font-bold text-green-800">Patch Generated & PR Opened!</p>
                                                <p className="text-xs text-green-600">Remediation successfully pushed.</p>
                                            </div>
                                        </div>
                                        <a
                                            href={healingResult?.pr_url || selectedArtifact.metadata?.pr_url}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="px-4 py-2 bg-green-600 text-white text-xs font-bold rounded-lg hover:bg-green-700 transition-colors flex items-center gap-2"
                                        >
                                            View Pull Request <ExternalLink className="w-3 h-3" />
                                        </a>
                                    </div>
                                )}

                                <div className="flex justify-end gap-3">
                                    {(selectedArtifact.metadata?.file_path && (selectedArtifact.metadata?.url?.includes('github.com') || selectedArtifact.metadata?.repository?.includes('github.com'))) && (
                                        <>
                                            {!selectedArtifact.metadata?.status && (
                                                <button
                                                    onClick={() => handleReportIssue(selectedArtifact.artifact_evidence_id)}
                                                    disabled={reportingIssue === selectedArtifact.artifact_evidence_id}
                                                    className="flex items-center gap-2 px-6 py-2.5 rounded-xl font-bold text-sm bg-indigo-600 text-white shadow-lg hover:shadow-xl active:scale-95 disabled:opacity-50 transition-all"
                                                >
                                                    {reportingIssue === selectedArtifact.artifact_evidence_id ? (
                                                        <>
                                                            <RefreshCw className="w-4 h-4 animate-spin" />
                                                            Reporting Issue...
                                                        </>
                                                    ) : (
                                                        <>
                                                            <Activity className="w-4 h-4" />
                                                            Report to GitHub Issue
                                                        </>
                                                    )}
                                                </button>
                                            )}

                                            {selectedArtifact.metadata?.status === 'reported' && !healingResult && (
                                                <button
                                                    onClick={() => handleSelfHeal(selectedArtifact.artifact_evidence_id)}
                                                    disabled={selfHealing === selectedArtifact.artifact_evidence_id}
                                                    className="flex items-center gap-2 px-6 py-2.5 rounded-xl font-bold text-sm bg-purple-600 text-white shadow-lg hover:shadow-xl active:scale-95 disabled:opacity-50 transition-all"
                                                >
                                                    {selfHealing === selectedArtifact.artifact_evidence_id ? (
                                                        <>
                                                            <RefreshCw className="w-4 h-4 animate-spin" />
                                                            AI Autopilot Patching...
                                                        </>
                                                    ) : (
                                                        <>
                                                            <Zap className="w-4 h-4" />
                                                            Approve & Apply AI Fix
                                                        </>
                                                    )}
                                                </button>
                                            )}

                                            {selectedArtifact.metadata?.status === 'fixed' && (
                                                <div className="flex items-center gap-2 px-6 py-2.5 rounded-xl font-bold text-sm bg-green-100 text-green-700">
                                                    <CheckCircle className="w-4 h-4" />
                                                    Fix Applied
                                                </div>
                                            )}
                                        </>
                                    )}
                                    <button
                                        onClick={() => handleDownloadArtifact(selectedArtifact.artifact_evidence_id)}
                                        className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-warm-100 text-text-primary font-bold text-sm hover:bg-warm-200 transition-all"
                                    >
                                        <Download className="w-4 h-4" /> Download Evidence Report
                                    </button>
                                </div>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
