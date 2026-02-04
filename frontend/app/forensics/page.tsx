'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
    ShieldCheck,
    History,
    FileSearch,
    Download,
    Activity,
    CheckCircle2,
    AlertTriangle,
    Fingerprint,
    Calendar,
    ArrowRight
} from 'lucide-react';
import Link from 'next/link';
import { Navbar } from '@/components/Navbar';

interface ForensicRecord {
    id: number;
    scan_id: number;
    evidence_id: string;
    integrity_status: 'VALID' | 'WARNING' | 'TAMPERED';
    is_tampered: boolean;
    scan_hash: string;
    created_at: string;
    updated_at: string;
}

export default function ForensicsPage() {
    const [records, setRecords] = useState<ForensicRecord[]>([]);
    const [loading, setLoading] = useState(true);
    const apiBase = process.env.NEXT_PUBLIC_API_URL || '';
    const apiPath = (path: string) => `${apiBase}${path}`;

    useEffect(() => {
        const fetchRecords = async () => {
            try {
                const response = await fetch(apiPath('/api/forensics/'));
                if (response.ok) {
                    const data = await response.json();
                    setRecords(data);
                }
            } catch (error) {
                console.error('Failed to fetch forensic records:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchRecords();
    }, []);

    return (
        <div className="min-h-screen bg-warm-50/30">
            <Navbar />

            <main className="max-w-7xl mx-auto px-6 py-12">
                {/* Header Section */}
                <section className="mb-12">
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="flex flex-col md:flex-row md:items-end justify-between gap-6"
                    >
                        <div>
                            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-accent-primary/10 text-accent-primary text-xs font-bold uppercase tracking-wider mb-4">
                                <ShieldCheck className="w-3.5 h-3.5" />
                                Immutable Evidence
                            </div>
                            <h1 className="text-4xl md:text-5xl font-serif font-medium text-text-primary mb-4">
                                Digital Forensics <span className="text-accent-primary">&</span> Evidence
                            </h1>
                            <p className="text-text-secondary max-w-2xl text-lg leading-relaxed">
                                Matrix captures cryptographically signed evidence for every scan.
                                Investigate timelines, verify integrity, and export court-ready forensic bundles.
                            </p>
                        </div>

                        <div className="flex gap-4">
                            <div className="glass-card px-6 py-4 flex items-center gap-4">
                                <div className="w-10 h-10 rounded-full bg-green-100 flex items-center justify-center text-green-600">
                                    <CheckCircle2 className="w-6 h-6" />
                                </div>
                                <div>
                                    <div className="text-xs text-text-muted font-medium uppercase">Integrity</div>
                                    <div className="text-xl font-bold text-text-primary">100% Valid</div>
                                </div>
                            </div>
                        </div>
                    </motion.div>
                </section>

                {/* Action Grid */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                    {/* Main List */}
                    <div className="lg:col-span-2 space-y-4">
                        <h2 className="text-xl font-serif font-medium text-text-primary flex items-center gap-2 mb-6">
                            <History className="w-5 h-5 text-accent-primary" />
                            Evidence Repository
                        </h2>

                        {loading ? (
                            <div className="space-y-4">
                                {[1, 2, 3].map((i) => (
                                    <div key={i} className="h-32 w-full animate-pulse bg-white/50 rounded-2xl border border-warm-200" />
                                ))}
                            </div>
                        ) : records.length === 0 ? (
                            <div className="glass-card p-12 text-center">
                                <div className="w-16 h-16 bg-warm-100 rounded-full flex items-center justify-center mx-auto mb-4 text-text-muted">
                                    <FileSearch className="w-8 h-8" />
                                </div>
                                <h3 className="text-lg font-medium text-text-primary mb-2">No evidence collected yet</h3>
                                <p className="text-text-muted max-w-xs mx-auto mb-6">
                                    Start a scan to automatically generate immutable forensic records.
                                </p>
                                <Link href="/scan" className="btn-primary inline-flex items-center gap-2">
                                    Launch Scan <ArrowRight className="w-4 h-4" />
                                </Link>
                            </div>
                        ) : (
                            records.map((record, index) => (
                                <motion.div
                                    key={record.id}
                                    initial={{ opacity: 0, x: -20 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    transition={{ delay: index * 0.1 }}
                                    className="glass-card p-6 hover:shadow-card transition-all group"
                                >
                                    <div className="flex flex-col md:flex-row justify-between gap-6">
                                        <div className="flex gap-5">
                                            <div className="w-12 h-12 rounded-xl bg-accent-primary/5 flex items-center justify-center text-accent-primary group-hover:bg-accent-primary group-hover:text-white transition-colors">
                                                <Fingerprint className="w-6 h-6" />
                                            </div>
                                            <div>
                                                <div className="flex items-center gap-3 mb-1">
                                                    <span className="text-lg font-bold text-text-primary font-mono tracking-tight">
                                                        {record.evidence_id}
                                                    </span>
                                                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${record.integrity_status === 'VALID'
                                                        ? 'bg-green-100 text-green-700'
                                                        : 'bg-red-100 text-red-700'
                                                        }`}>
                                                        {record.integrity_status}
                                                    </span>
                                                </div>
                                                <div className="flex items-center gap-4 text-sm text-text-muted">
                                                    <span className="flex items-center gap-1.5">
                                                        <Calendar className="w-3.5 h-3.5" />
                                                        {new Date(record.created_at).toLocaleDateString()}
                                                    </span>
                                                    <span className="flex items-center gap-1.5">
                                                        <Activity className="w-3.5 h-3.5" />
                                                        Scan ID: #{record.scan_id}
                                                    </span>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="flex items-center gap-3">
                                            <Link
                                                href={`/forensics/${record.scan_id}`}
                                                className="px-5 py-2.5 rounded-xl bg-warm-100/50 hover:bg-accent-primary/10 text-text-primary hover:text-accent-primary font-bold text-sm transition-all flex items-center gap-2"
                                            >
                                                Investigate <ArrowRight className="w-4 h-4" />
                                            </Link>
                                        </div>
                                    </div>
                                </motion.div>
                            ))
                        )}
                    </div>

                    {/* Right Sidebar Info */}
                    <div className="space-y-6">
                        <div className="glass-card p-6 border-l-4 border-accent-primary">
                            <h3 className="text-lg font-serif font-medium text-text-primary mb-4 flex items-center gap-2">
                                <CheckCircle2 className="w-5 h-5 text-accent-primary" />
                                Chain of Custody
                            </h3>
                            <p className="text-sm text-text-muted leading-relaxed mb-4">
                                Every byte collected is hashed with SHA-256 and stored in an append-only timeline.
                                Any modification to the data will invalidate the cryptographic manifest.
                            </p>
                            <ul className="space-y-3">
                                <li className="flex items-start gap-3 text-sm text-text-primary font-medium">
                                    <div className="w-1.5 h-1.5 rounded-full bg-accent-primary mt-1.5" />
                                    Cryptographic Hashing
                                </li>
                                <li className="flex items-start gap-3 text-sm text-text-primary font-medium">
                                    <div className="w-1.5 h-1.5 rounded-full bg-accent-primary mt-1.5" />
                                    Immutable Event Logs
                                </li>
                                <li className="flex items-start gap-3 text-sm text-text-primary font-medium">
                                    <div className="w-1.5 h-1.5 rounded-full bg-accent-primary mt-1.5" />
                                    Hardware-aware Metadata
                                </li>
                            </ul>
                        </div>

                        <div className="glass-card p-6 bg-accent-primary/5 border-accent-primary/10">
                            <h3 className="text-lg font-serif font-medium text-text-primary mb-4 flex items-center gap-2">
                                <Download className="w-5 h-5 text-accent-primary" />
                                Forensic Exports
                            </h3>
                            <p className="text-sm text-text-muted mb-6">
                                Download zip bundles containing raw evidence, timelines, and hash manifests.
                            </p>
                            <button disabled className="w-full py-3 rounded-xl bg-warm-200 text-text-disabled font-bold text-sm flex items-center justify-center gap-2 cursor-not-allowed">
                                Bulk Export <Download className="w-4 h-4" />
                            </button>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
}
