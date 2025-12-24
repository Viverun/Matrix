'use client';

import { useState, useEffect } from 'react';
import {
    TrendingUp, TrendingDown, Activity, Shield, AlertTriangle,
    BarChart3, PieChart, Calendar, ArrowUpRight, ArrowDownRight,
    Target, Zap, CheckCircle, Clock, FileSearch, Lightbulb, ArrowLeft
} from 'lucide-react';
import Link from 'next/link';
import { useAuth } from '../../context/AuthContext';
import { ProtectedRoute } from '../../components/ProtectedRoute';
import { Navbar } from '../../components/Navbar';
import { api, Scan } from '../../lib/api';

export default function AnalyticsPage() {
    const { user } = useAuth();
    const [scans, setScans] = useState<Scan[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [timeRange, setTimeRange] = useState('30d');

    useEffect(() => {
        const fetchData = async () => {
            setIsLoading(true);
            try {
                const data = await api.getScans(1, 50);
                setScans(data.items);
            } catch (err) {
                console.error('Failed to fetch analytics data');
            } finally {
                setIsLoading(false);
            }
        };
        fetchData();
    }, []);

    // Calculate aggregated stats
    const stats = scans.reduce((acc, scan) => ({
        totalScans: scans.length,
        totalVulnerabilities: acc.totalVulnerabilities + (scan.total_vulnerabilities || 0),
        criticalCount: acc.criticalCount + (scan.critical_count || 0),
        highCount: acc.highCount + (scan.high_count || 0),
        mediumCount: acc.mediumCount + (scan.medium_count || 0),
        lowCount: acc.lowCount + (scan.low_count || 0),
    }), {
        totalScans: 0,
        totalVulnerabilities: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
    });

    // Calculate security score based on vulnerabilities
    // Formula: Start at 100, deduct points based on severity
    // Critical: -10 points each, High: -5 points, Medium: -2 points, Low: -1 point (capped at min 0)
    const baseScore = 100;
    const criticalPenalty = stats.criticalCount * 10;
    const highPenalty = stats.highCount * 5;
    const mediumPenalty = stats.mediumCount * 2;
    const lowPenalty = stats.lowCount * 1;
    const securityScore = Math.max(0, baseScore - criticalPenalty - highPenalty - mediumPenalty - lowPenalty);
    const scoreColor = securityScore >= 70 ? 'text-green-600' : securityScore >= 40 ? 'text-yellow-600' : 'text-red-600';

    const insights = [
        {
            title: 'Most Common Vulnerability',
            value: stats.criticalCount > 0 ? 'Critical Issues' : stats.highCount > 0 ? 'High Severity' : 'Low Risk',
            description: `${stats.totalVulnerabilities} total vulnerabilities detected across ${stats.totalScans} scans.`,
            trend: stats.criticalCount === 0 ? 'down' : 'up',
            change: stats.criticalCount === 0 ? 'Safe' : `${stats.criticalCount} Critical`,
            icon: AlertTriangle,
            color: stats.criticalCount > 0 ? 'text-red-600' : 'text-orange-600',
            bg: stats.criticalCount > 0 ? 'bg-red-500/10' : 'bg-orange-500/10'
        },
        {
            title: 'Total Scans',
            value: `${stats.totalScans}`,
            description: 'Total security audits completed in your account history.',
            trend: 'up',
            change: 'All Time',
            icon: Clock,
            color: 'text-blue-600',
            bg: 'bg-blue-500/10'
        },
        {
            title: 'Security Score',
            value: `${securityScore}/100`,
            description: securityScore >= 70 ? 'Your security posture is strong.' : securityScore >= 40 ? 'Some vulnerabilities need attention.' : 'Critical issues require immediate action.',
            trend: securityScore >= 70 ? 'up' : 'down',
            change: securityScore >= 70 ? 'Good' : securityScore >= 40 ? 'Fair' : 'Poor',
            icon: Shield,
            color: scoreColor,
            bg: securityScore >= 70 ? 'bg-green-500/10' : securityScore >= 40 ? 'bg-yellow-500/10' : 'bg-red-500/10'
        },
        {
            title: 'Critical Issues',
            value: `${stats.criticalCount}`,
            description: stats.criticalCount === 0 ? 'No critical vulnerabilities detected.' : 'Critical issues require immediate remediation.',
            trend: stats.criticalCount === 0 ? 'down' : 'up',
            change: stats.criticalCount === 0 ? 'Clear' : 'Action Required',
            icon: Zap,
            color: stats.criticalCount === 0 ? 'text-green-600' : 'text-red-600',
            bg: stats.criticalCount === 0 ? 'bg-green-500/10' : 'bg-red-500/10'
        }
    ];

    const keynotes = [
        {
            priority: 'high',
            title: 'SQL Injection patterns detected in API endpoints',
            recommendation: 'Implement parameterized queries across all database interactions.',
            affectedScans: 3
        },
        {
            priority: 'medium',
            title: 'Missing security headers on 12 endpoints',
            recommendation: 'Add Content-Security-Policy and X-Frame-Options headers.',
            affectedScans: 5
        },
        {
            priority: 'low',
            title: 'Outdated dependencies in 2 repositories',
            recommendation: 'Update npm packages to latest stable versions.',
            affectedScans: 2
        }
    ];

    return (
        <ProtectedRoute>
            <div className="min-h-screen bg-bg-primary pattern-bg">
                <Navbar />

                <main className="max-w-7xl mx-auto px-6 py-12">
                    {/* Page Header */}
                    <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 mb-12">
                        <div className="animate-slide-up">
                            <Link href="/hub" className="inline-flex items-center gap-2 text-text-muted hover:text-accent-primary transition-colors mb-4">
                                <ArrowLeft className="w-4 h-4" />
                                Back to Hub
                            </Link>
                            <h2 className="text-4xl font-serif-display font-medium text-text-primary">
                                Past Records & Analytics
                            </h2>
                            <p className="text-text-secondary mt-2 text-lg">
                                Deep insights, trend analysis, and security intelligence from your audit history.
                            </p>
                        </div>

                        {/* Time Range Selector */}
                        <div className="flex items-center gap-2 bg-warm-50 rounded-xl p-1 border border-warm-200">
                            {['7d', '30d', '90d', 'All'].map((range) => (
                                <button
                                    key={range}
                                    onClick={() => setTimeRange(range)}
                                    className={`px-4 py-2 rounded-lg text-sm font-bold uppercase tracking-widest transition-all ${timeRange === range
                                        ? 'bg-accent-primary text-white shadow-lg'
                                        : 'text-text-muted hover:text-accent-primary'
                                        }`}
                                >
                                    {range}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Key Insights Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
                        {insights.map((insight, i) => (
                            <div key={i} className="glass-card p-6 hover:shadow-xl transition-all group">
                                <div className="flex items-start justify-between mb-4">
                                    <div className={`w-12 h-12 ${insight.bg} rounded-xl flex items-center justify-center`}>
                                        <insight.icon className={`w-6 h-6 ${insight.color}`} />
                                    </div>
                                    <div className={`flex items-center gap-1 text-sm font-bold ${insight.trend === 'up' ? 'text-green-600' : 'text-blue-600'
                                        }`}>
                                        {insight.trend === 'up' ? (
                                            <ArrowUpRight className="w-4 h-4" />
                                        ) : (
                                            <ArrowDownRight className="w-4 h-4" />
                                        )}
                                        {insight.change}
                                    </div>
                                </div>
                                <div className="text-2xl font-serif-display font-medium text-text-primary mb-1">
                                    {insight.value}
                                </div>
                                <div className="text-xs font-bold uppercase tracking-widest text-text-muted mb-2">
                                    {insight.title}
                                </div>
                                <p className="text-sm text-text-secondary leading-relaxed">
                                    {insight.description}
                                </p>
                            </div>
                        ))}
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
                        {/* Vulnerability Distribution */}
                        <div className="lg:col-span-2 glass-card p-8">
                            <h3 className="text-2xl font-serif-display font-medium text-text-primary flex items-center gap-3 mb-8">
                                <div className="w-2 h-8 bg-accent-primary rounded-full" />
                                Vulnerability Distribution
                            </h3>

                            <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mb-8">
                                <div className="text-center p-4 bg-red-500/5 rounded-xl border border-red-500/20">
                                    <div className="text-3xl font-serif-display font-medium text-red-600">{stats.criticalCount}</div>
                                    <div className="text-xs font-bold uppercase tracking-widest text-red-600 mt-1">Critical</div>
                                </div>
                                <div className="text-center p-4 bg-orange-500/5 rounded-xl border border-orange-500/20">
                                    <div className="text-3xl font-serif-display font-medium text-orange-600">{stats.highCount}</div>
                                    <div className="text-xs font-bold uppercase tracking-widest text-orange-600 mt-1">High</div>
                                </div>
                                <div className="text-center p-4 bg-yellow-500/5 rounded-xl border border-yellow-500/20">
                                    <div className="text-3xl font-serif-display font-medium text-yellow-600">{stats.mediumCount}</div>
                                    <div className="text-xs font-bold uppercase tracking-widest text-yellow-600 mt-1">Medium</div>
                                </div>
                                <div className="text-center p-4 bg-blue-500/5 rounded-xl border border-blue-500/20">
                                    <div className="text-3xl font-serif-display font-medium text-blue-600">{stats.lowCount}</div>
                                    <div className="text-xs font-bold uppercase tracking-widest text-blue-600 mt-1">Low</div>
                                </div>
                            </div>

                            {/* Visual Bar Chart */}
                            <div className="space-y-4">
                                {[
                                    { label: 'Critical', value: stats.criticalCount, max: stats.totalVulnerabilities || 1, color: 'bg-red-500' },
                                    { label: 'High', value: stats.highCount, max: stats.totalVulnerabilities || 1, color: 'bg-orange-500' },
                                    { label: 'Medium', value: stats.mediumCount, max: stats.totalVulnerabilities || 1, color: 'bg-yellow-500' },
                                    { label: 'Low', value: stats.lowCount, max: stats.totalVulnerabilities || 1, color: 'bg-blue-500' },
                                ].map((item, i) => (
                                    <div key={i} className="flex items-center gap-4">
                                        <div className="w-20 text-sm text-text-secondary font-medium">{item.label}</div>
                                        <div className="flex-1 h-3 bg-warm-100 rounded-full overflow-hidden">
                                            <div
                                                className={`h-full ${item.color} rounded-full transition-all duration-1000`}
                                                style={{ width: `${(item.value / item.max) * 100}%` }}
                                            />
                                        </div>
                                        <div className="w-12 text-right text-sm font-bold text-text-primary">{item.value}</div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Trend Analysis */}
                        <div className="glass-card p-8">
                            <h3 className="text-2xl font-serif-display font-medium text-text-primary flex items-center gap-3 mb-8">
                                <div className="w-2 h-8 bg-accent-gold rounded-full" />
                                Monthly Trend
                            </h3>

                            <div className="space-y-6">
                                {[
                                    { month: 'December', scans: 12, vulns: 45 },
                                    { month: 'November', scans: 8, vulns: 62 },
                                    { month: 'October', scans: 15, vulns: 38 },
                                    { month: 'September', scans: 6, vulns: 28 },
                                ].map((item, i) => (
                                    <div key={i} className="flex items-center justify-between py-3 border-b border-warm-100 last:border-0">
                                        <div>
                                            <div className="font-medium text-text-primary">{item.month}</div>
                                            <div className="text-xs text-text-muted">{item.scans} scans completed</div>
                                        </div>
                                        <div className="text-right">
                                            <div className="text-lg font-bold text-text-primary">{item.vulns}</div>
                                            <div className="text-xs text-text-muted">vulnerabilities</div>
                                        </div>
                                    </div>
                                ))}
                            </div>

                            <div className="mt-8 p-5 bg-accent-primary/5 rounded-2xl border border-accent-primary/10">
                                <div className="flex items-center gap-3 mb-3">
                                    <TrendingDown className="w-5 h-5 text-green-600" />
                                    <span className="font-medium text-text-primary">Positive Trend</span>
                                </div>
                                <p className="text-sm text-text-secondary leading-relaxed">
                                    Vulnerability count has decreased by <span className="text-green-600 font-bold">27%</span> compared to the previous quarter.
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Keynotes & Recommendations */}
                    <div className="glass-card p-8">
                        <h3 className="text-2xl font-serif-display font-medium text-text-primary flex items-center gap-3 mb-8">
                            <div className="w-2 h-8 bg-accent-gold rounded-full" />
                            <Lightbulb className="w-6 h-6 text-accent-gold" />
                            Key Recommendations
                        </h3>

                        <div className="space-y-6">
                            {keynotes.map((note, i) => (
                                <div
                                    key={i}
                                    className={`p-6 rounded-2xl border-l-4 ${note.priority === 'high'
                                        ? 'bg-red-500/5 border-l-red-500'
                                        : note.priority === 'medium'
                                            ? 'bg-orange-500/5 border-l-orange-500'
                                            : 'bg-blue-500/5 border-l-blue-500'
                                        }`}
                                >
                                    <div className="flex items-start justify-between gap-4">
                                        <div className="flex-1">
                                            <div className="flex items-center gap-3 mb-2">
                                                <span className={`text-xs font-bold uppercase tracking-widest px-2 py-1 rounded ${note.priority === 'high'
                                                    ? 'bg-red-500/10 text-red-600'
                                                    : note.priority === 'medium'
                                                        ? 'bg-orange-500/10 text-orange-600'
                                                        : 'bg-blue-500/10 text-blue-600'
                                                    }`}>
                                                    {note.priority} Priority
                                                </span>
                                                <span className="text-xs text-text-muted">
                                                    Affected {note.affectedScans} scan{note.affectedScans > 1 ? 's' : ''}
                                                </span>
                                            </div>
                                            <h4 className="text-lg font-medium text-text-primary mb-2">{note.title}</h4>
                                            <p className="text-sm text-text-secondary">{note.recommendation}</p>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Quick Actions */}
                    <div className="mt-12 flex flex-wrap justify-center gap-4">
                        <Link
                            href="/dashboard"
                            className="px-6 py-3 bg-warm-100 text-text-primary rounded-xl font-bold hover:bg-warm-200 transition-all"
                        >
                            Back to Dashboard
                        </Link>
                        <Link
                            href="/scan"
                            className="px-6 py-3 bg-accent-primary text-white rounded-xl font-bold hover:bg-accent-primary/90 transition-all shadow-lg"
                        >
                            Start New Scan
                        </Link>
                    </div>
                </main>
            </div>
        </ProtectedRoute>
    );
}
