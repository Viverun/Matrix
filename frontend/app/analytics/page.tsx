'use client';

import { useState, useEffect, useMemo } from 'react';
import {
    TrendingUp, TrendingDown, Activity, Shield, AlertTriangle,
    BarChart3, PieChart, Calendar, ArrowUpRight, ArrowDownRight,
    Target, Zap, CheckCircle, Clock, FileSearch, Lightbulb, ArrowLeft,
    Globe, Loader2, FileText, Download, ChevronRight, Eye, ExternalLink,
    User, Building, Mail, Filter, Search, XCircle
} from 'lucide-react';
import Link from 'next/link';
import { useAuth } from '../../context/AuthContext';
import { ProtectedRoute } from '../../components/ProtectedRoute';
import { Navbar } from '../../components/Navbar';
import { api, Scan, Vulnerability } from '../../lib/api';

export default function AnalyticsPage() {
    const { user } = useAuth();
    const [scans, setScans] = useState<Scan[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [timeRange, setTimeRange] = useState('All');
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedStatus, setSelectedStatus] = useState<string>('all');
    const [activeTab, setActiveTab] = useState<'overview' | 'reports'>('overview');

    useEffect(() => {
        const fetchData = async () => {
            setIsLoading(true);
            try {
                const data = await api.getScans(1, 100);
                setScans(data.items);
            } catch (err) {
                console.error('Failed to fetch analytics data');
            } finally {
                setIsLoading(false);
            }
        };
        fetchData();
    }, []);

    // Filter scans based on time range, search, and status
    const filteredScans = useMemo(() => {
        let result = [...scans];
        
        // Time range filter
        if (timeRange !== 'All') {
            const days = timeRange === '7d' ? 7 : timeRange === '30d' ? 30 : 90;
            const cutoff = new Date();
            cutoff.setDate(cutoff.getDate() - days);
            result = result.filter(s => new Date(s.created_at) >= cutoff);
        }
        
        // Search filter
        if (searchQuery) {
            const query = searchQuery.toLowerCase();
            result = result.filter(s => 
                s.target_url.toLowerCase().includes(query) ||
                s.target_name?.toLowerCase().includes(query)
            );
        }
        
        // Status filter
        if (selectedStatus !== 'all') {
            result = result.filter(s => s.status === selectedStatus);
        }
        
        return result;
    }, [scans, timeRange, searchQuery, selectedStatus]);

    // Calculate aggregated stats
    const stats = filteredScans.reduce((acc, scan) => ({
        totalScans: filteredScans.length,
        completedScans: acc.completedScans + (scan.status === 'completed' ? 1 : 0),
        totalVulnerabilities: acc.totalVulnerabilities + (scan.total_vulnerabilities || 0),
        criticalCount: acc.criticalCount + (scan.critical_count || 0),
        highCount: acc.highCount + (scan.high_count || 0),
        mediumCount: acc.mediumCount + (scan.medium_count || 0),
        lowCount: acc.lowCount + (scan.low_count || 0),
        infoCount: acc.infoCount + (scan.info_count || 0),
    }), {
        totalScans: 0,
        completedScans: 0,
        totalVulnerabilities: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
    });

    // Calculate security score
    const baseScore = 100;
    const criticalPenalty = stats.criticalCount * 10;
    const highPenalty = stats.highCount * 5;
    const mediumPenalty = stats.mediumCount * 2;
    const lowPenalty = stats.lowCount * 0.5;
    const securityScore = Math.max(0, Math.min(100, baseScore - criticalPenalty - highPenalty - mediumPenalty - lowPenalty));
    const scoreColor = securityScore >= 70 ? 'text-green-600' : securityScore >= 40 ? 'text-amber-600' : 'text-red-600';
    const scoreBg = securityScore >= 70 ? 'bg-green-500' : securityScore >= 40 ? 'bg-amber-500' : 'bg-red-500';

    // Get unique targets
    const uniqueTargets = Array.from(new Set(filteredScans.map(s => {
        try { return new URL(s.target_url).hostname; } catch { return s.target_url; }
    })));

    // Group scans by month for trend
    const scansByMonth = useMemo(() => {
        const grouped: { [key: string]: { scans: number; vulns: number } } = {};
        filteredScans.forEach(scan => {
            const date = new Date(scan.created_at);
            const key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
            if (!grouped[key]) grouped[key] = { scans: 0, vulns: 0 };
            grouped[key].scans++;
            grouped[key].vulns += scan.total_vulnerabilities || 0;
        });
        return Object.entries(grouped)
            .sort(([a], [b]) => b.localeCompare(a))
            .slice(0, 6)
            .map(([key, data]) => ({
                month: new Date(key + '-01').toLocaleDateString('en-US', { month: 'short', year: 'numeric' }),
                ...data
            }));
    }, [filteredScans]);

    const getStatusBadge = (status: string) => {
        const styles: Record<string, string> = {
            completed: 'bg-green-100 text-green-700 border-green-200',
            running: 'bg-blue-100 text-blue-700 border-blue-200',
            pending: 'bg-amber-100 text-amber-700 border-amber-200',
            failed: 'bg-red-100 text-red-700 border-red-200',
            cancelled: 'bg-gray-100 text-gray-700 border-gray-200',
        };
        return styles[status] || styles.pending;
    };

    if (isLoading) {
        return (
            <ProtectedRoute>
                <div className="min-h-screen bg-bg-primary flex items-center justify-center">
                    <div className="text-center space-y-4">
                        <Loader2 className="w-12 h-12 text-accent-primary animate-spin mx-auto opacity-40" />
                        <p className="text-text-muted font-serif italic text-lg animate-pulse">Loading analytics...</p>
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
                    {/* User Profile Header */}
                    <div className="glass-card p-8 mb-8 bg-gradient-to-r from-warm-50 to-green-50/30">
                        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                            <div className="flex items-center gap-6">
                                <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-accent-primary to-green-600 flex items-center justify-center text-white text-3xl font-bold shadow-lg">
                                    {user?.username?.charAt(0).toUpperCase() || 'U'}
                                </div>
                                <div>
                                    <h1 className="text-3xl font-serif-display font-medium text-text-primary">
                                        {user?.username || 'Security Analyst'}
                                    </h1>
                                    <div className="flex items-center gap-4 mt-2 text-text-secondary">
                                        <span className="flex items-center gap-1.5">
                                            <Mail className="w-4 h-4 opacity-60" />
                                            {user?.email}
                                        </span>
                                        {user?.company && (
                                            <span className="flex items-center gap-1.5">
                                                <Building className="w-4 h-4 opacity-60" />
                                                {user.company}
                                            </span>
                                        )}
                                    </div>
                                    <div className="flex items-center gap-2 mt-3">
                                        <span className="text-xs font-bold uppercase tracking-widest text-accent-primary bg-accent-primary/10 px-3 py-1 rounded-full">
                                            {stats.totalScans} Total Scans
                                        </span>
                                        <span className="text-xs font-bold uppercase tracking-widest text-text-muted bg-warm-100 px-3 py-1 rounded-full">
                                            {uniqueTargets.length} Unique Targets
                                        </span>
                                    </div>
                                </div>
                            </div>
                            
                            {/* Security Score Circle */}
                            <div className="flex items-center gap-6">
                                <div className="relative">
                                    <svg className="w-32 h-32 transform -rotate-90">
                                        <circle
                                            cx="64" cy="64" r="56"
                                            fill="none"
                                            stroke="currentColor"
                                            strokeWidth="8"
                                            className="text-warm-200"
                                        />
                                        <circle
                                            cx="64" cy="64" r="56"
                                            fill="none"
                                            stroke="currentColor"
                                            strokeWidth="8"
                                            strokeLinecap="round"
                                            className={scoreBg}
                                            strokeDasharray={`${(securityScore / 100) * 352} 352`}
                                        />
                                    </svg>
                                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                                        <span className={`text-3xl font-bold ${scoreColor}`}>{Math.round(securityScore)}</span>
                                        <span className="text-xs text-text-muted font-bold uppercase tracking-widest">Score</span>
                                    </div>
                                </div>
                                <div className="text-right">
                                    <div className="text-sm font-bold text-text-primary mb-1">Security Posture</div>
                                    <div className={`text-lg font-bold ${scoreColor}`}>
                                        {securityScore >= 70 ? 'Good' : securityScore >= 40 ? 'Fair' : 'Needs Attention'}
                                    </div>
                                    <div className="text-xs text-text-muted mt-1">
                                        Based on {stats.totalVulnerabilities} findings
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Tab Navigation */}
                    <div className="flex items-center gap-4 mb-8 border-b border-warm-200">
                        <button
                            onClick={() => setActiveTab('overview')}
                            className={`px-6 py-4 font-bold text-sm uppercase tracking-widest transition-all border-b-2 -mb-[2px] ${
                                activeTab === 'overview'
                                    ? 'text-accent-primary border-accent-primary'
                                    : 'text-text-muted border-transparent hover:text-text-primary'
                            }`}
                        >
                            <BarChart3 className="w-4 h-4 inline mr-2" />
                            Overview
                        </button>
                        <button
                            onClick={() => setActiveTab('reports')}
                            className={`px-6 py-4 font-bold text-sm uppercase tracking-widest transition-all border-b-2 -mb-[2px] ${
                                activeTab === 'reports'
                                    ? 'text-accent-primary border-accent-primary'
                                    : 'text-text-muted border-transparent hover:text-text-primary'
                            }`}
                        >
                            <FileText className="w-4 h-4 inline mr-2" />
                            Full Scan Reports
                        </button>
                    </div>

                    {/* Filters Bar */}
                    <div className="flex flex-col md:flex-row gap-4 mb-8">
                        {/* Search */}
                        <div className="flex-1 relative">
                            <Search className="w-5 h-5 absolute left-4 top-1/2 -translate-y-1/2 text-text-muted" />
                            <input
                                type="text"
                                placeholder="Search targets..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                className="w-full pl-12 pr-4 py-3 bg-white border border-warm-200 rounded-xl text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent-primary/20 focus:border-accent-primary transition-all"
                            />
                        </div>
                        
                        {/* Status Filter */}
                        <select
                            value={selectedStatus}
                            onChange={(e) => setSelectedStatus(e.target.value)}
                            className="px-4 py-3 bg-white border border-warm-200 rounded-xl text-text-primary font-medium focus:outline-none focus:ring-2 focus:ring-accent-primary/20 focus:border-accent-primary transition-all"
                        >
                            <option value="all">All Status</option>
                            <option value="completed">Completed</option>
                            <option value="running">Running</option>
                            <option value="pending">Pending</option>
                            <option value="failed">Failed</option>
                        </select>

                        {/* Time Range */}
                        <div className="flex items-center gap-1 bg-white rounded-xl p-1 border border-warm-200">
                            {['7d', '30d', '90d', 'All'].map((range) => (
                                <button
                                    key={range}
                                    onClick={() => setTimeRange(range)}
                                    className={`px-4 py-2 rounded-lg text-sm font-bold transition-all ${
                                        timeRange === range
                                            ? 'bg-accent-primary text-white shadow'
                                            : 'text-text-muted hover:text-accent-primary hover:bg-warm-50'
                                    }`}
                                >
                                    {range}
                                </button>
                            ))}
                        </div>
                    </div>

                    {activeTab === 'overview' ? (
                        <>
                            {/* Stats Cards */}
                            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
                                {[
                                    { label: 'Total Scans', value: stats.totalScans, icon: Target, color: 'text-accent-primary', bg: 'bg-accent-primary/10' },
                                    { label: 'Completed', value: stats.completedScans, icon: CheckCircle, color: 'text-green-600', bg: 'bg-green-100' },
                                    { label: 'Critical', value: stats.criticalCount, icon: XCircle, color: 'text-red-600', bg: 'bg-red-100' },
                                    { label: 'High', value: stats.highCount, icon: AlertTriangle, color: 'text-orange-600', bg: 'bg-orange-100' },
                                    { label: 'Medium', value: stats.mediumCount, icon: Shield, color: 'text-amber-600', bg: 'bg-amber-100' },
                                    { label: 'Low/Info', value: stats.lowCount + stats.infoCount, icon: Activity, color: 'text-blue-600', bg: 'bg-blue-100' },
                                ].map((stat, i) => (
                                    <div key={i} className="glass-card p-5 hover:shadow-lg transition-all">
                                        <div className={`w-10 h-10 ${stat.bg} rounded-xl flex items-center justify-center mb-3`}>
                                            <stat.icon className={`w-5 h-5 ${stat.color}`} />
                                        </div>
                                        <div className="text-2xl font-bold text-text-primary">{stat.value}</div>
                                        <div className="text-xs font-bold uppercase tracking-widest text-text-muted">{stat.label}</div>
                                    </div>
                                ))}
                            </div>

                            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
                                {/* Vulnerability Distribution */}
                                <div className="lg:col-span-2 glass-card p-8">
                                    <h3 className="text-xl font-serif-display font-medium text-text-primary flex items-center gap-3 mb-6">
                                        <div className="w-1.5 h-6 bg-accent-primary rounded-full" />
                                        Vulnerability Distribution
                                    </h3>

                                    <div className="grid grid-cols-4 gap-4 mb-6">
                                        {[
                                            { label: 'Critical', value: stats.criticalCount, color: 'bg-red-500', textColor: 'text-red-600' },
                                            { label: 'High', value: stats.highCount, color: 'bg-orange-500', textColor: 'text-orange-600' },
                                            { label: 'Medium', value: stats.mediumCount, color: 'bg-amber-500', textColor: 'text-amber-600' },
                                            { label: 'Low', value: stats.lowCount, color: 'bg-blue-500', textColor: 'text-blue-600' },
                                        ].map((item, i) => (
                                            <div key={i} className="text-center p-4 bg-warm-50 rounded-xl">
                                                <div className={`text-2xl font-bold ${item.textColor}`}>{item.value}</div>
                                                <div className="text-xs font-bold uppercase tracking-widest text-text-muted mt-1">{item.label}</div>
                                            </div>
                                        ))}
                                    </div>

                                    {/* Bar Chart */}
                                    <div className="space-y-3">
                                        {[
                                            { label: 'Critical', value: stats.criticalCount, color: 'bg-red-400' },
                                            { label: 'High', value: stats.highCount, color: 'bg-orange-400' },
                                            { label: 'Medium', value: stats.mediumCount, color: 'bg-amber-400' },
                                            { label: 'Low', value: stats.lowCount, color: 'bg-blue-400' },
                                        ].map((item, i) => (
                                            <div key={i} className="flex items-center gap-4">
                                                <div className="w-16 text-sm text-text-secondary font-medium">{item.label}</div>
                                                <div className="flex-1 h-4 bg-warm-100 rounded-full overflow-hidden">
                                                    <div
                                                        className={`h-full ${item.color} rounded-full transition-all duration-1000`}
                                                        style={{ width: `${stats.totalVulnerabilities ? (item.value / stats.totalVulnerabilities) * 100 : 0}%` }}
                                                    />
                                                </div>
                                                <div className="w-10 text-right text-sm font-bold text-text-primary">{item.value}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                {/* Monthly Trend */}
                                <div className="glass-card p-8">
                                    <h3 className="text-xl font-serif-display font-medium text-text-primary flex items-center gap-3 mb-6">
                                        <div className="w-1.5 h-6 bg-green-500 rounded-full" />
                                        Activity Trend
                                    </h3>

                                    <div className="space-y-4">
                                        {scansByMonth.length > 0 ? scansByMonth.map((item, i) => (
                                            <div key={i} className="flex items-center justify-between py-3 border-b border-warm-100 last:border-0">
                                                <div>
                                                    <div className="font-medium text-text-primary">{item.month}</div>
                                                    <div className="text-xs text-text-muted">{item.scans} scans</div>
                                                </div>
                                                <div className="text-right">
                                                    <div className="text-lg font-bold text-text-primary">{item.vulns}</div>
                                                    <div className="text-xs text-text-muted">findings</div>
                                                </div>
                                            </div>
                                        )) : (
                                            <p className="text-text-muted text-center py-8">No scan data available</p>
                                        )}
                                    </div>
                                </div>
                            </div>

                            {/* Top Targets */}
                            <div className="glass-card p-8">
                                <h3 className="text-xl font-serif-display font-medium text-text-primary flex items-center gap-3 mb-6">
                                    <div className="w-1.5 h-6 bg-accent-gold rounded-full" />
                                    <Globe className="w-5 h-5 text-accent-gold" />
                                    Scanned Targets
                                </h3>

                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                    {uniqueTargets.slice(0, 6).map((target, i) => {
                                        const targetScans = filteredScans.filter(s => {
                                            try { return new URL(s.target_url).hostname === target; } catch { return s.target_url === target; }
                                        });
                                        const totalVulns = targetScans.reduce((sum, s) => sum + (s.total_vulnerabilities || 0), 0);
                                        const criticals = targetScans.reduce((sum, s) => sum + (s.critical_count || 0), 0);
                                        
                                        return (
                                            <div key={i} className="p-4 bg-warm-50 rounded-xl border border-warm-100 hover:border-accent-primary/30 transition-all">
                                                <div className="flex items-center gap-3 mb-3">
                                                    <div className="w-10 h-10 bg-white rounded-lg flex items-center justify-center border border-warm-200">
                                                        <Globe className="w-5 h-5 text-accent-primary" />
                                                    </div>
                                                    <div className="flex-1 min-w-0">
                                                        <div className="font-medium text-text-primary truncate">{target}</div>
                                                        <div className="text-xs text-text-muted">{targetScans.length} scan{targetScans.length !== 1 ? 's' : ''}</div>
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-3">
                                                    <span className="text-xs font-bold px-2 py-1 rounded bg-warm-100 text-text-muted">
                                                        {totalVulns} findings
                                                    </span>
                                                    {criticals > 0 && (
                                                        <span className="text-xs font-bold px-2 py-1 rounded bg-red-100 text-red-600">
                                                            {criticals} critical
                                                        </span>
                                                    )}
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>
                        </>
                    ) : (
                        /* Full Scan Reports Tab */
                        <div className="glass-card overflow-hidden">
                            <div className="p-6 border-b border-warm-100 bg-warm-50/50">
                                <div className="flex items-center justify-between">
                                    <h3 className="text-xl font-serif-display font-medium text-text-primary flex items-center gap-3">
                                        <FileText className="w-5 h-5 text-accent-primary" />
                                        Full Scan Reports
                                    </h3>
                                    <span className="text-sm text-text-muted">
                                        Showing {filteredScans.length} of {scans.length} scans
                                    </span>
                                </div>
                            </div>

                            {/* Table Header */}
                            <div className="hidden md:grid grid-cols-12 gap-4 px-6 py-3 bg-warm-50 text-xs font-bold uppercase tracking-widest text-text-muted border-b border-warm-100">
                                <div className="col-span-1">ID</div>
                                <div className="col-span-3">Target</div>
                                <div className="col-span-2">Date</div>
                                <div className="col-span-1">Status</div>
                                <div className="col-span-3">Findings</div>
                                <div className="col-span-2 text-right">Actions</div>
                            </div>

                            {/* Scan Rows */}
                            <div className="divide-y divide-warm-100">
                                {filteredScans.length === 0 ? (
                                    <div className="p-12 text-center">
                                        <FileSearch className="w-12 h-12 text-text-muted/40 mx-auto mb-4" />
                                        <p className="text-text-muted">No scans found matching your filters</p>
                                    </div>
                                ) : (
                                    filteredScans.map((scan) => (
                                        <div key={scan.id} className="grid grid-cols-1 md:grid-cols-12 gap-4 px-6 py-4 hover:bg-warm-50/50 transition-colors items-center">
                                            {/* ID */}
                                            <div className="md:col-span-1">
                                                <span className="text-xs font-mono font-bold text-accent-primary bg-accent-primary/10 px-2 py-1 rounded">
                                                    #{scan.id}
                                                </span>
                                            </div>

                                            {/* Target */}
                                            <div className="md:col-span-3">
                                                <div className="flex items-center gap-2">
                                                    <Globe className="w-4 h-4 text-text-muted flex-shrink-0" />
                                                    <div className="min-w-0">
                                                        <div className="font-medium text-text-primary truncate">
                                                            {scan.target_name || (() => { try { return new URL(scan.target_url).hostname; } catch { return scan.target_url; } })()}
                                                        </div>
                                                        <div className="text-xs text-text-muted truncate">{scan.target_url}</div>
                                                    </div>
                                                </div>
                                            </div>

                                            {/* Date */}
                                            <div className="md:col-span-2">
                                                <div className="text-sm text-text-primary">
                                                    {new Date(scan.created_at).toLocaleDateString()}
                                                </div>
                                                <div className="text-xs text-text-muted">
                                                    {new Date(scan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                                </div>
                                            </div>

                                            {/* Status */}
                                            <div className="md:col-span-1">
                                                <span className={`text-xs font-bold uppercase px-2 py-1 rounded border ${getStatusBadge(scan.status)}`}>
                                                    {scan.status}
                                                </span>
                                            </div>

                                            {/* Findings */}
                                            <div className="md:col-span-3">
                                                <div className="flex items-center gap-2 flex-wrap">
                                                    <span className="text-sm font-bold text-text-primary">
                                                        {scan.total_vulnerabilities || 0} total
                                                    </span>
                                                    <div className="flex items-center gap-1.5">
                                                        {scan.critical_count > 0 && (
                                                            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-100 text-red-600">
                                                                {scan.critical_count}C
                                                            </span>
                                                        )}
                                                        {scan.high_count > 0 && (
                                                            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-orange-100 text-orange-600">
                                                                {scan.high_count}H
                                                            </span>
                                                        )}
                                                        {scan.medium_count > 0 && (
                                                            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-amber-100 text-amber-600">
                                                                {scan.medium_count}M
                                                            </span>
                                                        )}
                                                        {scan.low_count > 0 && (
                                                            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-blue-100 text-blue-600">
                                                                {scan.low_count}L
                                                            </span>
                                                        )}
                                                    </div>
                                                </div>
                                            </div>

                                            {/* Actions */}
                                            <div className="md:col-span-2 flex items-center justify-end gap-2">
                                                <Link
                                                    href={`/scans/${scan.id}`}
                                                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-accent-primary hover:bg-accent-primary/10 rounded-lg transition-colors"
                                                >
                                                    <Eye className="w-3.5 h-3.5" />
                                                    View
                                                </Link>
                                                <button className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-text-muted hover:bg-warm-100 rounded-lg transition-colors">
                                                    <Download className="w-3.5 h-3.5" />
                                                    Export
                                                </button>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>
                    )}

                    {/* Quick Actions */}
                    <div className="mt-12 flex flex-wrap justify-center gap-4">
                        <Link
                            href="/dashboard"
                            className="px-6 py-3 bg-white border border-warm-200 text-text-primary rounded-xl font-bold hover:border-accent-primary/30 hover:shadow-lg transition-all"
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
