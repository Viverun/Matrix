'use client';

import { useState, useEffect } from 'react';
import {
    Shield, Target, FileSearch, Activity,
    TrendingUp, AlertTriangle, CheckCircle, Clock,
    Plus, RefreshCw, Download
} from 'lucide-react';
import Link from 'next/link';

// Mock data
const mockScans = [
    { id: 1, target: 'https://example.com', status: 'completed', vulnerabilities: 7, date: '2024-01-15' },
    { id: 2, target: 'https://api.myapp.io', status: 'running', vulnerabilities: 0, date: '2024-01-15' },
    { id: 3, target: 'https://staging.test.com', status: 'completed', vulnerabilities: 3, date: '2024-01-14' },
];

const mockStats = {
    totalScans: 24,
    totalVulnerabilities: 87,
    criticalVulnerabilities: 5,
    fixedVulnerabilities: 62,
};

export default function DashboardPage() {
    const [scans, setScans] = useState(mockScans);
    const [stats, setStats] = useState(mockStats);

    return (
        <div className="min-h-screen">
            {/* Header */}
            <header className="border-b border-cyber-accent/20 bg-cyber-dark/50 backdrop-blur-sm sticky top-0 z-50">
                <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <Link href="/" className="flex items-center gap-3">
                            <Shield className="w-8 h-8 text-cyber-accent" />
                            <h1 className="text-xl font-bold text-white">
                                Cyber<span className="text-cyber-accent">Matrix</span>
                            </h1>
                        </Link>
                    </div>

                    <nav className="flex items-center gap-6">
                        <Link href="/dashboard" className="text-cyber-accent font-medium">Dashboard</Link>
                        <Link href="/scans" className="text-gray-300 hover:text-cyber-accent transition-colors">Scans</Link>
                        <Link href="/reports" className="text-gray-300 hover:text-cyber-accent transition-colors">Reports</Link>
                        <div className="w-8 h-8 bg-cyber-accent/20 rounded-full flex items-center justify-center">
                            <span className="text-cyber-accent text-sm font-bold">U</span>
                        </div>
                    </nav>
                </div>
            </header>

            <main className="max-w-7xl mx-auto px-4 py-8">
                {/* Page Title */}
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h2 className="text-3xl font-bold text-white">Dashboard</h2>
                        <p className="text-gray-400 mt-1">Overview of your security posture</p>
                    </div>
                    <Link href="/scans/new" className="cyber-btn flex items-center gap-2">
                        <Plus className="w-5 h-5" />
                        New Scan
                    </Link>
                </div>

                {/* Stats Grid */}
                <div className="grid grid-cols-4 gap-4 mb-8">
                    <div className="cyber-card p-6">
                        <div className="flex items-center justify-between mb-4">
                            <Target className="w-8 h-8 text-cyber-accent" />
                            <span className="text-xs text-gray-500">This month</span>
                        </div>
                        <div className="text-3xl font-bold text-white">{stats.totalScans}</div>
                        <div className="text-sm text-gray-400">Total Scans</div>
                    </div>

                    <div className="cyber-card p-6">
                        <div className="flex items-center justify-between mb-4">
                            <AlertTriangle className="w-8 h-8 text-yellow-500" />
                            <span className="text-xs text-gray-500">Active</span>
                        </div>
                        <div className="text-3xl font-bold text-white">{stats.totalVulnerabilities}</div>
                        <div className="text-sm text-gray-400">Vulnerabilities Found</div>
                    </div>

                    <div className="cyber-card p-6">
                        <div className="flex items-center justify-between mb-4">
                            <AlertTriangle className="w-8 h-8 text-red-500" />
                            <span className="text-xs text-red-500">Urgent</span>
                        </div>
                        <div className="text-3xl font-bold text-red-500">{stats.criticalVulnerabilities}</div>
                        <div className="text-sm text-gray-400">Critical Issues</div>
                    </div>

                    <div className="cyber-card p-6">
                        <div className="flex items-center justify-between mb-4">
                            <CheckCircle className="w-8 h-8 text-green-500" />
                            <span className="text-xs text-green-500">Resolved</span>
                        </div>
                        <div className="text-3xl font-bold text-green-500">{stats.fixedVulnerabilities}</div>
                        <div className="text-sm text-gray-400">Fixed Issues</div>
                    </div>
                </div>

                {/* Main Content Grid */}
                <div className="grid grid-cols-3 gap-6">
                    {/* Recent Scans */}
                    <div className="col-span-2 cyber-card p-6">
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="text-lg font-bold text-white flex items-center gap-2">
                                <Activity className="w-5 h-5 text-cyber-accent" />
                                Recent Scans
                            </h3>
                            <button className="text-gray-400 hover:text-cyber-accent transition-colors">
                                <RefreshCw className="w-5 h-5" />
                            </button>
                        </div>

                        <div className="space-y-4">
                            {scans.map((scan) => (
                                <div
                                    key={scan.id}
                                    className="flex items-center justify-between p-4 bg-cyber-dark/50 rounded-lg border border-gray-700/50 hover:border-cyber-accent/30 transition-colors"
                                >
                                    <div className="flex items-center gap-4">
                                        <div className={`w-3 h-3 rounded-full ${scan.status === 'running' ? 'bg-cyber-accent animate-pulse' :
                                                scan.status === 'completed' ? 'bg-green-500' : 'bg-gray-500'
                                            }`} />
                                        <div>
                                            <div className="font-medium text-white">{scan.target}</div>
                                            <div className="text-sm text-gray-400 flex items-center gap-2">
                                                <Clock className="w-3 h-3" />
                                                {scan.date}
                                            </div>
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-4">
                                        {scan.status === 'completed' && (
                                            <div className="text-right">
                                                <div className={`font-bold ${scan.vulnerabilities > 0 ? 'text-yellow-500' : 'text-green-500'}`}>
                                                    {scan.vulnerabilities} issues
                                                </div>
                                                <div className="text-xs text-gray-500">Found</div>
                                            </div>
                                        )}
                                        {scan.status === 'running' && (
                                            <div className="text-cyber-accent text-sm flex items-center gap-2">
                                                <div className="w-4 h-4 border-2 border-cyber-accent border-t-transparent rounded-full animate-spin" />
                                                Scanning...
                                            </div>
                                        )}
                                        <Link
                                            href={`/scans/${scan.id}`}
                                            className="text-gray-400 hover:text-cyber-accent transition-colors"
                                        >
                                            View →
                                        </Link>
                                    </div>
                                </div>
                            ))}
                        </div>

                        <Link
                            href="/scans"
                            className="block text-center text-cyber-accent hover:underline mt-4 text-sm"
                        >
                            View all scans
                        </Link>
                    </div>

                    {/* Vulnerability Breakdown */}
                    <div className="cyber-card p-6">
                        <h3 className="text-lg font-bold text-white flex items-center gap-2 mb-6">
                            <FileSearch className="w-5 h-5 text-cyber-accent" />
                            Vulnerability Breakdown
                        </h3>

                        <div className="space-y-4">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <div className="w-3 h-3 rounded-full bg-red-500" />
                                    <span className="text-gray-300">Critical</span>
                                </div>
                                <span className="font-mono text-red-500">5</span>
                            </div>

                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <div className="w-3 h-3 rounded-full bg-orange-500" />
                                    <span className="text-gray-300">High</span>
                                </div>
                                <span className="font-mono text-orange-500">12</span>
                            </div>

                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <div className="w-3 h-3 rounded-full bg-yellow-500" />
                                    <span className="text-gray-300">Medium</span>
                                </div>
                                <span className="font-mono text-yellow-500">28</span>
                            </div>

                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <div className="w-3 h-3 rounded-full bg-blue-500" />
                                    <span className="text-gray-300">Low</span>
                                </div>
                                <span className="font-mono text-blue-500">42</span>
                            </div>
                        </div>

                        {/* Simple Bar Chart */}
                        <div className="mt-6 pt-6 border-t border-gray-700/50">
                            <div className="h-32 flex items-end gap-2">
                                {[
                                    { value: 5, color: 'bg-red-500', label: 'Crit' },
                                    { value: 12, color: 'bg-orange-500', label: 'High' },
                                    { value: 28, color: 'bg-yellow-500', label: 'Med' },
                                    { value: 42, color: 'bg-blue-500', label: 'Low' },
                                ].map((bar, i) => (
                                    <div key={i} className="flex-1 flex flex-col items-center gap-1">
                                        <div
                                            className={`w-full ${bar.color} rounded-t transition-all duration-500`}
                                            style={{ height: `${(bar.value / 42) * 100}%` }}
                                        />
                                        <span className="text-xs text-gray-500">{bar.label}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>

                {/* Quick Actions */}
                <div className="mt-8 grid grid-cols-4 gap-4">
                    <Link href="/scans/new" className="cyber-card p-4 hover:border-cyber-accent/50 transition-colors group">
                        <Plus className="w-6 h-6 text-cyber-accent group-hover:scale-110 transition-transform" />
                        <div className="mt-2 font-medium text-white">New Scan</div>
                        <div className="text-sm text-gray-400">Start a new security scan</div>
                    </Link>

                    <Link href="/reports" className="cyber-card p-4 hover:border-cyber-accent/50 transition-colors group">
                        <Download className="w-6 h-6 text-cyber-accent group-hover:scale-110 transition-transform" />
                        <div className="mt-2 font-medium text-white">Export Report</div>
                        <div className="text-sm text-gray-400">Download PDF/HTML report</div>
                    </Link>

                    <Link href="/settings" className="cyber-card p-4 hover:border-cyber-accent/50 transition-colors group">
                        <TrendingUp className="w-6 h-6 text-cyber-accent group-hover:scale-110 transition-transform" />
                        <div className="mt-2 font-medium text-white">Analytics</div>
                        <div className="text-sm text-gray-400">View security trends</div>
                    </Link>

                    <Link href="/integrations" className="cyber-card p-4 hover:border-cyber-accent/50 transition-colors group">
                        <Activity className="w-6 h-6 text-cyber-accent group-hover:scale-110 transition-transform" />
                        <div className="mt-2 font-medium text-white">Integrations</div>
                        <div className="text-sm text-gray-400">CI/CD & webhook setup</div>
                    </Link>
                </div>
            </main>
        </div>
    );
}
