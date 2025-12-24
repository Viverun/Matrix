/**
 * API client for Matrix backend
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface ApiError {
    detail: string;
}

class ApiClient {
    private token: string | null = null;

    setToken(token: string) {
        this.token = token;
        if (typeof window !== 'undefined') {
            localStorage.setItem('matrix_token', token);
        }
    }

    getToken(): string | null {
        if (this.token) return this.token;
        if (typeof window !== 'undefined') {
            return localStorage.getItem('matrix_token');
        }
        return null;
    }

    clearToken() {
        this.token = null;
        if (typeof window !== 'undefined') {
            localStorage.removeItem('matrix_token');
        }
    }

    private async request<T>(
        endpoint: string,
        options: RequestInit = {}
    ): Promise<T> {
        const token = this.getToken();

        const headers: HeadersInit = {
            'Content-Type': 'application/json',
            ...options.headers,
        };

        if (token) {
            (headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
        }

        const response = await fetch(`${API_BASE}${endpoint}`, {
            ...options,
            headers,
        });

        if (!response.ok) {
            const error: ApiError = await response.json().catch(() => ({ detail: 'Unknown error' }));
            throw new Error(error.detail || `HTTP error ${response.status}`);
        }

        return response.json();
    }

    // Auth endpoints
    async register(data: {
        email: string;
        username: string;
        password: string;
        full_name?: string;
    }) {
        return this.request<{
            access_token: string;
            user: User;
        }>('/api/auth/register', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    async login(email: string, password: string) {
        const response = await this.request<{
            access_token: string;
            user: User;
        }>('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({ email, password }),
        });

        this.setToken(response.access_token);
        return response;
    }

    async getCurrentUser() {
        return this.request<User>('/api/auth/me');
    }

    // Scan endpoints
    async createScan(data: {
        target_url: string;
        target_name?: string;
        scan_type?: string;
        agents_enabled?: string[];
    }) {
        return this.request<Scan>('/api/scans/', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }

    async getScans(page: number = 1, size: number = 20) {
        return this.request<{
            items: Scan[];
            total: number;
            page: number;
            size: number;
            pages: number;
        }>(`/api/scans/?page=${page}&size=${size}`);
    }

    async getScan(scanId: number) {
        return this.request<Scan>(`/api/scans/${scanId}`);
    }

    async startScan(scanId: number) {
        return this.request<Scan>(`/api/scans/${scanId}/start`, {
            method: 'POST',
        });
    }

    async cancelScan(scanId: number) {
        return this.request<Scan>(`/api/scans/${scanId}/cancel`, {
            method: 'POST',
        });
    }

    async deleteScan(scanId: number) {
        return this.request<void>(`/api/scans/${scanId}`, {
            method: 'DELETE',
        });
    }

    // Vulnerability endpoints
    async getVulnerabilities(scanId: number, page: number = 1, size: number = 50) {
        return this.request<{
            items: Vulnerability[];
            total: number;
            page: number;
            size: number;
        }>(`/api/vulnerabilities/?scan_id=${scanId}&page=${page}&size=${size}`);
    }

    async getVulnerabilitySummary(scanId: number) {
        return this.request<{
            total: number;
            critical: number;
            high: number;
            medium: number;
            low: number;
            info: number;
        }>(`/api/vulnerabilities/scan/${scanId}/summary`);
    }

    async updateVulnerability(
        vulnId: number,
        data: {
            is_false_positive?: boolean;
            is_verified?: boolean;
            is_fixed?: boolean;
        }
    ) {
        return this.request<Vulnerability>(`/api/vulnerabilities/${vulnId}`, {
            method: 'PATCH',
            body: JSON.stringify(data),
        });
    }
}

// Types
export interface User {
    id: number;
    email: string;
    username: string;
    full_name?: string;
    company?: string;
    is_active: boolean;
    is_verified: boolean;
    created_at: string;
}

export interface Scan {
    id: number;
    target_url: string;
    target_name?: string;
    scan_type: string;
    status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
    progress: number;
    total_vulnerabilities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    info_count: number;
    technology_stack: string[];
    agents_enabled: string[];
    error_message?: string;
    created_at: string;
    started_at?: string;
    completed_at?: string;
}

export interface Vulnerability {
    id: number;
    vulnerability_type: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    cvss_score?: number;
    url: string;
    parameter?: string;
    method: string;
    title: string;
    description: string;
    evidence?: string;
    ai_confidence: number;
    ai_analysis?: string;
    remediation?: string;
    remediation_code?: string;
    reference_links: string[];
    owasp_category?: string;
    cwe_id?: string;
    is_false_positive: boolean;
    is_verified: boolean;
    is_fixed: boolean;
    detected_by?: string;
    detected_at: string;
    scan_id: number;
}

// Export singleton instance
export const api = new ApiClient();
