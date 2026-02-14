/**
 * API client for Matrix backend
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || '';
console.log('[API] Initialized with API_BASE:', API_BASE);

interface ApiError {
    detail: string;
}

export class MatrixApiClient {
    // No explicit token management needed - handled by HttpOnly cookies

    // Helper to get cookie by name
    private getCookie(name: string): string | null {
        if (typeof document === 'undefined') return null;

        // More robust cookie parsing
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            const [cookieName, cookieValue] = cookie.split('=').map(c => c.trim());
            if (cookieName === name) {
                console.log(`[API] Found cookie ${name}:`, cookieValue?.substring(0, 10) + '...');
                return cookieValue || null;
            }
        }
        console.log(`[API] Cookie ${name} not found. Available cookies:`, document.cookie);
        return null;
    }

    private extractErrorMessage(errorData: any, status: number, endpoint?: string): string {
        let message: string;
        if (typeof errorData.detail === 'string') {
            message = errorData.detail;
        } else if (typeof errorData.detail === 'object' && errorData.detail !== null) {
            message = JSON.stringify(errorData.detail);
        } else if (errorData.message) {
            message = errorData.message;
        } else if (errorData.error) {
            message = typeof errorData.error === 'string' ? errorData.error : JSON.stringify(errorData.error);
        } else {
            message = `HTTP error ${status}`;
        }

        const isAuthEndpoint = endpoint?.includes('/api/auth/login/') || endpoint?.includes('/api/auth/register/');
        if (!isAuthEndpoint && (message === 'Could not validate credentials' || status === 401)) {
            return 'Session expired. Please log in again.';
        }
        return message;
    }

    private async request<T>(
        endpoint: string,
        options: RequestInit = {}
    ): Promise<T> {
        const headers: HeadersInit = {
            'Content-Type': 'application/json',
            ...options.headers,
        };

        // Inject Authorization header if token is available in memory
        if (this.accessToken) {
            (headers as any)['Authorization'] = `Bearer ${this.accessToken}`;
        }

        // Inject CSRF Token from memory (fallback to cookie)
        const csrfToken = this.csrfToken || this.getCookie('CSRF-TOKEN');
        if (csrfToken) {
            console.log('[API] CSRF Token found, injecting into headers');
            (headers as any)['X-CSRF-Token'] = csrfToken;
        } else {
            if (options.method && options.method !== 'GET') {
                console.warn('[API] WARNING: No CSRF token found for unsafe request:', endpoint);
            }
        }

        try {
            const response = await fetch(`${API_BASE}${endpoint}`, {
                ...options,
                headers,
                credentials: 'include', // CRITICAL: Send cookies
                cache: 'no-store', // Disable caching to ensure fresh scan data
            });

            // Handle 401 Unauthorized (Token Expired?)
            if (response.status === 401 && !endpoint.includes('/auth/login')) {
                // Attempt refresh
                try {
                    const refreshResponse = await fetch(`${API_BASE}/api/auth/refresh/`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': this.getCookie('CSRF-TOKEN') || ''
                        },
                        credentials: 'include',
                    });

                    if (refreshResponse.ok) {
                        // Retry original request with same headers (which include CSRF)
                        const retryResponse = await fetch(`${API_BASE}${endpoint}`, {
                            ...options,
                            headers,
                            credentials: 'include',
                        });

                        if (!retryResponse.ok) {
                            const errorData = await retryResponse.json().catch(() => ({ detail: 'Unknown error' }));
                            throw new Error(this.extractErrorMessage(errorData, retryResponse.status, endpoint));
                        }

                        return retryResponse.json();
                    }
                } catch (e) {
                    console.error("Auto-refresh failed", e);
                }
            }

            if (!response.ok) {
                const errorData: any = await response.json().catch(() => ({ detail: 'Unknown error' }));
                const message = this.extractErrorMessage(errorData, response.status, endpoint);

                console.error('[API] Request failed:', { endpoint, status: response.status, message, data: errorData });
                throw new Error(message);
            }

            return response.json();
        } catch (err) {
            throw err;
        }
    }

    // Store tokens in memory for cross-site compatibility
    private csrfToken: string | null = null;
    private accessToken: string | null = null;

    async ensureCsrf() {
        const response = await this.request<{ status: string; csrf_token?: string }>('/api/csrf/');
        // Store the token from the response body
        if (response.csrf_token) {
            this.csrfToken = response.csrf_token;
            console.log('[API] CSRF token received and stored:', this.csrfToken.substring(0, 10) + '...');
        }
        return response;
    }

    // Auth endpoints
    async register(data: {
        email: string;
        username: string;
        password: string;
        full_name?: string;
        company?: string;
    }) {
        console.log('[API] Registration attempt starting...');

        // Ensure CSRF token before registration
        if (!this.csrfToken) {
            console.log('[API] Fetching CSRF token before registration...');
            try {
                await this.ensureCsrf();
            } catch (e) {
                console.warn('[API] CSRF fetch failed, continuing with cookie fallback');
            }
        }

        const response = await this.request<{
            access_token: string;
            user: User;
        }>('/api/auth/register/', {
            method: 'POST',
            body: JSON.stringify(data),
        });

        if (response.access_token) {
            this.accessToken = response.access_token;
            console.log('[API] Registration successful, access token stored');
        }
        return response;
    }

    async login(email: string, password: string) {
        console.log('[API] Login attempt starting...');

        // Ensure CSRF token before login
        if (!this.csrfToken) {
            console.log('[API] Fetching CSRF token before login...');
            try {
                await this.ensureCsrf();
            } catch (e) {
                console.warn('[API] CSRF fetch failed, continuing with cookie fallback');
            }
        }

        // Response contains token for backward compat, but cookies are set
        const response = await this.request<{
            access_token: string;
            user: User;
        }>('/api/auth/login/', {
            method: 'POST',
            body: JSON.stringify({ email, password }),
        });

        if (response.access_token) {
            this.accessToken = response.access_token;
            console.log('[API] Login successful, access token stored');
        }
        return response;
    }

    async logout() {
        this.accessToken = null;
        return this.request<{ message: string }>('/api/auth/logout/', {
            method: 'POST'
        });
    }

    async getCurrentUser() {
        return this.request<User>('/api/auth/me/');
    }

    async createScan(data: {
        target_url: string;
        target_name?: string;
        scan_type?: string;
        agents_enabled?: string[];
        enable_waf_evasion?: boolean;
        waf_evasion_consent?: boolean;
        custom_headers?: Record<string, string>;
        custom_cookies?: Record<string, string>;
    }) {
        return this.request<Scan>('/api/scans/', {
            method: 'POST',
            body: JSON.stringify(data)
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
        return this.request<Scan>(`/api/scans/${scanId}/`);
    }

    async startScan(scanId: number) {
        return this.request<Scan>(`/api/scans/${scanId}/start/`, {
            method: 'POST',
        });
    }

    async cancelScan(scanId: number) {
        return this.request<Scan>(`/api/scans/${scanId}/cancel/`, {
            method: 'POST',
        });
    }

    async deleteScan(scanId: number) {
        return this.request<void>(`/api/scans/${scanId}/`, {
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
        }>(`/api/vulnerabilities/scan/${scanId}/summary/`);
    }

    async updateVulnerability(
        vulnId: number,
        data: {
            is_false_positive?: boolean;
            is_verified?: boolean;
            is_fixed?: boolean;
        }
    ) {
        return this.request<Vulnerability>(`/api/vulnerabilities/${vulnId}/`, {
            method: 'PATCH',
            body: JSON.stringify(data),
        });
    }

    // Chat endpoint
    async chat(message: string, scanId?: number) {
        return this.request<{
            response: string;
            metadata?: any;
            suggested_questions: string[];
        }>('/api/chat/', {
            method: 'POST',
            body: JSON.stringify({ message, scan_id: scanId }),
        });
    }

    async resetChat() {
        return this.request<{ status: string }>('/api/chat/reset/', {
            method: 'POST',
        });
    }

    // Forensics & Self-Healing
    async selfHealArtifact(scanId: string, artifactId: string) {
        return this.request<any>(`/api/forensics/${scanId}/artifacts/${artifactId}/self-heal/`, {
            method: 'POST',
        });
    }

    async reportIssue(scanId: string, artifactId: string) {
        return this.request<any>(`/api/forensics/${scanId}/artifacts/${artifactId}/report-issue/`, {
            method: 'POST',
        });
    }

    // ==================== GitHub Token Management ====================

    async saveGitHubToken(token: string): Promise<{ message: string; username: string; configured: boolean }> {
        return this.request('/api/auth/settings/github-token/', {
            method: 'POST',
            body: JSON.stringify({ token }),
        });
    }

    async getGitHubTokenStatus(): Promise<{ configured: boolean; username?: string; valid: boolean; last_validated?: string }> {
        return this.request('/api/auth/settings/github-token/status/');
    }

    async deleteGitHubToken(): Promise<{ message: string }> {
        return this.request('/api/auth/settings/github-token/', {
            method: 'DELETE',
        });
    }

    async validateGitHubToken(): Promise<{ valid: boolean; username?: string; message: string }> {
        return this.request('/api/auth/settings/github-token/validate/', {
            method: 'POST',
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
    scanned_files?: string[];
    enable_waf_evasion: boolean;
    waf_evasion_consent: boolean;
    custom_headers: Record<string, string> | null;
    custom_cookies: Record<string, string> | null;
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
    file_path?: string;
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
    is_suppressed: boolean;
    suppression_reason?: string;

    // Final Verdict Layer
    final_verdict?: string;
    action_required: boolean;
    detection_confidence: number;
    exploit_confidence: number;

    // Scope & Impact
    scope_impact?: {
        affected_endpoints: number;
        affected_methods: string[];
        is_systemic: boolean;
        summary: string;
        description?: string;
    };

    detected_by?: string;
    detected_at: string;
    scan_id: number;
}



// Export singleton instance
export const api: MatrixApiClient = new MatrixApiClient();
