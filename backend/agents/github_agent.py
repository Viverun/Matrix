"""

Features:
"""
import re
import httpx
import asyncio
import hashlib
import math
from typing import List, Dict, Any, Optional, Set, Tuple, TYPE_CHECKING
from urllib.parse import urlparse
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import logging
from .dependency_parser import DependencyParser, ParsedDependency

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType
from core.groq_client import repo_generate, groq_manager, ModelTier
from scoring import VulnerabilityContext, ConfidenceMethod

if TYPE_CHECKING:
    from core.scan_context import ScanContext

logger = logging.getLogger(__name__)


# ==================== Configuration Classes ====================

class GithubAgentConfig:
    """Configuration constants for GitHub Security Agent"""

    # API Settings
    DEFAULT_TIMEOUT = 20.0
    MAX_RETRIES = 3
    RETRY_BACKOFF_BASE = 2
    RATE_LIMIT_BUFFER = 10  # Keep this many requests in reserve

    # File Processing
    MAX_FILES_TO_SCAN = 50  # Increased from 15
    MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5MB max per file
    CONCURRENT_FILE_LIMIT = 5

    # Secret Detection
    MIN_ENTROPY_THRESHOLD = 4.5  # Shannon entropy threshold
    SECRET_MIN_LENGTH = 20
    SECRET_MAX_LENGTH = 200

    # Caching
    CACHE_TTL_SECONDS = 3600  # 1 hour
    ENABLE_CACHE = True

    # Dependency Scanning
    ENABLE_DEPENDENCY_SCAN = True
    OSV_API_URL = "https://api.osv.dev/v1/querybatch"

    # File Priority Scores
    PRIORITY_CRITICAL = 100  # Config files with secrets
    PRIORITY_HIGH = 80  # Auth/API files
    PRIORITY_MEDIUM = 60  # Database/connection files
    PRIORITY_LOW = 40  # Regular source code
    PRIORITY_MINIMAL = 20  # Test files


class SecretPattern:
    """Enhanced secret patterns with metadata"""

    PATTERNS = [
        # Cloud Providers
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key", True),
        (r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z\/+]{40}[\'"]', "AWS Secret Key", True),
        (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", True),
        (r'ya29\.[0-9A-Za-z\-_]+', "Google OAuth Token", True),

        # API Keys
        (r'sk-[a-zA-Z0-9]{48}', "OpenAI API Key", True),
        (r'sk-proj-[a-zA-Z0-9\-_]{48,}', "OpenAI Project Key", True),
        (r'sk-ant-[a-zA-Z0-9\-_]{95,}', "Anthropic API Key", True),

        # Version Control
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token", True),
        (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token", True),
        (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', "GitHub Fine-Grained PAT", True),
        (r'glpat-[a-zA-Z0-9\-_]{20}', "GitLab Personal Access Token", True),

        # Payment/Commerce
        (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Secret Key", True),
        (r'rk_live_[0-9a-zA-Z]{24,}', "Stripe Live Restricted Key", True),
        (r'sq0csp-[0-9A-Za-z\-_]{43}', "Square Access Token", True),

        # Communication
        (r'xox[baprs]-[0-9a-zA-Z\-]{10,72}', "Slack Token", True),
        (r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+', "Slack Webhook", True),

        # Databases
        (r'postgres://[a-zA-Z0-9]+:[a-zA-Z0-9!@#$%^&*()_+=\-]+@[a-zA-Z0-9.\-]+:[0-9]+/[a-zA-Z0-9_]+',
         "PostgreSQL Connection String", True),
        (r'mongodb(\+srv)?://[a-zA-Z0-9]+:[a-zA-Z0-9!@#$%^&*()_+=\-]+@[a-zA-Z0-9.\-]+', "MongoDB Connection String",
         True),
        (r'mysql://[a-zA-Z0-9]+:[a-zA-Z0-9!@#$%^&*()_+=\-]+@[a-zA-Z0-9.\-]+:[0-9]+/[a-zA-Z0-9_]+',
         "MySQL Connection String", True),

        # Other Services
        (r'sqp_[a-zA-Z0-9]{40}', "SonarQube Token", True),
        (r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----', "Private Key", True),
        (r'-----BEGIN OPENSSH PRIVATE KEY-----', "OpenSSH Private Key", True),

        # JWT (with validation) - low confidence, needs entropy check
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+', "Potential JWT Token", False),
    ]


class DependencyFile:
    """Dependency file patterns and parsers"""

    PACKAGE_FILES = {
        'package.json': 'npm',
        'package-lock.json': 'npm',
        'yarn.lock': 'yarn',
        'requirements.txt': 'pip',
        'Pipfile': 'pip',
        'Pipfile.lock': 'pip',
        'poetry.lock': 'poetry',
        'pyproject.toml': 'poetry',
        'go.mod': 'go',
        'go.sum': 'go',
        'Gemfile': 'ruby',
        'Gemfile.lock': 'ruby',
        'composer.json': 'php',
        'composer.lock': 'php',
        'pom.xml': 'maven',
        'build.gradle': 'gradle',
        'Cargo.toml': 'rust',
        'Cargo.lock': 'rust',
    }


class NodeTaintRules:
    """Node.js/Express Taint Analysis Rules"""
    
    SOURCES = [
        'req.body', 'req.query', 'req.params', 'req.headers', 'req.cookies',
        'process.env', 'process.argv'
    ]
    
    SINKS = [
        # SQL Injection
        'sequelize.query', '.query', '.execute', '.raw', 'QueryTypes',
        # Command Injection
        'exec', 'spawn', 'execSync', 'spawnSync', 'child_process',
        # RCE / Code Injection
        'eval', 'setTimeout', 'setInterval', 'new Function', 'vm.runInContext',
        # Crypto
        'crypto.createCipher', 'jwt.sign',
        # File System
        'fs.readFile', 'fs.writeFile', 'fs.unlink'
    ]


# ==================== Data Classes ====================

@dataclass
class FileMetadata:
    """Metadata for prioritizing file scanning"""
    path: str
    priority_score: int
    file_type: str
    size: int = 0
    sha: str = ""

    def __lt__(self, other):
        """Enable sorting by priority (lower score is 'less')"""
        return self.priority_score < other.priority_score


@dataclass
class RateLimitInfo:
    """GitHub API rate limit tracking"""
    remaining: int
    limit: int
    reset_time: datetime

    @property
    def is_exhausted(self) -> bool:
        """Check if rate limit is critically low"""
        return self.remaining < GithubAgentConfig.RATE_LIMIT_BUFFER

    @property
    def seconds_until_reset(self) -> float:
        """Time until rate limit resets"""
        return max(0, (self.reset_time - datetime.now(timezone.utc)).total_seconds())


@dataclass
class SecretMatch:
    """Detected secret with metadata"""
    pattern_name: str
    value: str
    line_number: int
    entropy: float
    confidence: int
    high_confidence: bool


@dataclass
class CacheEntry:
    """Cache entry for file content"""
    content: str
    timestamp: datetime
    file_sha: str

    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        age = datetime.now(timezone.utc) - self.timestamp
        return age.total_seconds() > GithubAgentConfig.CACHE_TTL_SECONDS


# ==================== Main Agent Class ====================

# ==================== Main Agent Class ====================

class GithubSecurityAgent(BaseSecurityAgent):

    agent_name = "github_security"
    agent_description = "Analyzes GitHub repository source code with advanced detection"
    vulnerability_types = [
        VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
        VulnerabilityType.SQL_INJECTION,
        VulnerabilityType.XSS_STORED,
        VulnerabilityType.PATH_TRAVERSAL,
    ]

    # Files and directories to ignore
    IGNORE_EXTENSIONS = {
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.pdf',
        '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
        '.mp4', '.avi', '.mov', '.mp3', '.wav',
        '.exe', '.dll', '.so', '.dylib',
        '.woff', '.woff2', '.ttf', '.eot',
        '.min.js', '.min.css',  # Minified files
    }

    IGNORE_DIRS = {
        'node_modules', '.git', 'venv', '__pycache__',
        'dist', 'build', 'target', 'vendor',
        '.next', '.nuxt', 'coverage', '.pytest_cache',
        'migrations', 'locale', 'locales',
    }

    # File extensions by priority category
    CRITICAL_FILES = {'.env', '.env.local', '.env.production', 'secrets.json', 'credentials.json'}
    HIGH_PRIORITY_EXTENSIONS = {'.py', '.js', '.ts', '.tsx', '.jsx', '.go', '.java', '.php', '.rb', '.cs'}
    CONFIG_EXTENSIONS = {'.json', '.yml', '.yaml', '.toml', '.ini', '.conf', '.config', '.xml'}

    # Paths that indicate high-value files
    HIGH_VALUE_PATHS = ['auth', 'login', 'api', 'config', 'admin', 'security', 'payment', 'database', 'db']

    # Patterns for file classification (NEW - False Positive Fix)
    TEST_PATTERNS = [
        '/tests/', '/test/', '/__tests__/', '/spec/', '/specs/',
        'test_', '_test.', '.test.', '.spec.', 'mock_', 'fixture_'
    ]
    
    PAYLOAD_PATTERNS = [
        '/payloads/', '_payloads.', '/exploits/', '_exploits.'
    ]
    
    FIXTURE_PATTERNS = [
        'fixtures/', 'fixture_', '/mocks/', '/mock/'
    ]
    
    DOC_PATTERNS = [
        '/docs/', '/examples/', '/samples/', 'readme', '/documentation/'
    ]
    
    PRODUCTION_PATTERNS = [
        '/api/', '/routes/', '/controllers/', '/views/', '/models/',
        '/services/', '/handlers/', '/middleware/', '/core/',
        '/src/', '/app/', '/lib/', '/utils/', '/helpers/'
        # NOTE: /agents/ excluded - these are security testing tools, not application code
    ]
    
    # Additional patterns for scanner-specific files to skip
    SCANNER_INFRASTRUCTURE = [
        '/agents/', '/scanner/', '/tests/', '/benchmarks/'
    ]

    def _build_github_context(
            self,
            url: str,
            vulnerability_type: str,
            description: str,
            detection_method: str = "static_analysis",
            confidentiality_impact: str = "None",
            integrity_impact: str = "None",
            availability_impact: str = "None",
            metric_impact: float = 5.0,
            data_exposed: List[str] = None
    ) -> VulnerabilityContext:
        """Build VulnerabilityContext for GitHub findings."""
        # Map High/Low impacts to context fields for CVSS calculation
        exposed = list(data_exposed) if data_exposed else []
        modifiable = []
        disruption = False
        
        if confidentiality_impact and confidentiality_impact.lower() == "high":
            if "secrets" not in exposed: exposed.append("secrets")
            if "database" not in exposed: exposed.append("database")
            
        if integrity_impact and integrity_impact.lower() == "high":
            modifiable.append("filesystem")
            modifiable.append("database")
            
        if availability_impact and availability_impact.lower() == "high":
            disruption = True

        return VulnerabilityContext(
            vulnerability_type=vulnerability_type,
            detection_method=detection_method,
            endpoint=url,
            parameter="source_code",
            http_method="GET",
            requires_user_interaction=False,
            requires_authentication=False, # Code is accessible
            escapes_security_boundary=False,
            payload_succeeded=True,
            data_exposed=exposed,
            data_modifiable=modifiable,
            service_disruption_possible=disruption,
            additional_context={
                "description": description,
                "impact_level": metric_impact,
                "dos_severity": "complete" if disruption else "none"
            }
        )
    
    def _classify_file(self, file_path: str) -> Dict[str, Any]:
        """
        Classify file to determine if it should be scanned for vulnerabilities.
        Returns dict with: is_production, category, confidence
        """
        path_lower = file_path.lower()
        
        # Check if it's a test file (HIGHEST PRIORITY - most common false positives)
        if any(pattern in path_lower for pattern in self.TEST_PATTERNS):
            return {
                "is_production": False,
                "category": "test",
                "confidence": 0.95,
                "reason": "Test file pattern detected"
            }
        
        # Check if it's a payload definition file
        if any(pattern in path_lower for pattern in self.PAYLOAD_PATTERNS):
            return {
                "is_production": False,
                "category": "payload_definition",
                "confidence": 0.95,
                "reason": "Payload definition file"
            }
        
        # Check if it's a fixture
        if any(pattern in path_lower for pattern in self.FIXTURE_PATTERNS):
            return {
                "is_production": False,
                "category": "fixture",
                "confidence": 0.90,
                "reason": "Test fixture file"
            }
        
        # Check if it's scanner infrastructure (agents, scanner tools, benchmarks)
        if any(pattern in path_lower for pattern in self.SCANNER_INFRASTRUCTURE):
            return {
                "is_production": False,
                "category": "scanner_infrastructure",
                "confidence": 0.95,
                "reason": "Scanner/agent infrastructure file"
            }
        
        # Check if it's documentation
        if any(pattern in path_lower for pattern in self.DOC_PATTERNS):
            return {
                "is_production": False,
                "category": "documentation",
                "confidence": 0.85,
                "reason": "Documentation file"
            }
        
        # Check if it's production code
        if any(pattern in path_lower for pattern in self.PRODUCTION_PATTERNS):
            return {
                "is_production": True,
                "category": "production",
                "confidence": 0.90,
                "reason": "Production code pattern detected"
            }
        
        # Default: assume production but with lower confidence
        return {
            "is_production": True,
            "category": "unknown",
            "confidence": 0.60,
            "reason": "No definitive pattern, assuming production"
        }

    def __init__(self, github_token: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.github_token = github_token
        self.rate_limit_info: Optional[RateLimitInfo] = None
        self.file_cache: Dict[str, CacheEntry] = {}
        self.vulnerability_db_cache: Dict[str, List[Dict]] = {}

        # Concurrency Control for AI
        self._ai_semaphore = asyncio.Semaphore(1)

        # Statistics
        self.stats = {
            'files_scanned': 0,
            'secrets_found': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'api_calls': 0,
            'ai_calls': 0
        }

    # ==================== Main Scan Entry Point ====================

    async def scan(
            self,
            target_url: str,
            endpoints: List[Dict[str, Any]] = None,
            technology_stack: List[str] = None,
            scan_context: Optional["ScanContext"] = None
    ) -> List[AgentResult]:
        """
        Scan a GitHub repository with enhanced capabilities.
        """
        import json
        results = []
        repo_info = self._parse_github_url(target_url)

        if not repo_info:
            logger.error(f"Invalid GitHub URL: {target_url}")
            return []

        owner, repo = repo_info
        logger.info(f"Starting optimized scan of repository: {owner}/{repo}")

        try:
            # 1. Get default branch
            default_branch = await self._get_default_branch(owner, repo)
            
            # 2. Reconnaissance
            files = await self._fetch_repo_files(owner, repo, default_branch)
            if not files:
                return []

            # 3. AI Hotspot Detection
            logger.info("Step 1/4: Identifying high-risk hotspots via AI...")
            raw_hotspots = await self._get_hotspots_via_ai(files, owner, repo, default_branch)
            hotspots = {h.strip('/') for h in raw_hotspots}
            logger.info(f"AI identified {len(hotspots)} potential hotspots")

            # 4. Static Scan + Content Fetching
            limit = GithubAgentConfig.MAX_FILES_TO_SCAN
            logger.info("Step 2/4: Running static security scan...")
            priority_metadata = self._prioritize_files(files, hotspots)
            files_to_scan = priority_metadata[:limit]
            
            # Populate scanned files in context early so frontend can show them
            if scan_context:
                scan_context.scanned_files = [f.path for f in files_to_scan]

            static_results, hotspot_data = await self._scan_files_batch(
                owner, repo, default_branch, files_to_scan, hotspots
            )
            results.extend(static_results)


            # 5. Batch AI Analysis for Hotspots
            if hotspot_data and groq_manager.is_configured:
                logger.info(f"Step 3/4: Performing deep AI analysis on {len(hotspot_data)} hotspots (batched)...")
                ai_results = await self._ai_analysis_batch(hotspot_data, owner, repo, default_branch)
                results.extend(ai_results)
            else:
                logger.info("Step 3/4: Skipping deep AI analysis (no hotspots or Groq not configured)")

            # 6. Dependency scanning
            if GithubAgentConfig.ENABLE_DEPENDENCY_SCAN:
                logger.info("Step 4/4: Scanning dependencies for vulnerabilities...")
                dep_results = await self._scan_dependencies(owner, repo, default_branch, files)
                results.extend(dep_results)

            self._log_scan_statistics(owner, repo)

        except Exception as e:
            logger.error(f"Error scanning repository {owner}/{repo}: {e}", exc_info=True)

        return results

    def _parse_github_url(self, url: str) -> Optional[Tuple[str, str]]:
        """Parse owner and repo from GitHub URL."""
        try:
            parsed = urlparse(url)
            path_parts = [p for p in parsed.path.split('/') if p]
            if len(path_parts) >= 2:
                return path_parts[0], path_parts[1]
            return None
        except Exception:
            return None

    def _is_interesting_for_ai(self, file_path: str) -> bool:
        """Filter files for AI analysis based on extension."""
        interesting_exts = {
            '.js', '.jsx', '.ts', '.tsx',  # JavaScript/TypeScript
            '.py',                         # Python
            '.go',                         # Go
            '.java',                       # Java
            '.php',                        # PHP
            '.rb',                         # Ruby
            '.c', '.cpp', '.h',            # C/C++
            '.cs',                         # C#
            '.sh', '.bash',                # Shell
            '.yml', '.yaml', '.json'       # Config
        }
        return any(file_path.lower().endswith(ext) for ext in interesting_exts)

    def _get_cached_content(self, file_path: str, sha: str) -> Optional[str]:
        """Retrieve local cached content if available and valid."""
        if not GithubAgentConfig.ENABLE_CACHE:
            return None
            
        entry = self.file_cache.get(file_path)
        if entry:
            if entry.file_sha == sha and not entry.is_expired():
                self.stats['cache_hits'] += 1
                return entry.content
            # Invalid or expired
            del self.file_cache[file_path]
            
        self.stats['cache_misses'] += 1
        return None

    def _cache_content(self, file_path: str, content: str, sha: str) -> None:
        """Cache file content locally."""
        if not GithubAgentConfig.ENABLE_CACHE:
            return

        self.file_cache[file_path] = CacheEntry(
            content=content,
            timestamp=datetime.now(timezone.utc),
            file_sha=sha
        )

    # ==================== GitHub API Methods ====================

    async def _get_default_branch(self, owner: str, repo: str) -> str:
        """
        Dynamically detect the repository's default branch.
        """
        url = f"https://api.github.com/repos/{owner}/{repo}"

        try:
            async with httpx.AsyncClient() as client:
                response = await self._make_github_request(client, url)
                if response and response.status_code == 200:
                    data = response.json()
                    return data.get('default_branch', 'main')
        except Exception as e:
            logger.warning(f"Could not detect default branch, using 'main': {e}")

        return 'main'

    async def _fetch_repo_files(
            self,
            owner: str,
            repo: str,
            branch: str
    ) -> List[Dict[str, Any]]:
        """
        Fetch recursive file list from GitHub API.
        """
        url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"

        try:
            async with httpx.AsyncClient() as client:
                response = await self._make_github_request(client, url)

                if not response or response.status_code != 200:
                    logger.error(f"Failed to fetch file list: {response.status_code if response else 'No response'}")
                    return []

                data = response.json()
                files = [f for f in data.get('tree', []) if f['type'] == 'blob']

                logger.info(f"Retrieved {len(files)} files from repository")
                return files

        except Exception as e:
            logger.error(f"Error fetching file list: {e}")
            return []

    async def _make_github_request(
            self,
            client: httpx.AsyncClient,
            url: str,
            retry_count: int = 0
    ) -> Optional[httpx.Response]:
        """
        Make a GitHub API request with rate limiting and retry logic.
        """
        headers = {'Accept': 'application/vnd.github.v3+json'}

        if self.github_token:
            headers['Authorization'] = f'token {self.github_token}'

        # Check rate limit before making request
        if self.rate_limit_info and self.rate_limit_info.is_exhausted:
            wait_time = self.rate_limit_info.seconds_until_reset
            logger.warning(f"Rate limit exhausted. Waiting {wait_time:.0f} seconds...")
            await asyncio.sleep(wait_time + 1)

        try:
            self.stats['api_calls'] += 1
            response = await client.get(
                url,
                headers=headers,
                timeout=GithubAgentConfig.DEFAULT_TIMEOUT
            )

            # Update rate limit info
            self._update_rate_limit_info(response)

            # Handle rate limiting
            if response.status_code == 403 and 'rate limit' in response.text.lower():
                if retry_count < GithubAgentConfig.MAX_RETRIES:
                    wait_time = self.rate_limit_info.seconds_until_reset if self.rate_limit_info else 60
                    logger.warning(f"Rate limited. Waiting {wait_time:.0f}s before retry {retry_count + 1}")
                    await asyncio.sleep(wait_time + 1)
                    return await self._make_github_request(client, url, retry_count + 1)
                else:
                    logger.error("Max retries exceeded for rate limiting")
                    return None

            # Handle other errors with exponential backoff
            if response.status_code >= 500 and retry_count < GithubAgentConfig.MAX_RETRIES:
                wait_time = GithubAgentConfig.RETRY_BACKOFF_BASE ** retry_count
                logger.warning(f"Server error {response.status_code}. Retrying in {wait_time}s...")
                await asyncio.sleep(wait_time)
                return await self._make_github_request(client, url, retry_count + 1)

            return response

        except httpx.TimeoutException:
            if retry_count < GithubAgentConfig.MAX_RETRIES:
                logger.warning(f"Request timeout. Retry {retry_count + 1}/{GithubAgentConfig.MAX_RETRIES}")
                await asyncio.sleep(GithubAgentConfig.RETRY_BACKOFF_BASE ** retry_count)
                return await self._make_github_request(client, url, retry_count + 1)
            logger.error("Request timeout after max retries")
            return None

        except Exception as e:
            logger.error(f"Error making GitHub request: {e}")
            return None

    def _update_rate_limit_info(self, response: httpx.Response) -> None:
        """Update rate limit tracking from response headers"""
        try:
            remaining = int(response.headers.get('X-RateLimit-Remaining', 5000))
            limit = int(response.headers.get('X-RateLimit-Limit', 5000))
            reset_timestamp = int(response.headers.get('X-RateLimit-Reset', 0))

            self.rate_limit_info = RateLimitInfo(
                remaining=remaining,
                limit=limit,
                reset_time=datetime.fromtimestamp(reset_timestamp)
            )

            if remaining < 100:
                logger.warning(f"GitHub API rate limit low: {remaining}/{limit} remaining")

        except (ValueError, TypeError) as e:
            logger.debug(f"Could not parse rate limit headers: {e}")

    # ==================== AI Analysis & Batching ====================

    async def _ai_analysis_batch(
            self,
            hotspot_data: List[Dict[str, str]],
            owner: str,
            repo: str,
            branch: str
    ) -> List[AgentResult]:
        logger.info(f"DEBUG: Starting AI analysis batch with {len(hotspot_data)} items")
        all_results = []
        
        # Batching parameters (Optimized for Free Tier)
        MAX_FILES_PER_BATCH = 2
        MAX_CHARS_PER_BATCH = 30000 
        MAX_FILE_CHARS = 3000
        
        current_batch = []
        current_chars = 0
        
        batches = []
        for item in hotspot_data:
            # Truncate file content to stay within token limits
            truncated_content = item['content'][:MAX_FILE_CHARS]
            content_len = len(truncated_content)
            
            if (len(current_batch) >= MAX_FILES_PER_BATCH or 
                current_chars + content_len > MAX_CHARS_PER_BATCH) and current_batch:
                batches.append(current_batch)
                current_batch = []
                current_chars = 0
                
            current_batch.append({
                'path': item['path'],
                'content': truncated_content
            })
            current_chars += content_len
            
        if current_batch:
            batches.append(current_batch)
            
        logger.info(f"Processing {len(batches)} AI batches for {len(hotspot_data)} files")
        
        for idx, batch in enumerate(batches):
            try:
                logger.info(f"Analyzing AI batch {idx+1}/{len(batches)} ({len(batch)} files)")
                batch_results = await self._analyze_batch_single_call(batch, owner, repo, branch)
                all_results.extend(batch_results)
            except Exception as e:
                logger.error(f"Error in AI batch {idx+1}: {e}")
                
        return all_results

    async def _analyze_batch_single_call(
            self,
            batch: List[Dict[str, str]],
            owner: str,
            repo: str,
            branch: str
    ) -> List[AgentResult]:
        """Make a single AI call for a batch of files"""
        import json
        results = []
        
        # Construct combined prompt
        files_summary = "\n".join([f"- {f['path']} ({len(f['content'])} chars)" for f in batch])
        
        # Classify files and add context
        file_classifications = []
        for f in batch:
            classification = self._classify_file(f['path'])
            status = "⚠️ NON-PRODUCTION" if not classification["is_production"] else "✓ PRODUCTION"
            file_classifications.append(f"{status} | {f['path']} ({classification['category']})")
        
        files_content = ""
        for f in batch:
            files_content += f"\n--- FILE: {f['path']} ---\n{f['content']}\n"
            
        prompt = f"""
CRITICAL INSTRUCTION: You are analyzing SOURCE CODE of a security scanner application called Matrix.

CONTEXT AWARENESS RULES (MOST IMPORTANT):
1. Files in tests/, test_*.py, *_test.py, fixtures/ → These are TEST CODE, NOT production vulnerabilities
2. Files in scanner/payloads/, *_payloads.py → These define ATTACK PAYLOADS for testing targets, NOT vulnerabilities in Matrix
3. Files in agents/, scanner/ → These are SECURITY TESTING TOOLS (the scanner itself), NOT application code
4. Test endpoint URLs like "dvwa/vulnerabilities/sqli" are TARGET APPLICATIONS to scan, NOT Matrix code
5. SQLAlchemy ORM (db.query(), filter(), session.execute(select())) → This is PARAMETERIZED and SAFE, NOT SQL injection
6. Jinja2 with auto_escape=True → This is SAFE, NOT XSS
7. Enum definitions (VulnerabilityType.XSS_REFLECTED) → These are TYPE DEFINITIONS, NOT vulnerabilities
8. ONLY flag vulnerabilities in USER-FACING APPLICATION code (api/auth.py, api/scans.py, api/vulnerabilities.py)

WHAT TO IGNORE:
✗ Enum definitions containing vulnerability names (e.g., "class VulnerabilityType(Enum): SQL_INJECTION = ...")
✗ Security agent files that test for vulnerabilities (agents/auth_agent.py, agents/sql_agent.py)
✗ Model files that just define database schemas with SQLAlchemy
✗ Files marked as NON-PRODUCTION in classification below

FILE CLASSIFICATION:
{chr(10).join(file_classifications)}

FILES TO ANALYZE:
{files_summary}

SOURCE CODE:
{files_content}

DETECTION RULES - READ CAREFULLY:
✗ DO NOT flag test files, fixtures, payload definitions, or scanner infrastructure  
✗ DO NOT flag enum definitions as vulnerabilities
✗ DO NOT flag SQLAlchemy ORM usage as SQL injection
✗ DO NOT flag security testing agent code as vulnerabilities
✗ DO NOT flag model schema definitions
✓ ONLY report vulnerabilities with HIGH CONFIDENCE (≥70%) in USER-FACING API code
✓ ONLY report exploitable vulnerabilities with clear attack paths in public endpoints


Return a JSON object with this structure:
{{
  "vulnerabilities": [
    {{
      "file": "path/to/file",
      "type": "Vulnerability Type",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "line": 123,
      "title": "Short Title",
      "description": "Details",
      "fix": "How to fix",
      "confidence": 85
    }}
  ]
}}
"""
        
        # Inject Taint Analysis Instructions for Node.js
        if any(f['path'].endswith(('.js', '.ts', '.jsx', '.tsx')) for f in batch):
            prompt += """
TAINT ANALYSIS INSTRUCTION (Node.js/Express):
1. Identify SOURCES (User Input): req.body, req.query, req.params, req.headers.
2. Identify SINKS (Execution): sequelize.query, exec, eval, new Function, fs.*.
3. Trace data flow from SOURCES to SINKS.
4. Flag a vulnerability ONLY if user input reaches a sink without proper sanitization.
5. Watch out for 'concatenation SQLi' (e.g. "SELECT * FROM users WHERE email = '" + req.body.email + "'").
6. Watch out for 'command injection' (e.g. exec("ping " + host)).
"""
        
        # Inject Python-specific ORM Pattern Detection
        if any(f['path'].endswith('.py') for f in batch):
            prompt += """
PYTHON-SPECIFIC RULES:
1. SQLAlchemy ORM is SAFE: db.query(User).filter(User.id == user_id) → NOT SQL injection
2. Django ORM is SAFE: User.objects.filter(id=user_id) → NOT SQL injection  
3. ONLY flag SQLi if you see string concatenation: cursor.execute("SELECT * FROM users WHERE id=" + user_id)

"""
        
        system_prompt = "You are a senior security researcher. Provide deep logic review. Output ONLY valid JSON."
        
        async with self._ai_semaphore:
            self.stats['ai_calls'] += 1
            response = await repo_generate(
                prompt=prompt,
                system_prompt=system_prompt,
                tier=ModelTier.LARGE_CONTEXT, # Use large context for batches
                json_mode=True,
                max_tokens=512,
                temperature=0.1
            )
        
        try:
            content_str = response.get('content', '{}')
            
            # Robust JSON extraction
            import re
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', content_str, re.DOTALL)
            if not json_match:
                json_match = re.search(r'(\{.*\})', content_str, re.DOTALL)
            
            if json_match:
                content_str = json_match.group(1)
                
            data = json.loads(content_str)
            vulns = data.get('vulnerabilities', [])
            
            # Confidence threshold for filtering (NEW - False Positive Fix)
            MIN_CONFIDENCE_THRESHOLD = 70
            
            for v in vulns:
                confidence_score = v.get('confidence', 0)
                
                # Skip low confidence findings
                if confidence_score < MIN_CONFIDENCE_THRESHOLD:
                    logger.info(f"⊘ Skipping low confidence finding ({confidence_score}%): {v.get('title')}")
                    continue
                
                file_path = v.get('file', batch[0]['path'])
                
                # Additional check: Skip if file is not production code (NEW - False Positive Fix)
                classification = self._classify_file(file_path)
                if not classification["is_production"]:
                    logger.info(f"⊘ Skipping non-production file: {file_path} ({classification['category']})")
                    continue
                
                # Additional check: Skip enum definition findings (FINAL FIX)
                # AI sometimes flags enum names like "VulnerabilityType.SQL_INJECTION" as vulnerabilities
                vuln_type_str = v.get('type', '')
                vuln_desc = v.get('description', '')
                vuln_title = v.get('title', '')
                
                if 'VulnerabilityType' in vuln_type_str or \
                   'VulnerabilityType' in vuln_desc or \
                   ('enum' in vuln_desc.lower() and 'definition' in vuln_desc.lower()):
                    logger.info(f"⊘ Skipping enum definition finding: {v.get('title')} (type: {vuln_type_str})")
                    continue
                
                vuln_type = self._map_vuln_type(v.get('type'))
                
                # Determine context based on AI output
                confidentiality = "High" if "sensitive" in v.get('type', '').lower() or "secret" in v.get('type', '').lower() else "Low"
                integrity = "High" if "injection" in v.get('type', '').lower() else "Low"
                
                logger.info(f"✓ Accepted finding: {v.get('title')} (confidence={confidence_score}%, file={file_path})")
                
                results.append(self.create_result(
                    vulnerability_type=vuln_type,
                    is_vulnerable=True,
                    severity=self._map_severity(v.get('severity')),
                    confidence=self.calculate_confidence(
                        ConfidenceMethod.GENERIC_ERROR_OR_AI,
                        evidence_quality=min(float(v.get('confidence', 50)) / 100.0, 1.0)
                    ),
                    url=f"https://github.com/{owner}/{repo}/blob/{branch}/{file_path}#L{v.get('line', 1)}",
                    file_path=file_path,
                    title=v.get('title', 'Security Finding'),
                    description=v.get('description', ''),
                    evidence=v.get('evidence', f"Found in {file_path}"),
                    remediation=v.get('fix', ''),
                    ai_analysis=json.dumps(v),
                    vulnerability_context=self._build_github_context(
                        f"https://github.com/{owner}/{repo}/blob/{branch}/{file_path}",
                        vuln_type,
                        v.get('description', ''),
                        "ai_code_analysis",
                        confidentiality_impact=confidentiality,
                        integrity_impact=integrity,
                        metric_impact=7.0 # AI typically checks logical flaws
                    )
                ))
        except Exception as e:
            print(f"DEBUG EXCEPTION: {e}")
            logger.error(f"Failed to parse AI batch response: {e}")
            
        return results

    async def _ai_analysis(
            self,
            content: str,
            file_path: str,
            owner: str,
            repo: str,
            branch: str
    ) -> List[AgentResult]:
        """Legacy helper for single file analysis (rarely used now)"""
        return await self._analyze_batch_single_call([{"path": file_path, "content": content}], owner, repo, branch)

    async def _get_hotspots_via_ai(
            self,
            files: List[Dict[str, Any]],
            owner: str,
            repo: str,
            branch: str
    ) -> List[str]:
        import json
        
        # Filter for files that are actually interesting for AI logic audit
        file_paths = [f['path'] for f in files if self._is_interesting_for_ai(f['path'])]
        
        # If no interesting files found, fallback to scannable files
        if not file_paths:
            logger.info("DEBUG: No interesting files found for AI")
            file_paths = [f['path'] for f in files if self._is_scannable_file(f['path'])]
            logger.info(f"DEBUG: Fallback to scannable files: {len(file_paths)}")

        # If repo is small, we can just treat everything as a hotspot (up to a limit)
        if len(file_paths) < 15:
            logger.info(f"DEBUG: Small repo, returning all {len(file_paths)} files as hotspots")
            return file_paths[:15]
            
        # Get README content if available for context
        readme_content = ""
        for f in files:
            if f['path'].lower().endswith('readme.md'):
                try:
                    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{f['path']}"
                    async with httpx.AsyncClient() as client:
                        resp = await client.get(url, timeout=5)
                        if resp.status_code == 200:
                            readme_content = resp.text[:2000] # First 2k chars
                except Exception:
                    pass
                break

            if f['path'].lower() == 'readme.md':
                # We need content. If it's not fetched yet, we can't use it easily in this phase 
                # without extra API call. For now, assume we might have it or skip.
                # Actually, in _fetch_repo_files we only got metadata. 
                # So we'll skip detailed README content unless we fetch it.
                # To save time/tokens, we'll just use filenames.
                pass
                
        # Optimization: Only send the file paths, not full dicts, to save tokens
        # Sort by depth (shallower files often architecture definers)
        files_sorted = sorted(file_paths, key=lambda p: p.count('/'))
        
        # Limit to top 300 most likely relevant files for the prompt
        truncated_list = files_sorted[:300]

        prompt = f"""
You are a security auditor. 
Repo: {owner}/{repo} (Branch: {branch})

Task: Select top 10 files most likely to contain security vulnerabilities (Auth, API, Secrets, SQL).
File List:
{json.dumps(truncated_list)}

Return a JSON object with this key "hotspots" containing a list of strings: {{"hotspots": ["path/to/file1", "path/to/file2"]}}
"""

        system_prompt = "You are a senior security architect. Identify high-risk attack surfaces."

        async with self._ai_semaphore:
            self.stats['ai_calls'] += 1
            response = await repo_generate(
                prompt=prompt,
                system_prompt=system_prompt,
                tier=ModelTier.FAST, # Use Fast model for this listing task
                json_mode=True,
                max_tokens=256,
                temperature=0.1
            )
            
        try:
            content_str = response.get('content', '{}')
            
            # Robust JSON extraction
            import re
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', content_str, re.DOTALL)
            if not json_match:
                json_match = re.search(r'(\{.*\})', content_str, re.DOTALL)
            
            if json_match:
                content_str = json_match.group(1)
                
            data = json.loads(content_str)
            return data.get('hotspots', [])
        except Exception as e:
            logger.error(f"Failed to parse Hotspot AI response: {e}")
            return file_paths[:10] # Fallback
    def _calculate_file_priority(self, path: str) -> int:
        """Calculate priority score for a file"""
        score = 0
        path_lower = path.lower()
        filename = path_lower.split('/')[-1]

        # 1. Critical Checks (Immediate Return)
        if filename in self.CRITICAL_FILES:
            return GithubAgentConfig.PRIORITY_CRITICAL

        # 2. Assign Base Score by Extension/Type
        if filename in DependencyFile.PACKAGE_FILES:
            score = GithubAgentConfig.PRIORITY_HIGH
        elif any(path_lower.endswith(e) for e in self.CONFIG_EXTENSIONS):
            score = GithubAgentConfig.PRIORITY_MEDIUM
        # Boost JS/TS files for Node sink analysis
        elif any(path_lower.endswith(e) for e in ['.js', '.ts', '.jsx', '.tsx']):
            score = 75 
        elif any(path_lower.endswith(e) for e in self.HIGH_PRIORITY_EXTENSIONS):
            score = GithubAgentConfig.PRIORITY_MEDIUM
        elif any(x in path_lower for x in ['test', 'spec', '__test__']):
            score = GithubAgentConfig.PRIORITY_MINIMAL
        elif path_lower.endswith('.md') or 'doc' in path_lower:
            score = GithubAgentConfig.PRIORITY_MINIMAL
        else:
            score = GithubAgentConfig.PRIORITY_LOW

        # 3. Context Modifiers
        # If the file is in a high-value path (api, auth, etc.), ensure it's at least HIGH priority
        if any(hvp in path_lower for hvp in self.HIGH_VALUE_PATHS):
            score = max(score, GithubAgentConfig.PRIORITY_HIGH)

        # Boost root files or config directories
        if path.count('/') <= 1 or '/config/' in path_lower:
            score += 10

        return min(score, 100)

    def _prioritize_files(self, files: List[Dict[str, Any]], hotspots: Set[str] = None) -> List[FileMetadata]:
        """
        Intelligently prioritize files for scanning based on security value.
        """
        priority_files = []
        hotspots = hotspots or set()
        
        for file_info in files:
            path = file_info.get('path', '')
            score = self._calculate_file_priority(path)
            
            # Boost score for AI-identified hotspots
            if path.strip('/') in hotspots:
                score = max(score, 95)
            
            priority_files.append(FileMetadata(
                path=path,
                priority_score=score,
                file_type=file_info.get('type', 'blob'),
                size=file_info.get('size', 0),
                sha=file_info.get('sha', '')
            ))
            
        # Sort by priority score descending
        priority_files.sort(reverse=True)
        return priority_files

    def _is_scannable_file(self, path: str) -> bool:
        ext = path.split('.')[-1].lower() if '.' in path else 'unknown'
        return ext

    # ==================== File Scanning ====================

    async def _scan_files_batch(
            self,
            owner: str,
            repo: str,
            branch: str,
            files: List[FileMetadata],
            hotspots: Set[str] = None
    ) -> Tuple[List[AgentResult], List[Dict[str, str]]]:
        results = []
        hotspot_data = []
        hotspots = hotspots or set()

        # Process files in batches to control concurrency
        for i in range(0, len(files), GithubAgentConfig.CONCURRENT_FILE_LIMIT):
            batch = files[i:i + GithubAgentConfig.CONCURRENT_FILE_LIMIT]

            tasks = []
            for file_meta in batch:
                is_hs = file_meta.path.strip('/') in hotspots
                tasks.append(
                    self._analyze_file(owner, repo, branch, file_meta, is_hotspot=is_hs)
                )

            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"File analysis error: {result}")
                elif isinstance(result, tuple):
                    res, hs_info = result
                    results.extend(res)
                    if hs_info:
                        hotspot_data.append(hs_info)

            # Small delay between batches to be nice to GitHub
            if i + GithubAgentConfig.CONCURRENT_FILE_LIMIT < len(files):
                await asyncio.sleep(0.5)

        return results, hotspot_data

    async def _analyze_file(
            self,
            owner: str,
            repo: str,
            branch: str,
            file_meta: FileMetadata,
            is_hotspot: bool = False
    ) -> Tuple[List[AgentResult], Optional[Dict[str, str]]]:
        results = []
        file_path = file_meta.path

        if file_meta.size > GithubAgentConfig.MAX_FILE_SIZE_BYTES:
            return [], None

        content = self._get_cached_content(file_path, file_meta.sha)

        if content is None:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(raw_url, timeout=GithubAgentConfig.DEFAULT_TIMEOUT)
                    if response.status_code != 200:
                        return [], None
                    content = response.text
                    self._cache_content(file_path, content, file_meta.sha)
                    self.stats['cache_misses'] += 1
            except Exception as e:
                logger.error(f"Error downloading {file_path}: {e}")
                return [], None
        else:
            self.stats['cache_hits'] += 1

        # 1. Static Secret scanning (Always run)
        try:
            secret_results = self._scan_for_secrets(content, owner, repo, branch, file_path)
            results.extend(secret_results)
            self.stats['files_scanned'] += 1
        except Exception as e:
            logger.error(f"Error in static analysis for {file_path}: {e}")

        # 2. Return content for hotspot analysis (if flagged)
        hotspot_info = None
        if is_hotspot:
            # Skip lockfiles and very large files for AI
            if not any(file_path.endswith(ext) for ext in ['.lock', '-lock.json', '.lockb', '.yaml', '.yml']):
                hotspot_info = {"path": file_path, "content": content[:50000]} # Limit individual file size for AI

        return results, hotspot_info

    # ==================== Secret Detection ====================

    def _scan_for_secrets(
            self,
            content: str,
            owner: str,
            repo: str,
            branch: str,
            file_path: str
    ) -> List[AgentResult]:
        results = []
        secrets_found = []

        for pattern, name, high_confidence in SecretPattern.PATTERNS:
            matches = re.finditer(pattern, content, re.MULTILINE)

            for match in matches:
                secret_value = match.group(0)
                line_num = content[:match.start()].count('\n') + 1

                # Calculate entropy for additional validation
                entropy = self._calculate_entropy(secret_value)

                # Validate secret
                if not self._is_valid_secret(secret_value, entropy, high_confidence):
                    continue

                # Check if it's a false positive (test/example data)
                if self._is_false_positive_secret(secret_value, content, file_path):
                    continue

                # Calculate confidence score
                confidence = self._calculate_secret_confidence(
                    secret_value,
                    entropy,
                    high_confidence,
                )

                secret_match = SecretMatch(
                    pattern_name=name,
                    value=secret_value,
                    line_number=line_num,
                    entropy=entropy,
                    confidence=confidence,
                    high_confidence=high_confidence
                )

                secrets_found.append(secret_match)

        # Create vulnerability results
        for secret in secrets_found:
            results.append(self.create_result(
                vulnerability_type=VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                is_vulnerable=True,
                severity=self._determine_secret_severity(secret),
                confidence=secret.confidence,
                url=f"https://github.com/{owner}/{repo}/blob/{branch}/{file_path}#L{secret.line_number}",
                title=f"Exposed Secret: {secret.pattern_name}",
                description=(
                    f"A hardcoded secret ({secret.pattern_name}) was detected in {file_path} "
                    f"at line {secret.line_number}. This secret should be immediately revoked "
                    f"and moved to a secure secret management system."
                ),
                evidence=self._obfuscate_secret(secret.value),
                remediation=(
                    "1. IMMEDIATELY revoke this secret in the service provider\n"
                    "2. Remove the secret from the repository (including git history)\n"
                    "3. Use environment variables or a secret management service:\n"
                    "   - GitHub Secrets (for CI/CD)\n"
                    "   - AWS Secrets Manager\n"
                    "   - HashiCorp Vault\n"
                    "   - Azure Key Vault\n"
                    "4. Never commit secrets to version control"
                ),
                owasp_category="A01:2021 – Broken Access Control",
                cwe_id="CWE-798",
                ai_analysis=f"Entropy: {secret.entropy:.2f} | Confidence: {secret.confidence}%",
                vulnerability_context=self._build_github_context(
                    file_path, "sensitive_data_exposure",
                    f"Exposed secret: {secret.pattern_name}",
                    "regex_entropy",
                    confidentiality_impact="High",
                    metric_impact=9.0 if self._determine_secret_severity(secret) == Severity.CRITICAL else 7.0,
                    data_exposed=[secret.pattern_name]
                )
            ))

            self.stats['secrets_found'] += 1

        return results

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0

        # Count character frequencies
        frequencies = defaultdict(int)
        for char in text:
            frequencies[char] += 1

        # Calculate Shannon entropy
        entropy = 0.0
        text_len = len(text)

        for count in frequencies.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)

        return entropy

    def _is_valid_secret(self, secret: str, entropy: float, high_confidence: bool) -> bool:
        secret_lower = secret.lower()
        file_path_lower = file_path.lower()

        # Test/example files
        if any(indicator in file_path_lower for indicator in ['test', 'example', 'sample', 'mock', 'demo', 'fixture']):
            return True

        # Common placeholder patterns
        placeholders = [
            'example', 'sample', 'test', 'dummy', 'fake', 'mock',
            'placeholder', 'your_key_here', 'insert_key', 'xxx',
            'yyy', 'zzz', '12345', 'abcde'
        ]

        if any(placeholder in secret_lower for placeholder in placeholders):
            return True

        # Check context around the secret
        secret_index = content.find(secret)
        if secret_index != -1:
            # Get surrounding context (50 chars before and after)
            start = max(0, secret_index - 50)
            end = min(len(content), secret_index + len(secret) + 50)
            context = content[start:end].lower()

            # Check for example/test indicators in context
            if any(indicator in context for indicator in ['example', 'test', 'sample', 'demo']):
                return True

        return False

    def _calculate_secret_confidence(
            self,
            secret: str,
            entropy: float,
            high_confidence: bool,
            file_path: str
    ) -> int:
        # Critical cloud provider keys and payment keys
        critical_types = [
            'AWS Access Key', 'AWS Secret Key',
            'Stripe Live Secret Key', 'Private Key',
            'OpenSSH Private Key'
        ]

        if any(ct in secret.pattern_name for ct in critical_types):
            return Severity.CRITICAL

        # High: API keys and access tokens
        if secret.confidence >= 90:
            return Severity.HIGH

        if secret.confidence >= 70:
            return Severity.MEDIUM

        return Severity.LOW

    def _obfuscate_secret(self, secret: str) -> str:
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

    def _determine_secret_severity(self, secret: SecretMatch) -> str:
        if secret.pattern_name == "Private Key" or secret.pattern_name == "AWS Secret Key":
            return Severity.CRITICAL
        if secret.confidence >= 90:
            return Severity.CRITICAL
        if secret.confidence >= 70:
            return Severity.MEDIUM
        return Severity.LOW

    def _map_vuln_type(self, type_str: str) -> str:
        type_str = type_str.lower()
        if 'sql' in type_str: return VulnerabilityType.SQL_INJECTION
        if 'xss' in type_str: return VulnerabilityType.XSS_REFLECTED
        if 'rce' in type_str or 'command' in type_str: return VulnerabilityType.OS_COMMAND_INJECTION
        if 'path' in type_str or 'traversal' in type_str: return VulnerabilityType.PATH_TRAVERSAL
        if 'secret' in type_str or 'sensitive' in type_str: return VulnerabilityType.SENSITIVE_DATA_EXPOSURE
        if 'auth' in type_str: return VulnerabilityType.BROKEN_AUTH
        return VulnerabilityType.SECURITY_MISCONFIG

    def _map_severity(self, sev_str: str) -> str:
        if not sev_str: return Severity.MEDIUM
        mapping = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO
        }
        return mapping.get(sev_str.lower(), Severity.MEDIUM)

    async def _fetch_file_content(
            self,
            owner: str,
            repo: str,
            file_path: str,
            branch: str
    ) -> Optional[str]:
        """Fetch raw file content from GitHub."""
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=GithubAgentConfig.DEFAULT_TIMEOUT)
                if response.status_code == 200:
                    return response.text
                return None
        except Exception as e:
            logger.error(f"Failed to fetch {file_path}: {e}")
            return None

    async def _check_dependency_vulnerabilities(
            self,
            dependencies: List[Any], # List[ParsedDependency]
            ecosystem: str,
            owner: str,
            repo: str,
            branch: str,
            file_path: str
    ) -> List[AgentResult]:
        """Check against OSV API."""
        results = []
        batch_size = 50
        
        for i in range(0, len(dependencies), batch_size):
            batch = dependencies[i:i + batch_size]
            queries = []
            
            for dep in batch:
                osv_eco = self._map_ecosystem_to_osv(ecosystem)
                if not osv_eco: continue
                
                # Handle ParsedDependency objects
                name = dep.name if hasattr(dep, 'name') else dep.get('name')
                version = dep.version if hasattr(dep, 'version') else dep.get('version')
                
                if not name or not version: continue

                queries.append({
                    "package": {
                        "name": name,
                        "ecosystem": osv_eco
                    },
                    "version": version
                })
            
            if not queries: continue

            logger.debug(f"OSV Query Batch Size: {len(queries)}")

            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        GithubAgentConfig.OSV_API_URL, 
                        json={"queries": queries}, 
                        timeout=GithubAgentConfig.DEFAULT_TIMEOUT
                    )
                    
                    logger.debug(f"OSV Response Code: {resp.status_code}")
                    if resp.status_code == 200:
                        data = resp.json()
                        for idx, res in enumerate(data.get("results", [])):
                            if "vulns" in res:
                                dep = batch[idx]
                                dep_name = dep.name if hasattr(dep, 'name') else dep.get('name')
                                dep_ver = dep.version if hasattr(dep, 'version') else dep.get('version')
                                
                                for vuln in res["vulns"]:
                                    results.append(self._create_dependency_finding(
                                        vuln, dep_name, dep_ver, owner, repo, branch, file_path
                                    ))
            except Exception as e:
                logger.error(f"OSV check failed: {e}")
                
        return results

    def _map_ecosystem_to_osv(self, eco: str) -> Optional[str]:
        mapping = {
            'npm': 'npm',
            'pip': 'PyPI',
            'go': 'Go',
            'maven': 'Maven',
            'gem': 'RubyGems',
            'cargo': 'Crates.io',
            'nuget': 'NuGet',
            'composer': 'Packagist'
        }
        return mapping.get(eco)

    def _create_dependency_finding(self, vuln: Dict, dep_name: str, dep_version: str, owner: str, repo: str, branch: str, file_path: str) -> AgentResult:
        summary = vuln.get('summary', 'Unknown vulnerability')
        details = vuln.get('details', '')
        
        return self.create_result(
            vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
            is_vulnerable=True,
            severity=Severity.HIGH, 
            confidence=100.0,
            url=f"https://github.com/{owner}/{repo}/blob/{branch}/{file_path}",
            title=f"Vulnerable Dependency: {dep_name} ({summary})",
            description=f"Package {dep_name}@{dep_version} is vulnerable.\n{details}",
            evidence=f"Installed: {dep_version}\nAdvisory: {vuln.get('id')}",
            remediation="Update to a patched version.",
            owasp_category="A06:2021 – Vulnerable and Outdated Components",
            cwe_id="CWE-1395",
            vulnerability_context=self._build_github_context(
                file_path, "vulnerable_dependency",
                summary, "osv_database",
                confidentiality_impact="High", metric_impact=8.0, data_exposed=[dep_name]
            )
        )

    async def _scan_dependencies(
            self,
            owner: str,
            repo: str,
            branch: str,
            files: List[Dict[str, Any]]
    ) -> List[AgentResult]:
        """Scan dependency files for known vulnerabilities using OSV"""
        results = []
        
        # Identify dependency files
        dep_files = []
        for f in files:
            path = f['path']
            filename = path.split('/')[-1]
            if filename in DependencyFile.PACKAGE_FILES:
                dep_files.append(f)
                
        if not dep_files:
            return []

        logger.info(f"Found {len(dep_files)} dependency files to scan")
        
        ecosystem_stats = defaultdict(int)

        for f in dep_files:
            file_path = f['path']
            ecosystem = DependencyFile.PACKAGE_FILES.get(file_path.split('/')[-1])
            
            try:
                # Fetch content
                content = await self._fetch_file_content(owner, repo, file_path, branch)
                if not content:
                    continue
                    
                # Parse dependencies
                # We need to use valid parsing logic. 
                # Assuming DependencyParser exists and works.
                from .dependency_parser import DependencyParser
                dependencies = DependencyParser.parse(content, ecosystem, file_path)
                
                ecosystem_stats[ecosystem] += len(dependencies)
                
                # Check for vulnerabilities
                vuln_results = await self._check_dependency_vulnerabilities(dependencies, ecosystem, owner, repo, branch, file_path)
                results.extend(vuln_results)

            except Exception as e:
                logger.error(f"Error scanning dependency file {file_path}: {e}")

        # Log ecosystem statistics
        if ecosystem_stats:
            logger.info("Dependency scan statistics by ecosystem:")
            for eco, count in ecosystem_stats.items():
                logger.info(f"  {eco}: {count} dependencies")

        return results

    def _log_scan_statistics(self, owner: str, repo: str) -> None:
        # Log scanning statistics
        cache_hit_rate = 0.0
        total_cache_ops = self.stats['cache_hits'] + self.stats['cache_misses']
        if total_cache_ops > 0:
            cache_hit_rate = (self.stats['cache_hits'] / total_cache_ops) * 100

        logger.info(f"GitHub Scan Stats for {owner}/{repo}: "
                   f"Files={self.stats['files_scanned']}, "
                   f"Secrets={self.stats['secrets_found']}, "
                   f"Cache Hit Rate={cache_hit_rate:.1f}%")

    def generate_sbom(
            self,
            owner: str,
            repo: str,
            all_dependencies: List[ParsedDependency]
    ) -> Dict[str, Any]:
        # Generate a Software Bill of Materials (SBOM) for the repository.
        # Useful for compliance and supply chain security.
        from datetime import datetime

        # Group by ecosystem
        by_ecosystem = {}
        for dep in all_dependencies:
            ecosystem = dep.source.split('/')[-1]
            if ecosystem not in by_ecosystem:
                by_ecosystem[ecosystem] = []
            by_ecosystem[ecosystem].append({
                'name': dep.name,
                'version': dep.version,
                'type': 'development' if dep.is_dev else 'production',
                'source': dep.source
            })

        sbom = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'version': 1,
            'metadata': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'component': {
                    'type': 'application',
                    'name': f"{owner}/{repo}",
                    'version': 'unknown'
                }
            },
            'components': [],
            'dependencies_by_ecosystem': by_ecosystem,
            'summary': {
                'total_dependencies': len(all_dependencies),
                'production_dependencies': len([d for d in all_dependencies if not d.is_dev]),
                'development_dependencies': len([d for d in all_dependencies if d.is_dev]),
                'ecosystems': list(by_ecosystem.keys())
            }
        }

        # Add individual components
        for dep in all_dependencies:
            sbom['components'].append({
                'type': 'library',
                'name': dep.name,
                'version': dep.version,
                'scope': 'optional' if dep.is_dev else 'required'
            })

        logger.info(f"Generated SBOM with {len(all_dependencies)} components")
        return sbom