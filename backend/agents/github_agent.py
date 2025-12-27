"""
GitHub Security Agent - Enhanced version with intelligent scanning capabilities.

Features:
- Intelligent file prioritization
- Advanced secret detection with entropy analysis
- GitHub API rate limiting and authentication
- Dependency vulnerability scanning
- Dynamic branch detection
- Performance optimizations and caching
"""
import re
import httpx
import asyncio
import hashlib
import math
from typing import List, Dict, Any, Optional, Set, Tuple, TYPE_CHECKING
from urllib.parse import urlparse
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import logging
from .dependency_parser import DependencyParser, ParsedDependency

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType
from core.hugging_face_client import hf_client_ii

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
    OSV_API_URL = "https://api.osv.dev/v1/query"

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
        (r'(?i)aws(.{0,20})?[\'\"][0-9a-zA-Z\/+]{40}[\'\"]', "AWS Secret Key", True),
        (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", True),
        (r'ya29\.[0-9A-Za-z\-_]+', "Google OAuth Token", True),

        # API Keys
        (r'sk-[a-zA-Z0-9]{48}', "OpenAI API Key", True),
        (r'sk-proj-[a-zA-Z0-9\-_]{48,}', "OpenAI Project Key", True),
        (r'gsk_[a-zA-Z0-9]{48}', "Groq API Key", True),
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
        """Enable sorting by priority (higher first)"""
        return self.priority_score > other.priority_score


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
        return max(0, (self.reset_time - datetime.now()).total_seconds())


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
        age = datetime.now() - self.timestamp
        return age.total_seconds() > GithubAgentConfig.CACHE_TTL_SECONDS


# ==================== Main Agent Class ====================

class GithubSecurityAgent(BaseSecurityAgent):
    """
    Enhanced GitHub Security Agent with intelligent scanning.

    Features:
    - Smart file prioritization
    - Advanced secret detection with entropy analysis
    - GitHub API rate limiting
    - Dependency vulnerability scanning
    - Caching and performance optimizations
    """

    agent_name = "github_security"
    agent_description = "Analyzes GitHub repository source code with advanced detection"
    vulnerability_types = [
        VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
        VulnerabilityType.SQL_INJECTION,
        VulnerabilityType.XSS_STORED,
        VulnerabilityType.PATH_TRAVERSAL,
        VulnerabilityType.OTHER
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

    def __init__(self, github_token: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.github_token = github_token
        self.rate_limit_info: Optional[RateLimitInfo] = None
        self.file_cache: Dict[str, CacheEntry] = {}
        self.vulnerability_db_cache: Dict[str, List[Dict]] = {}

        # Statistics
        self.stats = {
            'files_scanned': 0,
            'secrets_found': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'api_calls': 0,
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

        Args:
            target_url: GitHub repository URL
            endpoints: Not used for GitHub scanning
            technology_stack: Not used for GitHub scanning
            scan_context: Shared context between agents

        Returns:
            List of vulnerability findings
        """
        results = []
        repo_info = self._parse_github_url(target_url)

        if not repo_info:
            logger.error(f"Invalid GitHub URL: {target_url}")
            return []

        owner, repo = repo_info
        logger.info(f"Starting enhanced scan of repository: {owner}/{repo}")

        try:
            # 1. Get default branch dynamically
            default_branch = await self._get_default_branch(owner, repo)
            logger.info(f"Using branch: {default_branch}")

            # 2. Fetch and prioritize files
            files = await self._fetch_repo_files(owner, repo, default_branch)
            if not files:
                logger.warning(f"No files found in repository {owner}/{repo}")
                return []

            logger.info(f"Found {len(files)} total files in repository")

            # 3. Prioritize and filter files
            prioritized_files = self._prioritize_files(files)
            target_files = prioritized_files[:GithubAgentConfig.MAX_FILES_TO_SCAN]

            logger.info(f"Selected {len(target_files)} high-priority files for scanning")

            # 4. Scan files with concurrency control
            results.extend(await self._scan_files_batch(owner, repo, default_branch, target_files))

            # 5. Dependency scanning
            if GithubAgentConfig.ENABLE_DEPENDENCY_SCAN:
                dep_results = await self._scan_dependencies(owner, repo, default_branch, files)
                results.extend(dep_results)

            # 6. Log statistics
            self._log_scan_statistics(owner, repo)

        except Exception as e:
            logger.error(f"Error scanning repository {owner}/{repo}: {e}", exc_info=True)

        return results

    # ==================== GitHub API Methods ====================

    async def _get_default_branch(self, owner: str, repo: str) -> str:
        """
        Dynamically detect the repository's default branch.

        Returns:
            Branch name (e.g., 'main', 'master', 'develop')
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

        Returns:
            List of file metadata dictionaries
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

        Args:
            client: HTTP client
            url: API endpoint URL
            retry_count: Current retry attempt

        Returns:
            Response object or None on failure
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

    # ==================== File Prioritization ====================

    def _prioritize_files(self, files: List[Dict[str, Any]]) -> List[FileMetadata]:
        """
        Intelligently prioritize files for scanning based on security value.

        Scoring system:
        - Critical (100): Config files likely containing secrets
        - High (80): Authentication, API, security-related files
        - Medium (60): Database, connection files
        - Low (40): Regular source code
        - Minimal (20): Test files, documentation

        Returns:
            Sorted list of FileMetadata (highest priority first)
        """
        prioritized = []

        for file_info in files:
            path = file_info['path'].lower()

            # Skip ignored files
            if not self._is_scannable_file(path):
                continue

            # Calculate priority score
            score = self._calculate_file_priority(path)

            if score > 0:
                metadata = FileMetadata(
                    path=file_info['path'],
                    priority_score=score,
                    file_type=self._get_file_type(path),
                    size=file_info.get('size', 0),
                    sha=file_info.get('sha', '')
                )
                prioritized.append(metadata)

        # Sort by priority (highest first)
        prioritized.sort()

        logger.info(f"Prioritized {len(prioritized)} scannable files")
        return prioritized

    def _calculate_file_priority(self, path: str) -> int:
        """Calculate priority score for a file"""
        score = 0
        filename = path.split('/')[-1].lower()

        # Critical: Config files with secrets
        if any(cf in filename for cf in self.CRITICAL_FILES):
            score = GithubAgentConfig.PRIORITY_CRITICAL

        # High: Security-sensitive paths
        elif any(hvp in path for hvp in self.HIGH_VALUE_PATHS):
            score = GithubAgentConfig.PRIORITY_HIGH

        # High: Dependency files
        elif filename in DependencyFile.PACKAGE_FILES:
            score = GithubAgentConfig.PRIORITY_HIGH

        # Medium: Config files
        elif any(path.endswith(ext) for ext in self.CONFIG_EXTENSIONS):
            score = GithubAgentConfig.PRIORITY_MEDIUM

        # Medium: Source code in critical languages
        elif any(path.endswith(ext) for ext in self.HIGH_PRIORITY_EXTENSIONS):
            score = GithubAgentConfig.PRIORITY_MEDIUM

        # Low: Test files
        elif 'test' in path or 'spec' in path or '__test__' in path:
            score = GithubAgentConfig.PRIORITY_MINIMAL

        # Low: Documentation
        elif path.endswith('.md') or 'doc' in path:
            score = GithubAgentConfig.PRIORITY_MINIMAL

        else:
            score = GithubAgentConfig.PRIORITY_LOW

        # Boost for files in root or config directories
        if path.count('/') <= 1 or '/config/' in path:
            score += 10

        return score

    def _is_scannable_file(self, path: str) -> bool:
        """Check if file should be scanned"""
        # Check ignored directories
        if any(ignored_dir in path for ignored_dir in self.IGNORE_DIRS):
            return False

        # Check ignored extensions
        ext = '.' + path.split('.')[-1] if '.' in path else ''
        if ext.lower() in self.IGNORE_EXTENSIONS:
            return False

        return True

    def _get_file_type(self, path: str) -> str:
        """Determine file type from path"""
        ext = path.split('.')[-1].lower() if '.' in path else 'unknown'
        return ext

    # ==================== File Scanning ====================

    async def _scan_files_batch(
            self,
            owner: str,
            repo: str,
            branch: str,
            files: List[FileMetadata]
    ) -> List[AgentResult]:
        """
        Scan files in controlled batches with concurrency limits.

        Returns:
            Combined results from all file scans
        """
        results = []

        # Process files in batches to control concurrency
        for i in range(0, len(files), GithubAgentConfig.CONCURRENT_FILE_LIMIT):
            batch = files[i:i + GithubAgentConfig.CONCURRENT_FILE_LIMIT]

            tasks = [
                self._analyze_file(owner, repo, branch, file_meta)
                for file_meta in batch
            ]

            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"File analysis error: {result}")
                elif result:
                    results.extend(result)

            # Small delay between batches to be nice to GitHub
            if i + GithubAgentConfig.CONCURRENT_FILE_LIMIT < len(files):
                await asyncio.sleep(0.5)

        return results

    async def _analyze_file(
            self,
            owner: str,
            repo: str,
            branch: str,
            file_meta: FileMetadata
    ) -> List[AgentResult]:
        """
        Download and analyze a single file.

        Returns:
            List of vulnerabilities found in the file
        """
        results = []
        file_path = file_meta.path

        # Check file size limit
        if file_meta.size > GithubAgentConfig.MAX_FILE_SIZE_BYTES:
            logger.warning(f"Skipping large file ({file_meta.size} bytes): {file_path}")
            return []

        # Check cache first
        content = self._get_cached_content(file_path, file_meta.sha)

        if content is None:
            # Download file
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"

            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(raw_url, timeout=GithubAgentConfig.DEFAULT_TIMEOUT)

                    if response.status_code != 200:
                        logger.debug(f"Could not fetch {file_path}: {response.status_code}")
                        return []

                    content = response.text
                    self._cache_content(file_path, content, file_meta.sha)
                    self.stats['cache_misses'] += 1

            except Exception as e:
                logger.error(f"Error downloading {file_path}: {e}")
                return []
        else:
            self.stats['cache_hits'] += 1

        # Analyze content
        try:
            # 1. Secret scanning with entropy analysis
            secret_results = self._scan_for_secrets(content, owner, repo, branch, file_path)
            results.extend(secret_results)

            # 2. AI-powered SAST (if configured)
            if hf_client_ii.is_configured:
                ai_results = await self._ai_analysis(content, file_path, owner, repo, branch)
                results.extend(ai_results)

            self.stats['files_scanned'] += 1

        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")

        return results

    # ==================== Secret Detection ====================

    def _scan_for_secrets(
            self,
            content: str,
            owner: str,
            repo: str,
            branch: str,
            file_path: str
    ) -> List[AgentResult]:
        """
        Scan file content for secrets with entropy analysis.

        Returns:
            List of secret vulnerability findings
        """
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
                    file_path
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
                ai_analysis=f"Entropy: {secret.entropy:.2f} | Confidence: {secret.confidence}%"
            ))

            self.stats['secrets_found'] += 1

        return results

    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string.
        Higher entropy indicates more randomness (likely a real secret).

        Returns:
            Entropy value (0-8 for base-2)
        """
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
        """Validate if a matched string is likely a real secret"""
        # Length check
        if len(secret) < GithubAgentConfig.SECRET_MIN_LENGTH:
            return False

        if len(secret) > GithubAgentConfig.SECRET_MAX_LENGTH:
            return False

        # High confidence patterns (like AWS keys) pass with lower entropy
        if high_confidence:
            return entropy >= 3.0

        # Low confidence patterns (like JWTs) need higher entropy
        return entropy >= GithubAgentConfig.MIN_ENTROPY_THRESHOLD

    def _is_false_positive_secret(self, secret: str, content: str, file_path: str) -> bool:
        """Check if secret is likely a false positive"""
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
        """Calculate confidence score for secret detection (0-100)"""
        confidence = 70  # Base confidence

        # High confidence pattern bonus
        if high_confidence:
            confidence += 20

        # Entropy bonus
        if entropy > 5.0:
            confidence += 10
        elif entropy > 4.0:
            confidence += 5

        # File location bonus
        if '.env' in file_path or 'config' in file_path.lower():
            confidence += 10

        # Penalize if in test/example files (but we already filter these)
        if 'test' in file_path.lower() or 'example' in file_path.lower():
            confidence -= 30

        return min(100, max(0, confidence))

    def _determine_secret_severity(self, secret: SecretMatch) -> Severity:
        """Determine severity based on secret type and confidence"""
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
        """Obfuscate secret for display"""
        if len(secret) <= 10:
            return '*' * len(secret)

        # Show first 5 and last 5 characters
        return secret[:5] + '...' + secret[-5:]

    # ==================== AI Analysis ====================

    async def _ai_analysis(
            self,
            content: str,
            file_path: str,
            owner: str,
            repo: str,
            branch: str
    ) -> List[AgentResult]:
        """Perform AI-powered static analysis"""
        results = []

        try:
            ai_results = await openrouter_client.analyze_code(file_path, content)

            if 'vulnerabilities' in ai_results:
                for vuln in ai_results['vulnerabilities']:
                    results.append(self.create_result(
                        vulnerability_type=self._map_vuln_type(vuln.get('type')),
                        is_vulnerable=True,
                        severity=self._map_severity(vuln.get('severity')),
                        confidence=vuln.get('confidence', 70),
                        url=f"https://github.com/{owner}/{repo}/blob/{branch}/{file_path}#L{vuln.get('line_number', 1)}",
                        title=vuln.get('title', 'Security Finding'),
                        description=vuln.get('description', ''),
                        evidence=vuln.get('evidence', ''),
                        remediation=vuln.get('remediation', ''),
                        ai_analysis=ai_results.get('summary', '')
                    ))
        except Exception as e:
            logger.error(f"AI analysis error for {file_path}: {e}")

        return results

    # ==================== Dependency Scanning ====================

    async def _scan_dependencies(
            self,
            owner: str,
            repo: str,
            branch: str,
            all_files: List[Dict[str, Any]]
    ) -> List[AgentResult]:
        """
        Scan dependency files for known vulnerabilities.
        Enhanced to handle all major package managers.

        Returns:
            List of dependency vulnerability findings
        """
        results = []

        # Find ALL dependency files (not just package files)
        dep_files = []
        for f in all_files:
            filename = f['path'].split('/')[-1]
            if filename in DependencyFile.PACKAGE_FILES:
                dep_files.append(f)

        if not dep_files:
            logger.info("No dependency files found")
            return []

        logger.info(f"Found {len(dep_files)} dependency files: {[f['path'] for f in dep_files]}")

        # Track stats by ecosystem
        ecosystem_stats = {}

        for dep_file in dep_files[:10]:  # Increased limit to 10 files
            file_path = dep_file['path']
            filename = file_path.split('/')[-1]
            ecosystem = DependencyFile.PACKAGE_FILES.get(filename)

            if not ecosystem:
                continue

            try:
                # Download dependency file
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
                async with httpx.AsyncClient() as client:
                    response = await client.get(raw_url, timeout=GithubAgentConfig.DEFAULT_TIMEOUT)

                    if response.status_code != 200:
                        logger.warning(f"Could not fetch {file_path}: {response.status_code}")
                        continue

                    content = response.text

                # Parse dependencies using enhanced parser
                dependencies = self._parse_dependencies(content, ecosystem, file_path)

                if not dependencies:
                    logger.info(f"No parseable dependencies in {file_path}")
                    continue

                # Track stats
                ecosystem_stats[ecosystem] = ecosystem_stats.get(ecosystem, 0) + len(dependencies)

                logger.info(f"Scanning {len(dependencies)} dependencies from {file_path}")

                # Check for vulnerabilities (in batches to avoid overwhelming the API)
                batch_size = 10
                for i in range(0, len(dependencies), batch_size):
                    batch = dependencies[i:i + batch_size]

                    vuln_results = await self._check_dependency_vulnerabilities(
                        batch, ecosystem, owner, repo, branch, file_path
                    )

                    results.extend(vuln_results)

                    # Small delay between batches
                    if i + batch_size < len(dependencies):
                        await asyncio.sleep(0.5)

            except Exception as e:
                logger.error(f"Error scanning dependency file {file_path}: {e}", exc_info=True)

        # Log ecosystem statistics
        if ecosystem_stats:
            logger.info("Dependency scan statistics by ecosystem:")
            for eco, count in ecosystem_stats.items():
                logger.info(f"  {eco}: {count} dependencies")

        return results

    def _parse_dependencies(
            self,
            content: str,
            ecosystem: str,
            file_path: str
    ) -> List[Tuple[str, str]]:
        """
        Parse dependency file to extract package names and versions.
        Uses the enhanced DependencyParser for comprehensive support.
        """
        dependencies: List[Tuple[str, str]] = []

        try:
            # Parse using the enhanced parser
            parsed_deps = DependencyParser.parse(content, ecosystem, file_path)

            if not parsed_deps:
                return []

            # Deduplicate dependencies
            parsed_deps = DependencyParser.deduplicate(parsed_deps)

            # Convert to tuple format
            for dep in parsed_deps:
                # Skip wildcard versions
                if dep.version and dep.version != "*":
                    dependencies.append((dep.name, dep.version))
                    logger.debug(
                        f"Parsed dependency: {dep.name}@{dep.version} from {file_path}"
                    )

            logger.info(
                f"Extracted {len(dependencies)} dependencies from {file_path}"
            )

        except Exception as e:
            logger.error(
                f"Error parsing dependencies from {file_path}: {e}",
                exc_info=True
            )

        return dependencies

    async def _check_dependency_vulnerabilities(
            self,
            dependencies: List[Tuple[str, str]],
            ecosystem: str,
            owner: str,
            repo: str,
            branch: str,
            file_path: str
    ) -> List[AgentResult]:
        """Check dependencies against OSV vulnerability database"""
        results = []

        # Map ecosystem names to OSV format
        ecosystem_map = {
            'npm': 'npm',
            'pip': 'PyPI',
            'go': 'Go',
            'ruby': 'RubyGems',
            'php': 'Packagist',
            'maven': 'Maven',
            'rust': 'crates.io'
        }

        osv_ecosystem = ecosystem_map.get(ecosystem)
        if not osv_ecosystem:
            return []

        for pkg_name, version in dependencies[:20]:  # Limit to 20 packages
            cache_key = f"{osv_ecosystem}:{pkg_name}:{version}"

            # Check cache
            if cache_key in self.vulnerability_db_cache:
                vulnerabilities = self.vulnerability_db_cache[cache_key]
            else:
                vulnerabilities = await self._query_osv_api(osv_ecosystem, pkg_name, version)
                self.vulnerability_db_cache[cache_key] = vulnerabilities

            # Create results for each vulnerability
            for vuln in vulnerabilities:
                results.append(self.create_result(
                    vulnerability_type=VulnerabilityType.OTHER,
                    is_vulnerable=True,
                    severity=self._map_osv_severity(vuln),
                    confidence=95,  # High confidence from CVE database
                    url=f"https://github.com/{owner}/{repo}/blob/{branch}/{file_path}",
                    title=f"Vulnerable Dependency: {pkg_name} {version}",
                    description=(
                        f"Package '{pkg_name}' version {version} has a known vulnerability: "
                        f"{vuln.get('summary', 'No summary available')}"
                    ),
                    evidence=f"CVE: {vuln.get('id', 'Unknown')}",
                    remediation=(
                        f"Update '{pkg_name}' to a patched version. "
                        f"Affected versions: {', '.join(vuln.get('affected_versions', []))}. "
                        f"Fixed versions: {', '.join(vuln.get('fixed_versions', ['See advisory']))}."
                    ),
                    owasp_category="A06:2021 – Vulnerable and Outdated Components",
                    cwe_id="CWE-1104"
                ))

        return results

    async def _query_osv_api(
            self,
            ecosystem: str,
            package: str,
            version: str
    ) -> List[Dict[str, Any]]:
        """Query OSV.dev API for vulnerability information"""
        try:
            async with httpx.AsyncClient() as client:
                payload = {
                    "package": {
                        "name": package,
                        "ecosystem": ecosystem
                    },
                    "version": version
                }

                response = await client.post(
                    GithubAgentConfig.OSV_API_URL,
                    json=payload,
                    timeout=10.0
                )

                if response.status_code == 200:
                    data = response.json()
                    return self._parse_osv_response(data)

        except Exception as e:
            logger.error(f"Error querying OSV API for {package}: {e}")

        return []

    def _parse_osv_response(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse OSV API response into simplified vulnerability objects"""
        vulnerabilities = []

        for vuln in data.get('vulns', []):
            vulnerabilities.append({
                'id': vuln.get('id', 'Unknown'),
                'summary': vuln.get('summary', 'No summary available'),
                'severity': vuln.get('severity', [{}])[0].get('type', 'UNKNOWN'),
                'affected_versions': self._extract_affected_versions(vuln),
                'fixed_versions': self._extract_fixed_versions(vuln)
            })

        return vulnerabilities

    def _extract_affected_versions(self, vuln: Dict[str, Any]) -> List[str]:
        """Extract affected version ranges from vulnerability"""
        versions = []
        for affected in vuln.get('affected', []):
            for version_range in affected.get('ranges', []):
                events = version_range.get('events', [])
                for event in events:
                    if 'introduced' in event:
                        versions.append(f">={event['introduced']}")
                    if 'fixed' in event:
                        versions.append(f"<{event['fixed']}")
        return versions

    def _extract_fixed_versions(self, vuln: Dict[str, Any]) -> List[str]:
        """Extract fixed versions from vulnerability"""
        versions = []
        for affected in vuln.get('affected', []):
            for version_range in affected.get('ranges', []):
                events = version_range.get('events', [])
                for event in events:
                    if 'fixed' in event:
                        versions.append(event['fixed'])
        return versions or ['See advisory']

    def _map_osv_severity(self, vuln: Dict[str, Any]) -> Severity:
        """Map OSV severity to internal Severity enum"""
        severity = vuln.get('severity', 'UNKNOWN').upper()

        if 'CRITICAL' in severity:
            return Severity.CRITICAL
        elif 'HIGH' in severity:
            return Severity.HIGH
        elif 'MEDIUM' in severity or 'MODERATE' in severity:
            return Severity.MEDIUM
        elif 'LOW' in severity:
            return Severity.LOW
        else:
            return Severity.INFO

    # ==================== Caching ====================

    def _get_cached_content(self, file_path: str, sha: str) -> Optional[str]:
        """Get cached file content if available and valid"""
        if not GithubAgentConfig.ENABLE_CACHE:
            return None

        cache_entry = self.file_cache.get(file_path)

        if cache_entry:
            # Check if cache is expired
            if cache_entry.is_expired():
                del self.file_cache[file_path]
                return None

            # Check if file has changed (SHA mismatch)
            if sha and cache_entry.file_sha != sha:
                del self.file_cache[file_path]
                return None

            return cache_entry.content

        return None

    def _cache_content(self, file_path: str, content: str, sha: str) -> None:
        """Cache file content"""
        if not GithubAgentConfig.ENABLE_CACHE:
            return

        self.file_cache[file_path] = CacheEntry(
            content=content,
            timestamp=datetime.now(),
            file_sha=sha
        )

    # ==================== Utility Methods ====================

    def _parse_github_url(self, url: str) -> Optional[Tuple[str, str]]:
        """Extract owner and repo name from GitHub URL"""
        parsed = urlparse(url)
        if parsed.netloc != 'github.com':
            return None

        path_parts = parsed.path.strip('/').split('/')
        if len(path_parts) >= 2:
            return path_parts[0], path_parts[1]

        return None

    def _map_vuln_type(self, type_str: str) -> VulnerabilityType:
        """Map AI vulnerability types to project enum"""
        type_str = type_str.lower() if type_str else ""
        if 'sql' in type_str:
            return VulnerabilityType.SQL_INJECTION
        if 'xss' in type_str:
            return VulnerabilityType.XSS_STORED
        if 'traversal' in type_str or 'path' in type_str:
            return VulnerabilityType.PATH_TRAVERSAL
        if 'data' in type_str or 'sensitive' in type_str:
            return VulnerabilityType.SENSITIVE_DATA_EXPOSURE
        return VulnerabilityType.OTHER

    def _map_severity(self, sev_str: str) -> Severity:
        """Map string severity to Severity enum"""
        mapping = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO
        }
        return mapping.get(sev_str.lower(), Severity.MEDIUM)

    def _log_scan_statistics(self, owner: str, repo: str) -> None:
        """Log scanning statistics"""
        cache_hit_rate = 0
        if self.stats['cache_hits'] + self.stats['cache_misses'] > 0:
            cache_hit_rate = (self.stats['cache_hits'] /
                              (self.stats['cache_hits'] + self.stats['cache_misses'])) * 100

        logger.info(f"""
========== GitHub Scan Statistics ==========
Repository: {owner}/{repo}
Files Scanned: {self.stats['files_scanned']}
Secrets Found: {self.stats['secrets_found']}
API Calls: {self.stats['api_calls']}
Cache Hits: {self.stats['cache_hits']}
Cache Misses: {self.stats['cache_misses']}
Cache Hit Rate: {cache_hit_rate:.1f}%
=============================================
        """.strip())

    def generate_sbom(
            self,
            owner: str,
            repo: str,
            all_dependencies: List[ParsedDependency]
    ) -> Dict[str, Any]:
        """
        Generate a Software Bill of Materials (SBOM) for the repository.
        Useful for compliance and supply chain security.

        Returns:
            SBOM in CycloneDX-like format
        """
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
                'timestamp': datetime.now().isoformat(),
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