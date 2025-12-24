"""
GitHub Security Agent - Analyzes repository source code for vulnerabilities.
"""
import re
import httpx
import asyncio
from typing import List, Dict, Any, Optional, TYPE_CHECKING
from urllib.parse import urlparse

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType
from core.openrouter_client import openrouter_client

if TYPE_CHECKING:
    from core.scan_context import ScanContext

class GithubSecurityAgent(BaseSecurityAgent):
    """
    Agent for scanning GitHub repositories.
    
    Performs:
    - Secret scanning (API keys, tokens)
    - SAST (Static Analysis Security Testing) via OpenRouter
    - Dependency analysis
    """
    
    agent_name = "github_security"
    agent_description = "Analyzes GitHub repository source code"
    vulnerability_types = [
        VulnerabilityType.SENSITIVE_DATA,
        VulnerabilityType.SQL_INJECTION,
        VulnerabilityType.XSS_STORED,
        VulnerabilityType.PATH_TRAVERSAL,
        VulnerabilityType.OTHER
    ]
    
    # Files to ignore in analysis
    IGNORE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.pdf', '.zip', '.tar', '.gz', '.mp4'}
    IGNORE_DIRS = {'node_modules', '.git', 'venv', '__pycache__', 'dist', 'build'}
    
    # Secret patterns
    SECRET_PATTERNS = [
        (r'AIza[0-9A-Za-z-_]{35}', "Google API Key"),
        (r'sk-[a-zA-Z0-9]{48}', "OpenAI API Key"),
        (r'gsk_[a-zA-Z0-9]{48}', "Groq API Key"),
        (r'sqp_[a-zA-Z0-9]{40}', "SonarQube Token"),
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
        (r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', "Potential JWT"),
        (r'postgres://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+:[0-9]+/+[a-zA-Z0-9_]+', "Postgres Connection String"),
        (r'mongodb\+srv://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+', "MongoDB Connection String"),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.github_token = None # Could be added for private repos

    async def scan(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]] = None,
        technology_stack: List[str] = None,
        scan_context: Optional["ScanContext"] = None
    ) -> List[AgentResult]:
        """
        Scan a GitHub repository.
        
        Args:
            target_url: GitHub repository URL (e.g., https://github.com/user/repo)
        """
        results = []
        repo_info = self._parse_github_url(target_url)
        
        if not repo_info:
            print(f"[GITHUB AGENT] Invalid GitHub URL: {target_url}")
            return []

        owner, repo = repo_info
        print(f"[GITHUB AGENT] Scanning repository: {owner}/{repo}")
        
        # 1. Fetch File List
        files = await self._fetch_repo_files(owner, repo)
        if not files:
            return []

        # 2. Process Files (Limit to top N files or specific extensions for proof of concept)
        # In a real app, we'd be more selective or use a dedicated worker
        target_files = [f for f in files if self._is_interesting_file(f['path'])]
        
        # Limit to 10 files for performance during demo/dev
        target_files = target_files[:15]
        
        analysis_tasks = []
        for file_info in target_files:
            task = self._analyze_file(owner, repo, file_info['path'])
            analysis_tasks.append(task)
        
        # Run analysis concurrently
        batch_results = await asyncio.gather(*analysis_tasks)
        
        for file_results in batch_results:
            results.extend(file_results)
            
        return results

    def _parse_github_url(self, url: str) -> Optional[tuple]:
        """Extract owner and repo name from GitHub URL."""
        parsed = urlparse(url)
        if parsed.netloc != 'github.com':
            return None
        
        path_parts = parsed.path.strip('/').split('/')
        if len(path_parts) >= 2:
            return path_parts[0], path_parts[1]
        
        return None

    def _is_interesting_file(self, file_path: str) -> bool:
        """Filter out non-source code files."""
        if any(d in file_path for d in self.IGNORE_DIRS):
            return False
            
        ext = '.' + file_path.split('.')[-1] if '.' in file_path else ''
        if ext.lower() in self.IGNORE_EXTENSIONS:
            return False
            
        # Prioritize config and source files
        return ext.lower() in {'.py', '.js', '.ts', '.tsx', '.go', '.java', '.php', '.env', '.json', '.yml', '.yaml'}

    async def _fetch_repo_files(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """Fetch recursive file list from GitHub API."""
        url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/main?recursive=1"
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=20.0)
                if response.status_code == 404:
                    # Try 'master' if 'main' fails
                    url = url.replace('/main?', '/master?')
                    response = await client.get(url, timeout=20.0)
                
                response.raise_for_status()
                data = response.json()
                return [f for f in data.get('tree', []) if f['type'] == 'blob']
        except Exception as e:
            print(f"[GITHUB AGENT] Error fetching file list: {e}")
            return []

    async def _analyze_file(self, owner: str, repo: str, file_path: str) -> List[AgentResult]:
        """Download and analyze a single file."""
        results = []
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{file_path}"
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(raw_url, timeout=15.0)
                if response.status_code == 404:
                    raw_url = raw_url.replace('/main/', '/master/')
                    response = await client.get(raw_url, timeout=15.0)
                
                if response.status_code != 200:
                    return []
                
                content = response.text
                
                # 1. Secret Scanning (Regex)
                for pattern, name in self.SECRET_PATTERNS:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        results.append(self.create_result(
                            vulnerability_type=VulnerabilityType.SENSITIVE_DATA,
                            is_vulnerable=True,
                            severity=Severity.CRITICAL,
                            confidence=100,
                            url=f"https://github.com/{owner}/{repo}/blob/main/{file_path}#L{line_num}",
                            title=f"Exposed Secret: {name}",
                            description=f"A hardcoded secret ({name}) was found in {file_path} at line {line_num}.",
                            evidence=match.group(0)[:5] + "..." + match.group(0)[-5:],
                            remediation="Revoke the secret immediately and use environment variables or a secret management service (e.g., AWS Secrets Manager, GitHub Secrets).",
                            owasp_category="A01:2021 – Broken Access Control",
                            cwe_id="CWE-798"
                        ))

                # 2. AI SAST Analysis (OpenRouter)
                if openrouter_client.is_configured:
                    ai_results = await openrouter_client.analyze_code(file_path, content)
                    if 'vulnerabilities' in ai_results:
                        for vuln in ai_results['vulnerabilities']:
                            results.append(self.create_result(
                                vulnerability_type=self._map_vuln_type(vuln.get('type')),
                                is_vulnerable=True,
                                severity=self._map_severity(vuln.get('severity')),
                                confidence=vuln.get('confidence', 70),
                                url=f"https://github.com/{owner}/{repo}/blob/main/{file_path}#L{vuln.get('line_number', 1)}",
                                title=vuln.get('title', 'Security Finding'),
                                description=vuln.get('description', ''),
                                evidence=vuln.get('evidence', ''),
                                remediation=vuln.get('remediation', ''),
                                ai_analysis=ai_results.get('summary', '')
                            ))
                            
        except Exception as e:
            print(f"[GITHUB AGENT] Error analyzing {file_path}: {e}")
            
        return results

    def _map_vuln_type(self, type_str: str) -> VulnerabilityType:
        """Map AI vulnerability types to project enum."""
        type_str = type_str.lower() if type_str else ""
        if 'sql' in type_str: return VulnerabilityType.SQL_INJECTION
        if 'xss' in type_str: return VulnerabilityType.XSS_STORED
        if 'traversal' in type_str or 'path' in type_str: return VulnerabilityType.PATH_TRAVERSAL
        if 'data' in type_str or 'sensitive' in type_str: return VulnerabilityType.SENSITIVE_DATA
        return VulnerabilityType.OTHER

    def _map_severity(self, sev_str: str) -> Severity:
        """Map string severity to Severity enum."""
        mapping = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO
        }
        return mapping.get(sev_str.lower(), Severity.MEDIUM)
