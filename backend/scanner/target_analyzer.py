"""
Target Analyzer - Scans and analyzes target applications.
"""
import re
import asyncio
from typing import List, Dict, Any, Set, Optional
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass, field
import httpx
from bs4 import BeautifulSoup


@dataclass
class DiscoveredEndpoint:
    """Represents a discovered endpoint."""
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    requires_auth: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "headers": self.headers,
            "content_type": self.content_type,
            "requires_auth": self.requires_auth,
        }


@dataclass
class TargetAnalysis:
    """Results of target analysis."""
    target_url: str
    technology_stack: List[str] = field(default_factory=list)
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    status_code: int = 0
    server: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "technology_stack": self.technology_stack,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "forms": self.forms,
            "headers": self.headers,
            "cookies": self.cookies,
            "scripts": self.scripts,
            "status_code": self.status_code,
            "server": self.server,
        }


class TargetAnalyzer:
    """
    Analyzes target applications to discover:
    - Technology stack
    - Endpoints and attack surfaces
    - Forms and input points
    - Security configurations
    """
    
    # Technology fingerprints
    TECHNOLOGY_SIGNATURES = {
        # Frameworks
        "React": [r"react", r"_react", r"__REACT", r"react-dom"],
        "Vue.js": [r"vue", r"__vue__", r"Vue\.js"],
        "Angular": [r"ng-", r"angular", r"\[ng-"],
        "jQuery": [r"jquery", r"\$\(", r"jQuery"],
        "Next.js": [r"__next", r"_next/", r"next\.js"],
        "Express": [r"express", r"X-Powered-By.*Express"],
        "Django": [r"csrfmiddlewaretoken", r"django"],
        "Flask": [r"werkzeug", r"flask"],
        "Laravel": [r"laravel", r"XSRF-TOKEN"],
        "Ruby on Rails": [r"rails", r"csrf-token", r"turbolinks"],
        "ASP.NET": [r"__VIEWSTATE", r"__EVENTVALIDATION", r"\.aspx"],
        "PHP": [r"\.php", r"PHPSESSID"],
        "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
        
        # Servers
        "Nginx": [r"nginx"],
        "Apache": [r"apache"],
        "IIS": [r"IIS", r"ASP\.NET"],
        
        # CDNs
        "Cloudflare": [r"cloudflare", r"cf-ray"],
        "AWS": [r"amazonaws", r"aws"],
        
        # Other
        "Bootstrap": [r"bootstrap"],
        "Tailwind": [r"tailwind"],
    }
    
    # Common paths to check
    COMMON_PATHS = [
        "/",
        "/login",
        "/register",
        "/admin",
        "/api",
        "/api/v1",
        "/api/users",
        "/dashboard",
        "/profile",
        "/search",
        "/contact",
        "/about",
        "/blog",
        "/products",
        "/cart",
        "/checkout",
    ]
    
    # Common vulnerable paths for test sites
    VULNERABLE_TEST_PATHS = [
        "/listproducts.php?cat=1",
        "/listproducts.php?artist=1",
        "/artists.php?artist=1",
        "/product.php?pic=1",
        "/guestbook.php",
        "/search.php?test=query",
        "/login.php",
        "/userinfo.php",
        "/comment.php",
        "/showimage.php?file=",
    ]
    
    def __init__(self, timeout: float = 30.0, max_depth: int = 2):
        """
        Initialize the target analyzer.
        
        Args:
            timeout: HTTP request timeout
            max_depth: Maximum crawl depth
        """
        self.timeout = timeout
        self.max_depth = max_depth
        self.http_client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False
        )
        self.visited_urls: Set[str] = set()
    
    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()
    
    async def analyze(self, target_url: str) -> TargetAnalysis:
        """
        Perform comprehensive analysis of a target.
        
        Args:
            target_url: URL to analyze
            
        Returns:
            TargetAnalysis object with all discoveries
        """
        self.visited_urls.clear()
        
        # Ensure URL has scheme
        if not target_url.startswith(("http://", "https://")):
            target_url = f"http://{target_url}"
        
        analysis = TargetAnalysis(target_url=target_url)
        
        print(f"[Analyzer] Starting analysis of {target_url}")
        
        # Get initial page
        try:
            response = await self.http_client.get(target_url)
            analysis.status_code = response.status_code
            analysis.headers = dict(response.headers)
            analysis.cookies = [str(c) for c in response.cookies.jar]
            
            # Get server header
            analysis.server = response.headers.get("Server", "Unknown")
            
            # Parse HTML
            soup = BeautifulSoup(response.text, "lxml")
            
            # Detect technologies
            analysis.technology_stack = await self._detect_technology(
                response.headers, 
                response.text,
                soup
            )
            
            # Extract forms
            analysis.forms = self._extract_forms(soup, target_url)
            
            # Discover endpoints
            analysis.endpoints = await self._discover_endpoints(
                target_url,
                soup,
                response.text
            )
            
            # Extract scripts
            analysis.scripts = self._extract_scripts(soup)
            
        except Exception as e:
            print(f"[Analyzer] Error analyzing {target_url}: {e}")
        
        print(f"[Analyzer] Analysis complete. Found {len(analysis.endpoints)} endpoints, {len(analysis.technology_stack)} technologies")
        
        return analysis
    
    async def _detect_technology(
        self,
        headers: httpx.Headers,
        html_content: str,
        soup: BeautifulSoup
    ) -> List[str]:
        """
        Detect technology stack from response.
        
        Args:
            headers: Response headers
            html_content: Page HTML
            soup: Parsed HTML
            
        Returns:
            List of detected technologies
        """
        detected = set()
        
        # Check headers
        headers_str = str(headers)
        
        # Check HTML content and headers against signatures
        for tech, patterns in self.TECHNOLOGY_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    detected.add(tech)
                    break
                if re.search(pattern, headers_str, re.IGNORECASE):
                    detected.add(tech)
                    break
        
        # Check meta tags
        for meta in soup.find_all("meta"):
            generator = meta.get("name", "").lower()
            content = meta.get("content", "")
            
            if generator == "generator":
                detected.add(content.split()[0] if content else "Unknown CMS")
        
        # Check X-Powered-By header
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            detected.add(powered_by)
        
        return list(detected)
    
    def _extract_forms(
        self,
        soup: BeautifulSoup,
        base_url: str
    ) -> List[Dict[str, Any]]:
        """
        Extract forms from the page.
        
        Args:
            soup: Parsed HTML
            base_url: Base URL for resolving relative paths
            
        Returns:
            List of form data
        """
        forms = []
        
        for form in soup.find_all("form"):
            form_data = {
                "action": urljoin(base_url, form.get("action", "")),
                "method": form.get("method", "GET").upper(),
                "inputs": [],
                "has_file_upload": False,
                "has_password": False,
            }
            
            # Extract all inputs
            for input_elem in form.find_all(["input", "textarea", "select"]):
                input_type = input_elem.get("type", "text")
                input_name = input_elem.get("name", "")
                
                if input_name:
                    form_data["inputs"].append({
                        "name": input_name,
                        "type": input_type,
                        "value": input_elem.get("value", ""),
                        "required": input_elem.has_attr("required"),
                    })
                
                if input_type == "file":
                    form_data["has_file_upload"] = True
                if input_type == "password":
                    form_data["has_password"] = True
            
            forms.append(form_data)
        
        return forms
    
    async def _discover_endpoints(
        self,
        base_url: str,
        soup: BeautifulSoup,
        html_content: str
    ) -> List[DiscoveredEndpoint]:
        """
        Discover endpoints from the page.
        
        Args:
            base_url: Base URL
            soup: Parsed HTML
            html_content: Raw HTML
            
        Returns:
            List of discovered endpoints
        """
        endpoints = []
        parsed_base = urlparse(base_url)
        
        # Extract links from HTML
        for link in soup.find_all("a", href=True):
            href = link.get("href", "")
            full_url = urljoin(base_url, href)
            parsed_url = urlparse(full_url)
            
            # Only include same-host URLs
            if parsed_url.netloc == parsed_base.netloc:
                if full_url not in self.visited_urls:
                    self.visited_urls.add(full_url)
                    
                    # Parse query parameters properly
                    query_params = {}
                    if parsed_url.query:
                        for key, values in parse_qs(parsed_url.query).items():
                            query_params[key] = values[0] if values else ""
                    
                    endpoints.append(DiscoveredEndpoint(
                        url=full_url.split("?")[0],
                        method="GET",
                        params=query_params
                    ))
        
        # Extract URLs from JavaScript
        js_urls = re.findall(r'["\']/(api/[^"\']+)["\']', html_content)
        for url in js_urls:
            full_url = urljoin(base_url, "/" + url)
            if full_url not in self.visited_urls:
                self.visited_urls.add(full_url)
                endpoints.append(DiscoveredEndpoint(
                    url=full_url,
                    method="GET"
                ))
        
        # Check common paths
        for path in self.COMMON_PATHS + self.VULNERABLE_TEST_PATHS:
            full_url = urljoin(base_url, path)
            if full_url not in self.visited_urls:
                try:
                    response = await self.http_client.head(full_url, timeout=5.0)
                    if response.status_code < 400:
                        self.visited_urls.add(full_url)
                        
                        # Parse query parameters from path
                        parsed_url = urlparse(full_url)
                        query_params = {}
                        if parsed_url.query:
                            for key, values in parse_qs(parsed_url.query).items():
                                query_params[key] = values[0] if values else ""
                        
                        endpoints.append(DiscoveredEndpoint(
                            url=full_url.split("?")[0],
                            method="GET",
                            params=query_params,
                            requires_auth=response.status_code in [401, 403]
                        ))
                except:
                    pass
        
        # Extract from forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            full_url = urljoin(base_url, action)
            
            params = {}
            for input_elem in form.find_all("input"):
                name = input_elem.get("name")
                if name:
                    params[name] = input_elem.get("value", "")
            
            endpoints.append(DiscoveredEndpoint(
                url=full_url,
                method=method,
                params=params
            ))
        
        return endpoints
    
    def _extract_scripts(self, soup: BeautifulSoup) -> List[str]:
        """
        Extract script sources from the page.
        
        Args:
            soup: Parsed HTML
            
        Returns:
            List of script URLs
        """
        scripts = []
        
        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src:
                scripts.append(src)
        
        return scripts
    
    def get_attack_surface(self, analysis: TargetAnalysis) -> Dict[str, Any]:
        """
        Generate attack surface summary.
        
        Args:
            analysis: Target analysis results
            
        Returns:
            Attack surface summary
        """
        attack_surface = {
            "total_endpoints": len(analysis.endpoints),
            "form_count": len(analysis.forms),
            "has_login": any(
                f["has_password"] for f in analysis.forms
            ),
            "has_file_upload": any(
                f["has_file_upload"] for f in analysis.forms
            ),
            "input_points": [],
            "technologies": analysis.technology_stack,
            "risk_factors": [],
        }
        
        # Identify input points
        for endpoint in analysis.endpoints:
            if endpoint.params:
                attack_surface["input_points"].append({
                    "url": endpoint.url,
                    "method": endpoint.method,
                    "params": list(endpoint.params.keys())
                })
        
        # Add risk factors
        if attack_surface["has_login"]:
            attack_surface["risk_factors"].append("authentication_forms")
        if attack_surface["has_file_upload"]:
            attack_surface["risk_factors"].append("file_upload")
        if len(analysis.endpoints) > 20:
            attack_surface["risk_factors"].append("large_attack_surface")
        
        return attack_surface
