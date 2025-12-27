"""
Target Analyzer - Scans and analyzes target applications.
Enhanced with concurrent probing, JS analysis, and comprehensive discovery.
"""
import re
import asyncio
from typing import List, Dict, Any, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass, field
import httpx
from bs4 import BeautifulSoup
import warnings

# Suppress SSL warnings for testing environments
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


@dataclass
class DiscoveredEndpoint:
    """Represents a discovered endpoint."""
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    requires_auth: bool = False
    source: str = "unknown"  # Track where endpoint was discovered
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "headers": self.headers,
            "content_type": self.content_type,
            "requires_auth": self.requires_auth,
            "source": self.source,
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
    api_docs: List[Dict[str, str]] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)
    waf_detected: Optional[str] = None
    
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
            "api_docs": self.api_docs,
            "security_headers": self.security_headers,
            "waf_detected": self.waf_detected,
        }


class TargetAnalyzer:
    """
    Analyzes target applications to discover:
    - Technology stack (including modern frameworks and cloud services)
    - Endpoints and attack surfaces
    - Forms and input points (including modern SPA patterns)
    - Security configurations and WAF detection
    - API documentation endpoints
    """
    
    # Enhanced technology fingerprints
    TECHNOLOGY_SIGNATURES = {
        # Modern Frontend Frameworks
        "React": [r"react", r"_react", r"__REACT", r"react-dom"],
        "Vue.js": [r"vue", r"__vue__", r"Vue\.js", r"vue@"],
        "Angular": [r"ng-", r"angular", r"\[ng-", r"@angular"],
        "Svelte": [r"svelte", r"__svelte", r"svelte@"],
        "SolidJS": [r"solid-js", r"solidjs"],
        "jQuery": [r"jquery", r"\$\(", r"jQuery"],
        
        # Meta Frameworks
        "Next.js": [r"__next", r"_next/", r"next\.js", r"next@"],
        "Remix": [r"remix", r"@remix-run"],
        "Astro": [r"astro", r"@astrojs"],
        "Nuxt.js": [r"__nuxt", r"nuxt\.js"],
        "Gatsby": [r"gatsby", r"___gatsby"],
        
        # Backend Frameworks
        "Express": [r"express", r"X-Powered-By.*Express"],
        "Django": [r"csrfmiddlewaretoken", r"django", r"__admin"],
        "Flask": [r"werkzeug", r"flask"],
        "FastAPI": [r"fastapi", r"swagger"],
        "Laravel": [r"laravel", r"XSRF-TOKEN", r"laravel_session"],
        "Ruby on Rails": [r"rails", r"csrf-token", r"turbolinks"],
        "ASP.NET": [r"__VIEWSTATE", r"__EVENTVALIDATION", r"\.aspx"],
        "PHP": [r"\.php", r"PHPSESSID"],
        "Spring Boot": [r"spring", r"Whitelabel Error Page"],
        "NestJS": [r"nestjs", r"@nestjs"],
        
        # CMS
        "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
        "Drupal": [r"drupal", r"sites/default"],
        "Joomla": [r"joomla", r"option=com_"],
        
        # Servers
        "Nginx": [r"nginx"],
        "Apache": [r"apache"],
        "IIS": [r"IIS", r"ASP\.NET"],
        "Caddy": [r"caddy"],
        
        # CDNs & Cloud Services
        "Cloudflare": [r"cloudflare", r"cf-ray", r"__cfduid"],
        "AWS": [r"amazonaws", r"aws", r"x-amz-"],
        "Firebase": [r"firebase", r"firebaseapp", r"__firebase"],
        "Amplify": [r"amplify", r"amplifyapp"],
        "Supabase": [r"supabase", r"supabase\.co"],
        "Vercel": [r"vercel", r"__vercel"],
        "Netlify": [r"netlify", r"__netlify"],
        "Azure": [r"azure", r"windows\.net"],
        "Google Cloud": [r"googleapis", r"gcp"],
        
        # WAFs
        "Cloudflare WAF": [r"cf-ray"],
        "Akamai": [r"akamai", r"x-akamai"],
        "Imperva": [r"imperva", r"incap_ses"],
        "AWS WAF": [r"x-amzn-waf"],
        "Sucuri": [r"sucuri", r"x-sucuri"],
        
        # UI Frameworks
        "Bootstrap": [r"bootstrap"],
        "Tailwind": [r"tailwind"],
        "Material-UI": [r"material-ui", r"@mui"],
        "Chakra UI": [r"chakra-ui"],
        
        # Build Tools
        "Webpack": [r"webpack", r"webpackJsonp"],
        "Vite": [r"vite", r"@vite"],
        "Parcel": [r"parcel"],
    }
    
    # Common paths to check (modern API-centric paths)
    COMMON_PATHS = [
        "/",
        "/login", "/signin", "/auth/login",
        "/register", "/signup", "/auth/register",
        "/admin", "/admin/login", "/administrator",
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/api/users", "/api/user", "/api/me",
        "/api/products", "/api/items",
        "/api/search", "/api/query",
        "/api/auth", "/api/auth/login",
        "/rest", "/rest/api", "/rest/v1",
        "/rest/user", "/rest/users",
        "/rest/products", "/rest/products/search",
        "/rest/basket", "/rest/cart",
        "/graphql", "/graphql/v1",
        "/dashboard", "/profile", "/account",
        "/search", "/contact", "/products",
        "/cart", "/checkout", "/basket",
        "/health", "/healthz", "/status",
        "/metrics", "/ping",
        # OWASP Juice Shop specific vulnerable endpoints
        "/rest/user/login",  # SQL injection vulnerable
        "/rest/user/whoami",
        "/rest/user/change-password",
        "/rest/user/reset-password",
        "/rest/products/search?q=test",  # SQL injection vulnerable
        "/rest/saveLoginIp",
        "/rest/basket/1",
        "/rest/order-history",
        "/api/Products",
        "/api/Products/1",
        "/api/Users",
        "/api/Feedbacks",
        "/api/Complaints",
        "/api/Recycles",
        "/api/SecurityQuestions",
        "/api/Challenges",
        "/api/Quantitys",
        "/api/BasketItems",
        "/ftp",  # Directory listing
        "/encryptionkeys",
        "/support/logs",
        # Common vulnerable test patterns with parameters
        "/search?q=test",
        "/search?query=test",
        "/api/search?q=test",
        "/api/search?term=test",
        "/products?id=1",
        "/user?id=1",
        "/item?id=1",
        "/page?id=1",
        "/article?id=1",
        "/view?id=1",
        "/profile?id=1",
        "/download?file=test",
        "/file?name=test",
        "/redirect?url=http://example.com",
        "/redirect?to=http://example.com",
    ]
    
    # API documentation paths
    API_DOC_PATHS = [
        "/swagger.json", "/swagger.yml", "/swagger.yaml",
        "/openapi.json", "/openapi.yml", "/openapi.yaml",
        "/api-docs", "/api-docs.json", "/api/docs",
        "/v2/api-docs", "/v3/api-docs",
        "/swagger-ui.html", "/swagger-ui/",
        "/docs", "/documentation",
        "/redoc", "/rapidoc",
        "/.well-known/security.txt",
        "/graphql", "/graphiql",
        "/api/swagger.json", "/api/openapi.json",
    ]
    
    # Patterns for extracting endpoints from JavaScript
    JS_ENDPOINT_PATTERNS = [
        r'["\']/(api/[^"\'\s<>{}]+)["\']',           # /api/*
        r'["\']/(rest/[^"\'\s<>{}]+)["\']',          # /rest/*
        r'["\']/(graphql)["\']',                      # GraphQL
        r'fetch\s*\(["\']([^"\')]+)["\']',           # fetch() calls
        r'axios\.[a-z]+\s*\(["\']([^"\')]+)',       # axios calls
        r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\')]+)', # jQuery ajax
        r'(?:get|post|put|delete|patch)\s*\(["\']([^"\')]+)', # HTTP method calls
        r'request\s*\(["\']([^"\')]+)',              # Generic request
        r'endpoint\s*[:=]\s*["\']([^"\')]+)',        # endpoint variable
        r'url\s*[:=]\s*["\']([^"\')]+)',             # url variable
        r'"((?:/api|/rest|/graphql)[a-zA-Z0-9/_-]+)"', # API paths
    ]
    
    def __init__(
        self,
        timeout: float = 30.0,
        max_depth: int = 2,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
        max_concurrent: int = 10
    ):
        """
        Initialize the target analyzer.
        
        Args:
            timeout: HTTP request timeout
            max_depth: Maximum crawl depth
            auth_headers: Optional authentication headers
            auth_cookies: Optional authentication cookies
            max_concurrent: Maximum concurrent requests
        """
        self.timeout = timeout
        self.max_depth = max_depth
        self.max_concurrent = max_concurrent
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        
        # Build headers
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/json,*/*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if auth_headers:
            headers.update(auth_headers)
        
        # Build cookies
        cookies = auth_cookies or {}
        
        self.http_client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers=headers,
            cookies=cookies
        )
        
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
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
        self.discovered_endpoints.clear()
        
        # Ensure URL has scheme
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"
        
        analysis = TargetAnalysis(target_url=target_url)
        
        print(f"[Analyzer] Starting analysis of {target_url}")
        
        # Get initial page
        try:
            response = await self._fetch_with_error_handling(target_url)
            if not response:
                print(f"[Analyzer] Failed to fetch {target_url}")
                return analysis
            
            analysis.status_code = response.status_code
            analysis.headers = dict(response.headers)
            analysis.cookies = [str(c) for c in response.cookies.jar]
            
            # Get server header
            analysis.server = response.headers.get("Server", "Unknown")
            
            # Extract security headers
            analysis.security_headers = self._extract_security_headers(response.headers)
            
            # Detect WAF
            analysis.waf_detected = self._detect_waf(response.headers, response.text)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, "lxml")
            
            # Detect technologies
            analysis.technology_stack = await self._detect_technology(
                response.headers, 
                response.text,
                soup
            )
            
            # Extract forms (including modern patterns)
            analysis.forms = self._extract_forms(soup, target_url)
            
            # Extract scripts
            analysis.scripts = self._extract_scripts(soup, target_url)
            
            # Discover API documentation
            analysis.api_docs = await self._discover_api_docs(target_url)
            
            # Discover endpoints (concurrent probing)
            endpoints = await self._discover_endpoints(
                target_url,
                soup,
                response.text,
                depth=0
            )
            
            # Analyze external JavaScript files concurrently
            js_endpoints = await self._analyze_javascript_files(
                analysis.scripts,
                target_url
            )
            endpoints.extend(js_endpoints)
            
            # Deduplicate endpoints
            seen = set()
            unique_endpoints = []
            for ep in endpoints:
                key = (ep.url, ep.method)
                if key not in seen:
                    seen.add(key)
                    unique_endpoints.append(ep)
            
            analysis.endpoints = unique_endpoints
            
        except Exception as e:
            print(f"[Analyzer] Error analyzing {target_url}: {e}")
        
        print(f"[Analyzer] Analysis complete. Found {len(analysis.endpoints)} endpoints, "
              f"{len(analysis.technology_stack)} technologies, {len(analysis.api_docs)} API docs")
        
        return analysis
    
    async def _fetch_with_error_handling(
        self,
        url: str,
        method: str = "GET",
        **kwargs
    ) -> Optional[httpx.Response]:
        """
        Fetch URL with comprehensive error handling.
        
        Args:
            url: URL to fetch
            method: HTTP method
            **kwargs: Additional arguments for httpx
            
        Returns:
            Response or None if failed
        """
        try:
            async with self.semaphore:
                if method == "GET":
                    response = await self.http_client.get(url, **kwargs)
                elif method == "HEAD":
                    response = await self.http_client.head(url, **kwargs)
                else:
                    response = await self.http_client.request(method, url, **kwargs)
                
                # Handle different encodings
                if response.status_code < 400:
                    try:
                        _ = response.text
                    except UnicodeDecodeError:
                        # Try different encodings
                        for encoding in ['utf-8', 'iso-8859-1', 'windows-1252']:
                            try:
                                response.encoding = encoding
                                _ = response.text
                                break
                            except:
                                continue
                
                return response
                
        except httpx.TimeoutException:
            print(f"[Analyzer] Timeout fetching {url}")
        except httpx.ConnectError:
            print(f"[Analyzer] Connection error to {url}")
        except httpx.TooManyRedirects:
            print(f"[Analyzer] Too many redirects for {url}")
        except Exception as e:
            print(f"[Analyzer] Error fetching {url}: {e}")
        
        return None
    
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
        
        # Check for common framework files
        script_srcs = [s.get("src", "") for s in soup.find_all("script", src=True)]
        for src in script_srcs:
            src_lower = src.lower()
            if "react" in src_lower:
                detected.add("React")
            if "vue" in src_lower:
                detected.add("Vue.js")
            if "angular" in src_lower:
                detected.add("Angular")
        
        return sorted(list(detected))
    
    def _extract_security_headers(self, headers: httpx.Headers) -> Dict[str, str]:
        """Extract security-related headers."""
        security_headers = {}
        security_header_names = [
            "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
            "Strict-Transport-Security", "X-XSS-Protection", "Referrer-Policy",
            "Permissions-Policy", "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy"
        ]
        
        for header_name in security_header_names:
            if header_name in headers:
                security_headers[header_name] = headers[header_name]
        
        return security_headers
    
    def _detect_waf(self, headers: httpx.Headers, content: str) -> Optional[str]:
        """Detect Web Application Firewall."""
        headers_str = str(headers).lower()
        
        waf_signatures = {
            "Cloudflare": ["cf-ray", "cloudflare"],
            "Akamai": ["akamai", "x-akamai"],
            "Imperva": ["imperva", "incap_ses", "visid_incap"],
            "AWS WAF": ["x-amzn-waf", "x-amzn-requestid"],
            "Sucuri": ["sucuri", "x-sucuri"],
            "ModSecurity": ["mod_security", "naxsi"],
        }
        
        for waf, signatures in waf_signatures.items():
            for sig in signatures:
                if sig in headers_str:
                    return waf
        
        return None
    
    def _extract_forms(
        self,
        soup: BeautifulSoup,
        base_url: str
    ) -> List[Dict[str, Any]]:
        """
        Extract forms from the page, including modern SPA patterns.
        
        Args:
            soup: Parsed HTML
            base_url: Base URL for resolving relative paths
            
        Returns:
            List of form data
        """
        forms = []
        
        # Traditional forms
        for form in soup.find_all("form"):
            form_data = {
                "action": urljoin(base_url, form.get("action", "")),
                "method": form.get("method", "GET").upper(),
                "inputs": [],
                "has_file_upload": False,
                "has_password": False,
                "form_type": "traditional",
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
                        "placeholder": input_elem.get("placeholder", ""),
                    })
                
                if input_type == "file":
                    form_data["has_file_upload"] = True
                if input_type == "password":
                    form_data["has_password"] = True
            
            forms.append(form_data)
        
        # Detect modern SPA forms (buttons with event handlers)
        # Look for login/submit buttons that might be part of SPA forms
        for button in soup.find_all(["button", "input"], type=["submit", "button"]):
            # Check if button has onClick or similar handlers
            if button.get("onclick") or button.get("data-action"):
                button_text = button.get_text(strip=True).lower()
                button_id = button.get("id", "").lower()
                
                # Look for login/submit patterns
                if any(keyword in button_text or keyword in button_id 
                       for keyword in ["login", "signin", "submit", "register", "signup"]):
                    
                    # Find nearby inputs
                    parent = button.find_parent(["div", "section", "main"])
                    if parent:
                        inputs = parent.find_all("input")
                        if inputs:
                            form_data = {
                                "action": base_url,
                                "method": "POST",
                                "inputs": [],
                                "has_file_upload": False,
                                "has_password": False,
                                "form_type": "spa",
                            }
                            
                            for input_elem in inputs:
                                input_type = input_elem.get("type", "text")
                                input_name = input_elem.get("name") or input_elem.get("id", "")
                                
                                if input_name:
                                    form_data["inputs"].append({
                                        "name": input_name,
                                        "type": input_type,
                                        "value": input_elem.get("value", ""),
                                        "required": input_elem.has_attr("required"),
                                        "placeholder": input_elem.get("placeholder", ""),
                                    })
                                
                                if input_type == "password":
                                    form_data["has_password"] = True
                            
                            if form_data["inputs"]:
                                forms.append(form_data)
        
        return forms
    
    async def _discover_endpoints(
        self,
        base_url: str,
        soup: BeautifulSoup,
        html_content: str,
        depth: int = 0
    ) -> List[DiscoveredEndpoint]:
        """
        Discover endpoints from the page with recursive crawling.
        
        Args:
            base_url: Base URL
            soup: Parsed HTML
            html_content: Raw HTML
            depth: Current crawl depth
            
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
                    
                    # Parse query parameters
                    query_params = {}
                    if parsed_url.query:
                        for key, values in parse_qs(parsed_url.query).items():
                            query_params[key] = values[0] if values else ""
                    
                    endpoints.append(DiscoveredEndpoint(
                        url=full_url.split("?")[0],
                        method="GET",
                        params=query_params,
                        source="html_link"
                    ))
        
        # Extract URLs from JavaScript
        for pattern in self.JS_ENDPOINT_PATTERNS:
            js_urls = re.findall(pattern, html_content)
            for url in js_urls:
                # Skip static assets
                if any(ext in url.lower() for ext in ['.js', '.css', '.png', '.jpg', '.svg', '.woff', '.ico']):
                    continue
                
                full_url = urljoin(base_url, url if url.startswith('/') else '/' + url)
                
                endpoint_key = full_url.split("?")[0]
                if endpoint_key not in self.discovered_endpoints:
                    self.discovered_endpoints.add(endpoint_key)
                    
                    parsed_url = urlparse(full_url)
                    query_params = {}
                    if parsed_url.query:
                        for key, values in parse_qs(parsed_url.query).items():
                            query_params[key] = values[0] if values else ""
                    
                    endpoints.append(DiscoveredEndpoint(
                        url=endpoint_key,
                        method="GET",
                        params=query_params,
                        source="javascript"
                    ))
        
        # Concurrent probing of common paths
        common_path_endpoints = await self._probe_common_paths(base_url)
        endpoints.extend(common_path_endpoints)
        
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
                params=params,
                source="form"
            ))
        
        # Recursive crawling (if depth permits)
        if depth < self.max_depth:
            crawl_tasks = []
            for link in soup.find_all("a", href=True)[:10]:  # Limit to 10 links per page
                href = link.get("href", "")
                full_url = urljoin(base_url, href)
                parsed_url = urlparse(full_url)
                
                # Only crawl same-host HTML pages
                if (parsed_url.netloc == parsed_base.netloc and 
                    full_url not in self.visited_urls and
                    not any(ext in full_url.lower() for ext in ['.pdf', '.zip', '.jpg', '.png'])):
                    
                    self.visited_urls.add(full_url)
                    crawl_tasks.append(self._crawl_page(full_url, depth + 1))
            
            if crawl_tasks:
                crawl_results = await asyncio.gather(*crawl_tasks, return_exceptions=True)
                for result in crawl_results:
                    if isinstance(result, list):
                        endpoints.extend(result)
        
        return endpoints
    
    async def _probe_common_paths(self, base_url: str) -> List[DiscoveredEndpoint]:
        """
        Probe common paths concurrently.
        
        Args:
            base_url: Base URL
            
        Returns:
            List of discovered endpoints
        """
        async def probe_path(path: str) -> Optional[DiscoveredEndpoint]:
            full_url = urljoin(base_url, path)
            
            # Check without query string to avoid duplicates
            base_check_url = full_url.split("?")[0]
            if base_check_url in self.visited_urls:
                return None
            
            try:
                response = await self._fetch_with_error_handling(full_url, method="HEAD", timeout=5.0)
                if response and response.status_code < 400:
                    self.visited_urls.add(base_check_url)
                    
                    # Parse query parameters from the path
                    parsed_url = urlparse(full_url)
                    query_params = {}
                    if parsed_url.query:
                        for key, values in parse_qs(parsed_url.query).items():
                            query_params[key] = values[0] if values else ""
                    
                    return DiscoveredEndpoint(
                        url=base_check_url,  # URL without query string
                        method="GET",
                        params=query_params,  # Include extracted params
                        requires_auth=response.status_code in [401, 403],
                        content_type=response.headers.get("Content-Type", ""),
                        source="common_path"
                    )
            except:
                pass
            
            return None
        
        # Probe all paths concurrently
        tasks = [probe_path(path) for path in self.COMMON_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out None values and exceptions
        endpoints = [r for r in results if isinstance(r, DiscoveredEndpoint)]
        return endpoints
    
    async def _crawl_page(self, url: str, depth: int) -> List[DiscoveredEndpoint]:
        """
        Crawl a single page and extract endpoints.
        
        Args:
            url: URL to crawl
            depth: Current depth
            
        Returns:
            List of discovered endpoints
        """
        endpoints = []
        
        try:
            response = await self._fetch_with_error_handling(url, timeout=10.0)
            if not response or response.status_code >= 400:
                return endpoints
            
            soup = BeautifulSoup(response.text, "lxml")
            endpoints = await self._discover_endpoints(url, soup, response.text, depth)
            
        except Exception as e:
            print(f"[Analyzer] Error crawling {url}: {e}")
        
        return endpoints
    
    async def _discover_api_docs(self, base_url: str) -> List[Dict[str, str]]:
        """
        Discover API documentation endpoints.
        
        Args:
            base_url: Base URL
            
        Returns:
            List of API documentation endpoints
        """
        async def check_doc_path(path: str) -> Optional[Dict[str, str]]:
            full_url = urljoin(base_url, path)
            
            try:
                response = await self._fetch_with_error_handling(full_url, timeout=5.0)
                if response and response.status_code == 200:
                    content_type = response.headers.get("Content-Type", "")
                    
                    # Check if it's JSON or HTML documentation
                    if "json" in content_type or "yaml" in content_type or "html" in content_type:
                        return {
                            "url": full_url,
                            "type": "openapi" if "openapi" in path or "swagger" in path else "graphql" if "graphql" in path else "other",
                            "content_type": content_type
                        }
            except:
                pass
            
            return None
        
        # Check all API doc paths concurrently
        tasks = [check_doc_path(path) for path in self.API_DOC_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out None values
        docs = [r for r in results if isinstance(r, dict)]
        
        if docs:
            print(f"[Analyzer] Found {len(docs)} API documentation endpoints")
        
        return docs
    
    async def _analyze_javascript_files(
        self,
        script_urls: List[str],
        base_url: str
    ) -> List[DiscoveredEndpoint]:
        """
        Fetch and analyze external JavaScript files for endpoints.
        
        Args:
            script_urls: List of script URLs
            base_urls: Base URL for resolution
            
        Returns:
            List of discovered endpoints
        """
        endpoints = []
        
        async def analyze_script(script_url: str) -> List[DiscoveredEndpoint]:
            script_endpoints = []
            
            # Resolve relative URLs
            full_url = urljoin(base_url, script_url)
            
            # Skip very large bundled files (>1MB based on URL patterns)
            if any(pattern in script_url.lower() for pattern in ['vendor', 'chunk', 'bundle']):
                # Still analyze but with size limit
                try:
                    response = await self._fetch_with_error_handling(full_url, timeout=10.0)
                    if not response:
                        return script_endpoints
                    
                    # Limit content size
                    content = response.text[:500000]  # First 500KB
                    
                    # Extract endpoints using patterns
                    for pattern in self.JS_ENDPOINT_PATTERNS:
                        urls = re.findall(pattern, content)
                        for url in urls:
                            # Skip static assets
                            if any(ext in url.lower() for ext in ['.js', '.css', '.png', '.jpg', '.svg']):
                                continue
                            
                            full_endpoint_url = urljoin(base_url, url if url.startswith('/') else '/' + url)
                            
                            endpoint_key = full_endpoint_url.split("?")[0]
                            if endpoint_key not in self.discovered_endpoints:
                                self.discovered_endpoints.add(endpoint_key)
                                
                                script_endpoints.append(DiscoveredEndpoint(
                                    url=endpoint_key,
                                    method="GET",
                                    source=f"external_js:{script_url}"
                                ))
                
                except Exception as e:
                    print(f"[Analyzer] Error analyzing script {script_url}: {e}")
            
            return script_endpoints
        
        # Limit to first 20 scripts and analyze concurrently
        tasks = [analyze_script(url) for url in script_urls[:20]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                endpoints.extend(result)
        
        if endpoints:
            print(f"[Analyzer] Found {len(endpoints)} endpoints from JavaScript analysis")
        
        return endpoints
    
    def _extract_scripts(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """
        Extract script sources from the page.
        
        Args:
            soup: Parsed HTML
            base_url: Base URL for resolving relative paths
            
        Returns:
            List of script URLs
        """
        scripts = []
        
        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src:
                full_url = urljoin(base_url, src)
                scripts.append(full_url)
        
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
            "api_documentation": len(analysis.api_docs) > 0,
            "input_points": [],
            "technologies": analysis.technology_stack,
            "security_posture": {
                "waf_detected": analysis.waf_detected,
                "security_headers": len(analysis.security_headers),
                "has_csp": "Content-Security-Policy" in analysis.security_headers,
                "has_hsts": "Strict-Transport-Security" in analysis.security_headers,
            },
            "risk_factors": [],
            "endpoint_sources": {},
        }
        
        # Count endpoints by source
        for endpoint in analysis.endpoints:
            source = endpoint.source
            attack_surface["endpoint_sources"][source] = attack_surface["endpoint_sources"].get(source, 0) + 1
        
        # Identify input points
        for endpoint in analysis.endpoints:
            if endpoint.params:
                attack_surface["input_points"].append({
                    "url": endpoint.url,
                    "method": endpoint.method,
                    "params": list(endpoint.params.keys()),
                    "source": endpoint.source
                })
        
        # Add risk factors
        if attack_surface["has_login"]:
            attack_surface["risk_factors"].append("authentication_forms")
        if attack_surface["has_file_upload"]:
            attack_surface["risk_factors"].append("file_upload")
        if len(analysis.endpoints) > 50:
            attack_surface["risk_factors"].append("large_attack_surface")
        if not analysis.security_headers:
            attack_surface["risk_factors"].append("missing_security_headers")
        if not analysis.waf_detected:
            attack_surface["risk_factors"].append("no_waf_detected")
        if attack_surface["api_documentation"]:
            attack_surface["risk_factors"].append("exposed_api_documentation")
        
        return attack_surface