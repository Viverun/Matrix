"""
XSS (Cross-Site Scripting) Security Agent - Detects XSS vulnerabilities.
"""
from typing import List, Dict, Any
import re
import html
from urllib.parse import urljoin, urlparse, quote

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType


class XSSAgent(BaseSecurityAgent):
    """
    Cross-Site Scripting (XSS) testing agent.
    
    Tests for various XSS vulnerabilities:
    - Reflected XSS
    - Stored XSS (basic detection)
    - DOM-based XSS indicators
    """
    
    agent_name = "xss"
    agent_description = "Detects Cross-Site Scripting (XSS) vulnerabilities"
    vulnerability_types = [
        VulnerabilityType.XSS_REFLECTED,
        VulnerabilityType.XSS_STORED,
        VulnerabilityType.XSS_DOM
    ]
    
    # XSS payloads - arranged by evasion technique
    BASIC_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
    ]
    
    ENCODED_PAYLOADS = [
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
    ]
    
    ATTRIBUTE_PAYLOADS = [
        "\" onmouseover=\"alert('XSS')\"",
        "' onfocus='alert(1)' autofocus='",
        "\" onfocus=\"alert(1)\" autofocus=\"",
        "' onclick='alert(1)'",
        "\" onclick=\"alert(1)\"",
    ]
    
    EVENT_HANDLER_PAYLOADS = [
        "<div onmouseover='alert(1)'>hover me</div>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
    ]
    
    POLYGLOT_PAYLOADS = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//>;",
        "'\"--></style></script><script>alert('XSS')</script>",
    ]
    
    # Unique marker for reflection detection
    REFLECTION_MARKER = "MATRIX_XSS_TEST_"
    
    # DOM XSS sink patterns
    DOM_SINKS = [
        r"document\.write\s*\(",
        r"document\.writeln\s*\(",
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"\.insertAdjacentHTML\s*\(",
        r"eval\s*\(",
        r"setTimeout\s*\([^,]*\+",
        r"setInterval\s*\([^,]*\+",
        r"new\s+Function\s*\(",
        r"location\s*=",
        r"location\.href\s*=",
        r"location\.replace\s*\(",
        r"location\.assign\s*\(",
    ]
    
    def __init__(self, **kwargs):
        """Initialize XSS agent."""
        super().__init__(**kwargs)
        self.dom_sink_patterns = [re.compile(p, re.IGNORECASE) for p in self.DOM_SINKS]
        self.test_id = 0
    
    async def scan(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        technology_stack: List[str] = None
    ) -> List[AgentResult]:
        """
        Scan for XSS vulnerabilities.
        
        Args:
            target_url: Base URL
            endpoints: Endpoints to test
            technology_stack: Detected technologies
            
        Returns:
            List of found vulnerabilities
        """
        results = []
        
        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "GET")
            params = endpoint.get("params", {})
            
            # Test each parameter for reflected XSS
            for param_name in params.keys():
                result = await self._test_reflected_xss(
                    url, method, params, param_name
                )
                if result:
                    results.append(result)
            
            # Check for DOM XSS indicators in the page
            dom_result = await self._check_dom_xss(url)
            if dom_result:
                results.append(dom_result)
        
        return results
    
    async def _test_reflected_xss(
        self,
        url: str,
        method: str,
        params: Dict,
        param_name: str
    ) -> AgentResult | None:
        """
        Test for reflected XSS in a parameter.
        
        Args:
            url: Target URL
            method: HTTP method
            params: Parameters
            param_name: Parameter to test
            
        Returns:
            AgentResult if vulnerable, None otherwise
        """
        self.test_id += 1
        marker = f"{self.REFLECTION_MARKER}{self.test_id}"
        
        # First, test if we have reflection at all
        test_params = params.copy()
        test_params[param_name] = marker
        
        try:
            if method.upper() == "GET":
                response = await self.make_request(url, method="GET", params=test_params)
            else:
                response = await self.make_request(url, method=method, data=test_params)
            
            if response is None:
                return None
            
            response_text = response.text
            
            # Check if our marker is reflected
            if marker not in response_text:
                return None  # No reflection, skip XSS tests
            
            # Try XSS payloads
            all_payloads = (
                self.BASIC_PAYLOADS + 
                self.ATTRIBUTE_PAYLOADS + 
                self.EVENT_HANDLER_PAYLOADS
            )
            
            for payload in all_payloads:
                test_params[param_name] = payload
                
                if method.upper() == "GET":
                    response = await self.make_request(url, method="GET", params=test_params)
                else:
                    response = await self.make_request(url, method=method, data=test_params)
                
                if response is None:
                    continue
                
                response_text = response.text
                
                # Check if payload is reflected without proper encoding
                if self._is_xss_reflected(payload, response_text):
                    # Use AI to analyze
                    ai_analysis = await self.analyze_with_ai(
                        vulnerability_type="Cross-Site Scripting (Reflected)",
                        context=f"Tested parameter '{param_name}' with payload: {payload}",
                        response_data=response_text[:1500]
                    )
                    
                    return self.create_result(
                        vulnerability_type=VulnerabilityType.XSS_REFLECTED,
                        is_vulnerable=True,
                        severity=Severity.HIGH,
                        confidence=ai_analysis.get("confidence", 85),
                        url=url,
                        parameter=param_name,
                        method=method,
                        title=f"Reflected XSS in '{param_name}' parameter",
                        description=f"A reflected Cross-Site Scripting (XSS) vulnerability was detected. User input in the '{param_name}' parameter is reflected back in the response without proper encoding, allowing execution of arbitrary JavaScript.",
                        evidence=f"Payload reflected: {payload}",
                        ai_analysis=ai_analysis.get("reason", ""),
                        remediation="Encode all user input before reflecting it in the response. Use context-appropriate encoding (HTML entity encoding for HTML context, JavaScript encoding for JS context). Implement Content Security Policy (CSP) headers.",
                        owasp_category="A03:2021 – Cross-Site Scripting",
                        cwe_id="CWE-79",
                        reference_links=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                        ],
                        request_data={"params": test_params, "payload": payload},
                        response_snippet=response_text[:500]
                    )
            
        except Exception as e:
            print(f"[XSS Agent] Error testing {param_name}: {e}")
        
        return None
    
    def _is_xss_reflected(self, payload: str, response: str) -> bool:
        """
        Check if XSS payload is reflected in a dangerous way.
        
        Args:
            payload: XSS payload used
            response: Response text
            
        Returns:
            True if payload is dangerously reflected
        """
        # Check for exact reflection (no encoding)
        if payload in response:
            return True
        
        # Check for partial reflection of dangerous elements
        dangerous_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=",
            r"<svg[^>]*onload",
            r"<img[^>]*onerror",
            r"<body[^>]*onload",
            r"<iframe[^>]*src\s*=\s*[\"']?javascript:",
        ]
        
        # Extract key parts of payload
        for pattern in dangerous_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                if re.search(pattern, response, re.IGNORECASE):
                    return True
        
        return False
    
    async def _check_dom_xss(self, url: str) -> AgentResult | None:
        """
        Check for DOM XSS indicators in JavaScript.
        
        Args:
            url: URL to check
            
        Returns:
            AgentResult if potential DOM XSS found, None otherwise
        """
        try:
            response = await self.make_request(url)
            if response is None:
                return None
            
            response_text = response.text
            
            # Look for dangerous DOM sinks
            found_sinks = []
            for pattern in self.dom_sink_patterns:
                matches = pattern.findall(response_text)
                if matches:
                    found_sinks.extend(matches)
            
            if found_sinks:
                # Check if user input sources are nearby
                source_patterns = [
                    r"location\.search",
                    r"location\.hash",
                    r"document\.referrer",
                    r"window\.name",
                    r"document\.cookie",
                ]
                
                has_sources = any(
                    re.search(p, response_text, re.IGNORECASE) 
                    for p in source_patterns
                )
                
                if has_sources:
                    return self.create_result(
                        vulnerability_type=VulnerabilityType.XSS_DOM,
                        is_vulnerable=True,
                        severity=Severity.MEDIUM,
                        confidence=60,  # Lower confidence as it needs manual verification
                        url=url,
                        title="Potential DOM-based XSS",
                        description="The page contains JavaScript code with dangerous DOM sinks that process user-controllable sources. This may lead to DOM-based XSS if user input is not properly sanitized.",
                        evidence=f"Found sinks: {', '.join(set(found_sinks[:5]))}",
                        remediation="Avoid using dangerous DOM sinks like innerHTML. Use textContent instead. Sanitize all user input before using it in DOM operations.",
                        owasp_category="A03:2021 – Cross-Site Scripting",
                        cwe_id="CWE-79",
                        reference_links=[
                            "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                            "https://portswigger.net/web-security/cross-site-scripting/dom-based"
                        ]
                    )
            
        except Exception as e:
            print(f"[XSS Agent] DOM check error: {e}")
        
        return None
