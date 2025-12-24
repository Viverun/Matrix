"""
Test Bench - Intentionally Vulnerable Endpoints
WARNING: DO NOT ENABLE IN PRODUCTION
"""
from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/test", tags=["Test Bench"])

class LoginRequest(BaseModel):
    username: str
    password: str

@router.get("/xss")
async def xss_vulnerability(q: str = ""):
    """
    Vulnerable to Reflected XSS.
    Reflects the 'q' parameter directly without sanitization.
    """
    # VULNERABLE CODE: Returning user input directly in HTML
    html_content = f"""
    <html>
        <body>
            <h1>Search Results</h1>
            <p>You searched for: {q}</p>
        </body>
    </html>
    """
    return Response(content=html_content, media_type="text/html")

@router.get("/sqli")
async def sqli_vulnerability(id: str = ""):
    """
    Vulnerable to SQL Injection.
    Simulates a vulnerable SQL query.
    """
    # VULNERABLE CODE: Simulating a SQL injection flaw
    if "'" in id:
        if "OR" in id.upper():
            # Simulate successful injection returning all users
            return {
                "query": f"SELECT * FROM users WHERE id = '{id}'",
                "result": [
                    {"id": 1, "username": "admin", "role": "admin"},
                    {"id": 2, "username": "user", "role": "user"},
                    {"id": 3, "username": "guest", "role": "guest"}
                ],
                "status": "vulnerable_success"
            }
        else:
            # Simulate SQL Syntax Error for error-based detection
            return Response(
                content="SQL syntax error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
                status_code=500
            )
    
    return {
        "query": f"SELECT * FROM users WHERE id = '{id}'",
        "result": [],
        "status": "no_results"
    }

@router.post("/auth-bypass")
async def auth_bypass(creds: LoginRequest):
    """
    Vulnerable to Authentication Bypass/Weak Password.
    Accepts 'admin' / 'admin'.
    """
    # VULNERABLE CODE: Hardcoded weak credentials
    if creds.username == "admin" and creds.password == "admin":
        return {"status": "success", "message": "Logged in as admin", "token": "vulnerable_token_123"}
    
    raise HTTPException(status_code=401, detail="Invalid credentials")
