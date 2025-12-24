"""
Groq AI client for security analysis.
Replaces the previous Gemini client.
"""
import asyncio
import os
from typing import Optional, List, Dict, Any
from groq import Groq
from config import get_settings
from core.scan_context import llm_cache

settings = get_settings()


# =============================================================================
# STRUCTURED PROMPT TEMPLATES
# =============================================================================
# All prompts enforce structured output for consistency and quality.
# Format: Finding → Evidence → Impact → Exploitability → Severity Justification
# =============================================================================

PROMPT_TEMPLATES = {
    "sql_injection": {
        "system": "You are a database security expert. Provide precise, evidence-based SQL injection analysis. No hyperbole.",
        "template": """**STRUCTURED ANALYSIS REQUIRED**

## Input
- **Vulnerability Type**: SQL Injection
- **Test Payload**: {context}
- **Server Response**:
```
{response_data}
```

## Reference Examples

**TRUE POSITIVE:**
Response: "You have an error in your SQL syntax; check the manual..."
→ VULNERABLE: Database error message leaked, confirms SQL parsing of input

**FALSE POSITIVE:**
Response: "Invalid input format. Please enter a valid number."
→ NOT VULNERABLE: Generic validation, no database interaction evidence

## Your Structured Analysis

Provide analysis in this EXACT structure:

1. **Finding**: [State what you found - vulnerable or not]
2. **Evidence**: [Quote specific response text that proves your conclusion]
3. **Impact**: [What could an attacker achieve if this is exploited?]
4. **Exploitability Conditions**: [What must be true for exploitation? Auth required? User interaction?]
5. **Severity Justification**: [Why this severity level is appropriate]

**Detection Criteria:**
- Database error messages (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Syntax error patterns with SQL keywords
- Time-based response delays matching SLEEP/WAITFOR
- UNION query data extraction indicators

Respond ONLY in valid JSON:
{{
    "is_vulnerable": boolean,
    "confidence": number (0-100),
    "finding": "one-line finding statement",
    "evidence": ["specific quoted text from response"],
    "impact": "what attacker could achieve",
    "exploitability_conditions": "requirements for exploitation",
    "severity_justification": "why this severity",
    "likelihood": number (0.0-10.0),
    "impact_score": number (0.0-10.0),
    "reason": "detailed technical explanation",
    "recommendations": ["remediation steps"]
}}"""
    },
    
    "xss_reflected": {
        "system": "You are a web security expert. Detect XSS with minimal false positives. Evidence required.",
        "template": """**STRUCTURED ANALYSIS REQUIRED**

## Input
- **Vulnerability Type**: Reflected Cross-Site Scripting (XSS)
- **Test Payload**: {context}
- **Server Response**:
```
{response_data}
```

## Reference Examples

**TRUE POSITIVE:**
Payload: `<script>alert('XSS')</script>`
Response: `Hello <script>alert('XSS')</script>!`
→ VULNERABLE: Payload reflected unescaped in HTML body context

**FALSE POSITIVE:**
Payload: `<script>alert('XSS')</script>`
Response: `Hello &lt;script&gt;alert('XSS')&lt;/script&gt;!`
→ NOT VULNERABLE: Payload properly HTML-encoded

**TRUE POSITIVE (Attribute Context):**
Payload: `" onload="alert(1)`
Response: `<input value="" onload="alert(1)">`
→ VULNERABLE: Attribute injection, broke out of quotes

## Your Structured Analysis

1. **Finding**: [Vulnerable or not vulnerable]
2. **Evidence**: [Quote the EXACT response text showing unescaped reflection]
3. **Impact**: [Session hijacking? Cookie theft? What specifically?]
4. **Exploitability Conditions**: [User interaction required? Same-origin? Auth state?]
5. **Severity Justification**: [Reflected = typically Medium unless chained]

**Detection Criteria:**
- Unescaped payload reflection (NOT encoded as &lt; &gt; etc.)
- Context breakout (tag, attribute, script block, event handler)
- DOM sink manipulation

Respond ONLY in valid JSON:
{{
    "is_vulnerable": boolean,
    "confidence": number (0-100),
    "finding": "one-line finding statement",
    "evidence": ["exact quoted reflection from response"],
    "impact": "specific attack outcome",
    "exploitability_conditions": "what's required for exploitation",
    "severity_justification": "why this severity",
    "likelihood": number (0.0-10.0),
    "impact_score": number (0.0-10.0),
    "reason": "detailed technical explanation",
    "recommendations": ["remediation steps"]
}}"""
    },
    
    "broken_auth": {
        "system": "You are an authentication security expert. Precise, evidence-based analysis only.",
        "template": """**STRUCTURED ANALYSIS REQUIRED**

## Input
- **Vulnerability Type**: Broken Authentication
- **Test Context**: {context}
- **Response Data**:
```
{response_data}
```

## Reference Examples

**TRUE POSITIVE (Username Enumeration):**
Login "admin"/"wrong": "Incorrect password"
Login "nouser"/"wrong": "User not found"
→ VULNERABLE: Different errors reveal valid usernames

**FALSE POSITIVE:**
Login any credentials: "Invalid credentials"
→ NOT VULNERABLE: Generic error, no enumeration

**TRUE POSITIVE (Insecure Session):**
Cookie: `sessionid=12345; Path=/;`
→ VULNERABLE: Missing HttpOnly, Secure, SameSite flags

## Your Structured Analysis

1. **Finding**: [What auth weakness exists?]
2. **Evidence**: [Quote exact response differences or cookie values]
3. **Impact**: [Account takeover? Brute force enabled? Session hijack?]
4. **Exploitability Conditions**: [Network position? Time required?]
5. **Severity Justification**: [Based on direct exploitability]

Respond ONLY in valid JSON:
{{
    "is_vulnerable": boolean,
    "confidence": number (0-100),
    "finding": "one-line finding statement",
    "evidence": ["specific auth weakness evidence"],
    "impact": "account compromise potential",
    "exploitability_conditions": "attack requirements",
    "severity_justification": "why this severity",
    "likelihood": number (0.0-10.0),
    "impact_score": number (0.0-10.0),
    "reason": "detailed explanation",
    "recommendations": ["remediation steps"]
}}"""
    },
    
    "sensitive_data": {
        "system": "You are a data privacy expert. Identify sensitive data exposure in code and responses.",
        "template": """**STRUCTURED ANALYSIS REQUIRED**

## Input
- **Vulnerability Type**: Sensitive Data Exposure
- **Context**: {context}
- **Data Found**:
```
{response_data}
```

## Reference Examples

**TRUE POSITIVE:**
Data: `"api_key": "sk-abc123xyz456"`
→ VULNERABLE: Hardcoded API key (not a placeholder)

**FALSE POSITIVE:**
Data: `"api_key": "YOUR_API_KEY_HERE"`
→ NOT VULNERABLE: Placeholder value

## Your Structured Analysis

1. **Finding**: [What sensitive data is exposed?]
2. **Evidence**: [Quote the exact sensitive values (redact if real)]
3. **Impact**: [Data breach? Credential theft? API abuse?]
4. **Exploitability Conditions**: [Is data usable? Current or stale?]
5. **Severity Justification**: [Based on data sensitivity]

Identify:
- API keys/tokens (not placeholders)
- Passwords/credentials
- PII (SSN, credit cards, emails in bulk)
- Private keys
- Connection strings

Respond ONLY in valid JSON:
{{
    "is_vulnerable": boolean,
    "confidence": number (0-100),
    "finding": "one-line finding statement",
    "evidence": ["specific secrets found (redacted)"],
    "impact": "data exposure consequences",
    "exploitability_conditions": "usability of exposed data",
    "severity_justification": "why this severity",
    "likelihood": number (0.0-10.0),
    "impact_score": number (0.0-10.0),
    "reason": "what sensitive data was found",
    "recommendations": ["remediation steps"]
}}"""
    },
    
    "api_security": {
        "system": "You are an API security expert. Calibrated, evidence-based assessments only. Zero hyperbole.",
        "template": """**STRUCTURED ANALYSIS REQUIRED**

## Input
- **Vulnerability Type**: API Security Issue
- **Test Context**: {context}
- **Response Snippet**:
```
{response_data}
```

## Your Structured Analysis

Provide analysis in this EXACT structure:

1. **Finding**: [What security issue exists, if any?]
2. **Evidence**: [Quote specific lines/patterns from response that prove this]
3. **Impact**: [What could an attacker achieve? Be specific, not dramatic]
4. **Exploitability Conditions**: 
   - Is this directly exploitable? YES/NO
   - If NO: "Requires chaining with [specific vuln type]"
   - If YES: "Directly exploitable because [reason]"
5. **Severity Justification**: [Map to INFO/LOW/MEDIUM/HIGH/CRITICAL with reasoning]

## CRITICAL RULES

**FORBIDDEN LANGUAGE** (auto-reject if used without proven chain):
- "high probability of exploitation"
- "immediate compromise"  
- "critical security breach"
- "severe vulnerability" (for informational findings)

**SEVERITY CALIBRATION:**
- INFO: Missing best-practice with no direct impact
- LOW: Increases attack surface, requires chaining
- MEDIUM: Exploitable with limited impact
- HIGH: Directly exploitable, significant impact
- CRITICAL: Proven exploit chain, severe consequences

**NO EVIDENCE = NO FINDING**: If you cannot quote specific response text, confidence must be ≤30.

Respond ONLY in valid JSON:
{{
    "is_vulnerable": boolean,
    "confidence": number (0-100),
    "finding": "one-line finding statement",
    "evidence": ["specific quoted patterns from response"],
    "impact": "specific attacker outcome",
    "exploitability_conditions": "direct vs conditional exploitability",
    "severity_justification": "calibrated severity reasoning",
    "likelihood": number (0.0-10.0),
    "impact_score": number (0.0-10.0),
    "reason": "precise technical explanation grounded in evidence",
    "recommendations": ["remediation steps"]
}}"""
    },
    
    # Generic fallback for other types
    "default": {
        "system": "You are a cybersecurity expert. Technical precision. Zero hyperbole. Evidence required.",
        "template": """**STRUCTURED ANALYSIS REQUIRED**

## Input
- **Vulnerability Type**: {vuln_type}
- **Test Context**: {context}
- **Response Data**:
```
{response_data}
```

## Your Structured Analysis

1. **Finding**: [Vulnerable or not? What specifically?]
2. **Evidence**: [Quote exact response text proving your conclusion]
3. **Impact**: [Realistic attacker outcome - no exaggeration]
4. **Exploitability Conditions**: 
   - Direct: "Exploitable because [X]"
   - Conditional: "Requires [X] to exploit"
5. **Severity Justification**: [Why this level? What gates passed/failed?]

## Rules
- No evidence = confidence ≤30
- No "high probability" without chain
- Prefer "may increase risk" over "leads to compromise"

Respond ONLY in valid JSON:
{{
    "is_vulnerable": boolean,
    "confidence": number (0-100),
    "finding": "one-line finding",
    "evidence": ["quoted evidence"],
    "impact": "realistic impact",
    "exploitability_conditions": "direct vs conditional",
    "severity_justification": "reasoning",
    "likelihood": number (0.0-10.0),
    "impact_score": number (0.0-10.0),
    "reason": "precise explanation",
    "recommendations": ["remediation steps"]
}}"""
    }
}


class GroqClient:
    """Client for interacting with Groq AI."""
    
    def __init__(self):
        """Initialize the Groq client."""
        # Check config or env var
        api_key = settings.groq_api_key or os.getenv("GROQ_API_KEY")
        
        if api_key:
            self.client = Groq(api_key=api_key)
            self.model_name = "llama-3.3-70b-versatile" # Updated to supported model
            print("[GROQ INIT] Groq client initialized successfully", flush=True)
        else:
            self.client = None
            print("[GROQ WARNING] GROQ_API_KEY not found in environment", flush=True)
    
    @property
    def is_configured(self) -> bool:
        """Check if Groq is properly configured."""
        return self.client is not None
    
    async def analyze_vulnerability(
        self,
        vulnerability_type: str,
        context: str,
        response_data: str
    ) -> Dict[str, Any]:
        """
        Analyze a potential vulnerability using AI with caching.
        
        Uses specialized prompts per vulnerability type and caches results
        to reduce API calls and costs.
        """
        if not self.is_configured:
            return {
                "is_vulnerable": False,
                "confidence": 0,
                "reason": "Groq AI not configured",
                "recommendations": []
            }
        
        # Check cache first
        cached_result = await llm_cache.get_cached_analysis(
            vulnerability_type,
            context,
            response_data
        )
        
        if cached_result:
            return cached_result
        
        # Select appropriate prompt template
        vuln_key = vulnerability_type.lower().replace(" ", "_")
        template_config = PROMPT_TEMPLATES.get(vuln_key, PROMPT_TEMPLATES["default"])
        
        # Build specialized prompt
        if vuln_key == "default":
            prompt = template_config["template"].format(
                vuln_type=vulnerability_type,
                context=context[:1500],
                response_data=response_data[:2000]
            )
        else:
            prompt = template_config["template"].format(
                context=context[:1500],
                response_data=response_data[:2000]
            )
        
        try:
            # Run blocking call in a separate thread
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                messages=[
                    {"role": "system", "content": template_config["system"]},
                    {"role": "user", "content": prompt}
                ],
                model=self.model_name,
                temperature=0.0,
                response_format={"type": "json_object"}
            )
            
            import json
            result_text = response.choices[0].message.content
            print(f"[GROQ] Analyzed {vulnerability_type} (prompt: {len(prompt)} chars)")
            result = json.loads(result_text)
            
            # Cache the result
            await llm_cache.cache_analysis(
                vulnerability_type,
                context,
                response_data,
                result
            )
            
            return result
            
        except Exception as e:
            print(f"[GROQ ERROR] Analysis failed: {e}")
            return {
                "is_vulnerable": False,
                "confidence": 0,
                "reason": f"Analysis error: {str(e)}",
                "recommendations": []
            }
    
    async def generate_fix_recommendation(
        self,
        vulnerability_type: str,
        code_context: str,
        technology_stack: List[str]
    ) -> Dict[str, Any]:
        """
        Generate fix recommendations for a vulnerability.
        """
        if not self.is_configured:
            return {
                "summary": "AI not configured",
                "steps": [],
                "code_example": ""
            }
        
        prompt = f"""You are a cybersecurity expert. Generate a fix for this vulnerability.

Vulnerability: {vulnerability_type}
Technology Stack: {', '.join(technology_stack)}
Context:
```
{code_context[:1500]}
```

Provide:
1. A summary of the fix
2. Step-by-step remediation instructions
3. Secure code example
4. Best practices to prevent this in the future

Respond ONLY in valid JSON format:
{{
    "summary": "string",
    "steps": ["list of steps"],
    "code_example": "string with secure code",
    "best_practices": ["list of best practices"]
}}
"""
        
        try:
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert. Output valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                model=self.model_name,
                temperature=0.0,
                response_format={"type": "json_object"}
            )
            
            import json
            result_text = response.choices[0].message.content
            return json.loads(result_text)
            
        except Exception as e:
            return {
                "summary": f"Error generating fix: {str(e)}",
                "steps": [],
                "code_example": ""
            }
    
    async def explain_vulnerability(
        self,
        vulnerability_type: str,
        severity: str
    ) -> str:
        """
        Generate an educational explanation of a vulnerability.
        """
        if not self.is_configured:
            return f"{vulnerability_type} is a security vulnerability. Configure Groq for detailed explanations."
        
        prompt = f"""Explain the {vulnerability_type} vulnerability in simple terms for a developer.

Severity: {severity}

Include:
1. What it is
2. How attackers exploit it
3. Real-world impact
4. Simple prevention methods

Keep it educational and under 300 words.
"""
        
        try:
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert educator."},
                    {"role": "user", "content": prompt}
                ],
                model=self.model_name,
                temperature=0.7
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating explanation: {str(e)}"


# Singleton instance (keeping name for backward compatibility)
gemini_client = GroqClient()
