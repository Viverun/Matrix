"""
Demonstration of Actionable Findings Features

Shows how to use:
1. Structured reporting (JSON/HTML/Markdown)
2. Evidence chain tracking
3. Diff-based detection
"""
import asyncio
from datetime import datetime
from typing import List

# Import our new components
from core.report_generator import ReportGenerator, ReportFormat, generate_report
from core.evidence_tracker import (
    get_evidence_tracker, reset_evidence_tracker,
    EvidenceChain, DetectionMethod
)
from core.diff_detector import DiffDetector, compare_responses

# Import existing components
from agents.base_agent import AgentResult
from models.vulnerability import Severity, VulnerabilityType


def demo_evidence_tracking():
    """Demonstrate evidence chain tracking."""
    print("=" * 60)
    print("EVIDENCE CHAIN TRACKING DEMO")
    print("=" * 60)
    
    # Get global evidence tracker
    tracker = get_evidence_tracker()
    
    # Create evidence chain for a vulnerability
    chain_id = tracker.generate_chain_id(
        url="http://example.com/login",
        parameter="username",
        vuln_type="sql_injection"
    )
    
    chain = tracker.create_chain(chain_id, DetectionMethod.TIME_BASED)
    
    # Add baseline
    chain.set_baseline(
        request={"method": "POST", "params": {"username": "admin", "password": "test"}},
        response={"text": "Login page loaded", "status": 200},
        response_time_ms=145.3,
        status_code=200
    )
    chain.update_confidence(50.0, "Baseline established")
    
    # Simulate testing process
    chain.add_attack_step("Testing with SQL injection payload: ' OR '1'='1")
    
    chain.add_interaction(
        request={"method": "POST", "params": {"username": "' OR '1'='1", "password": "test"}},
        response={"text": "SQL syntax error near '1'='1'", "status": 500},
        response_time_ms=156.7,
        status_code=500,
        note="SQL error detected in response"
    )
    chain.update_confidence(75.0, "SQL error message confirms vulnerability")
    
    # Confirmation test
    chain.add_attack_step("Confirming with boolean-based payload")
    chain.add_interaction(
        request={"method": "POST", "params": {"username": "' AND '1'='1", "password": "test"}},
        response={"text": "Welcome admin!", "status": 200},
        response_time_ms=148.2,
        status_code=200,
        note="Boolean TRUE payload succeeded"
    )
    chain.update_confidence(95.0, "Boolean-based blind SQL injection confirmed")
    
    # Correlate with another finding
    chain.correlate_with("finding_002", "Same vulnerable endpoint")
    
    # Export evidence
    evidence_data = chain.to_dict()
    
    print(f"\n[Chain ID] {chain_id}")
    print(f"[Method] {chain.detection_method.value}")
    print(f"[Final Confidence] {chain.get_final_confidence()}%")
    print(f"[Total Interactions] {len(chain.interactions)}")
    print(f"[Attack Steps]")
    for step in chain.attack_steps:
        print(f"  {step}")
    
    print(f"\n[Confidence Evolution]")
    for conf in chain.confidence_scores:
        print(f"  {conf['score']:5.1f}% - {conf['reason']}")
    
    print(f"\n[Related Findings] {len(chain.related_findings)}")
    
    return chain


def demo_diff_detection():
    """Demonstrate diff-based detection."""
    print("\n" + "=" * 60)
    print("DIFF-BASED DETECTION DEMO")
    print("=" * 60)
    
    detector = DiffDetector()
    
    # Baseline response
    baseline = """
<html>
<head><title>Login</title></head>
<body>
<h1>Login Page</h1>
<form method="post">
    <input name="username" />
    <input name="password" type="password" />
    <input type="submit" value="Login" />
</form>
<p>Session ID: abc123def456</p>
<p>Request ID: req-2024-001</p>
<p><!-- Generated at 2024-12-24 10:30:45 --></p>
</body>
</html>
"""
    
    # Response with SQL error
    sql_error_response = """
<html>
<head><title>Login</title></head>
<body>
<h1>Login Page</h1>
<form method="post">
    <input name="username" />
    <input name="password" type="password" />
    <input type="submit" value="Login" />
</form>
<p style="color:red">Error: SQL syntax error near '1'='1' at line 42</p>
<p>Session ID: xyz789ghi012</p>
<p>Request ID: req-2024-002</p>
<p><!-- Generated at 2024-12-24 10:31:12 --></p>
</body>
</html>
"""
    
    # Compare responses
    print("\n[Comparing baseline vs SQL error response]")
    diff = detector.compare_responses(baseline, sql_error_response, normalize=True)
    
    print(f"Similarity: {diff.similarity_ratio:.2%}")
    print(f"Byte Difference: {diff.byte_diff_count}")
    print(f"Token Difference: {diff.token_diff_count}")
    print(f"Significant: {diff.is_significant}")
    
    print(f"\n[Significance Reasons]")
    for reason in diff.significance_reasons:
        print(f"  - {reason}")
    
    print(f"\n[Added Lines]")
    for line in diff.added_lines[:3]:
        print(f"  + {line}")
    
    # Boolean-based detection
    print("\n[Testing boolean-based detection]")
    
    true_response = """
<html><body><h1>Welcome Admin!</h1><p>Last login: 2024-12-24</p></body></html>
"""
    
    false_response = """
<html><body><h1>Invalid Credentials</h1><p>Please try again</p></body></html>
"""
    
    boolean_analysis = detector.detect_boolean_based(baseline, true_response, false_response)
    
    print(f"Is Boolean-Based: {boolean_analysis['is_boolean_based']}")
    print(f"Recommendation: {boolean_analysis['recommendation']}")
    print(f"True vs False Similarity: {boolean_analysis['true_vs_false']['similarity']:.2%}")
    
    return diff


def demo_report_generation():
    """Demonstrate report generation in multiple formats."""
    print("\n" + "=" * 60)
    print("REPORT GENERATION DEMO")
    print("=" * 60)
    
    # Create mock vulnerability findings
    results = [
        AgentResult(
            agent_name="sql_injection",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            is_vulnerable=True,
            severity=Severity.CRITICAL,
            confidence=95.0,
            url="http://example.com/api/users",
            parameter="id",
            method="GET",
            title="SQL Injection in 'id' parameter",
            description="An error-based SQL injection vulnerability allows attackers to execute arbitrary SQL queries.",
            evidence="MySQL error: 'You have an error in your SQL syntax near '1'='1''",
            ai_analysis="High confidence SQL injection confirmed via error messages and boolean-based testing.",
            remediation="Use parameterized queries (prepared statements) instead of string concatenation.",
            remediation_code="""
# Vulnerable code:
query = f"SELECT * FROM users WHERE id = '{user_id}'"

# Secure code:
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
""",
            owasp_category="A03:2021 – Injection",
            cwe_id="CWE-89",
            reference_links=[
                "https://owasp.org/Top10/A03_2021-Injection/",
                "https://portswigger.net/web-security/sql-injection"
            ],
            request_data={"params": {"id": "' OR '1'='1"}},
            response_snippet="MySQL error: 'You have an error in your SQL syntax...'",
            likelihood=9.0,
            impact=10.0,
            exploitability_rationale="Directly exploitable. Can extract entire database contents.",
            evidence_chain_id="abc123"
        ),
        AgentResult(
            agent_name="xss",
            vulnerability_type=VulnerabilityType.XSS_REFLECTED,
            is_vulnerable=True,
            severity=Severity.HIGH,
            confidence=88.0,
            url="http://example.com/search",
            parameter="q",
            method="GET",
            title="Reflected XSS in search parameter",
            description="User input is reflected in HTML without proper encoding, allowing script injection.",
            evidence="Payload <script>alert('XSS')</script> was reflected unencoded in response.",
            ai_analysis="Confirmed reflected XSS via payload reflection analysis.",
            remediation="HTML-encode all user input before rendering in web pages. Use Content-Security-Policy header.",
            owasp_category="A03:2021 – Injection",
            cwe_id="CWE-79",
            reference_links=["https://owasp.org/Top10/A03_2021-Injection/"],
            request_data={"params": {"q": "<script>alert('XSS')</script>"}},
            response_snippet="<div class='results'>Search results for: <script>alert('XSS')</script></div>",
            likelihood=7.0,
            impact=7.0,
            exploitability_rationale="Requires user interaction but easily exploitable via phishing.",
            evidence_chain_id="def456"
        ),
        AgentResult(
            agent_name="csrf",
            vulnerability_type=VulnerabilityType.CSRF,
            is_vulnerable=True,
            severity=Severity.MEDIUM,
            confidence=85.0,
            url="http://example.com/api/profile/update",
            method="POST",
            title="Missing CSRF protection on profile update",
            description="State-changing operation lacks CSRF tokens, allowing cross-site request forgery.",
            evidence="POST request succeeded without CSRF token or SameSite cookie attribute.",
            ai_analysis="No CSRF tokens found in request or response. Cookies lack SameSite attribute.",
            remediation="Implement synchronizer tokens pattern. Set SameSite=Strict on session cookies.",
            owasp_category="A01:2021 – Broken Access Control",
            cwe_id="CWE-352",
            reference_links=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
            request_data={"data": {"email": "attacker@example.com"}},
            likelihood=6.0,
            impact=7.0,
            exploitability_rationale="Requires social engineering but no authentication bypass needed.",
            evidence_chain_id="ghi789"
        )
    ]
    
    # Scan metadata
    scan_metadata = {
        "scan_id": "scan_20241224_103045",
        "target_url": "http://example.com",
        "duration": "5m 32s",
        "agents_used": ["github_security", "sql_injection", "xss", "csrf", "auth", "api_security"]
    }
    
    # Generate reports in different formats
    generator = ReportGenerator()
    
    # JSON Report
    print("\n[Generating JSON Report]")
    json_report = generator.generate_report(results, scan_metadata, ReportFormat.JSON)
    print(f"JSON report size: {len(json_report)} bytes")
    print(f"Preview (first 500 chars):\n{json_report[:500]}...")
    
    # Save JSON report
    with open("security_report.json", "w", encoding="utf-8") as f:
        f.write(json_report)
    print(f"Saved to: security_report.json")
    
    # HTML Report
    print("\n[Generating HTML Report]")
    html_report = generator.generate_report(results, scan_metadata, ReportFormat.HTML)
    print(f"HTML report size: {len(html_report)} bytes")
    
    # Save HTML report
    with open("security_report.html", "w", encoding="utf-8") as f:
        f.write(html_report)
    print(f"Saved to: security_report.html")
    
    # Markdown Report
    print("\n[Generating Markdown Report]")
    md_report = generator.generate_report(results, scan_metadata, ReportFormat.MARKDOWN)
    print(f"Markdown report size: {len(md_report)} bytes")
    print(f"Preview (first 800 chars):\n{md_report[:800]}...")
    
    # Save Markdown report
    with open("security_report.md", "w", encoding="utf-8") as f:
        f.write(md_report)
    print(f"Saved to: security_report.md")
    
    return results


def main():
    """Run all demos."""
    print("\n" + "#" * 60)
    print("# ACTIONABLE FINDINGS - COMPREHENSIVE DEMONSTRATION")
    print("#" * 60)
    
    # Reset evidence tracker
    reset_evidence_tracker()
    
    # 1. Evidence Tracking
    evidence_chain = demo_evidence_tracking()
    
    # 2. Diff Detection
    diff_result = demo_diff_detection()
    
    # 3. Report Generation
    results = demo_report_generation()
    
    print("\n" + "=" * 60)
    print("DEMO COMPLETE!")
    print("=" * 60)
    print("\nGenerated Files:")
    print("  - security_report.json  (Machine-readable, API-ready)")
    print("  - security_report.html  (Human-readable, executive summary)")
    print("  - security_report.md    (Documentation, GitHub issues)")
    print("\nKey Features Demonstrated:")
    print("  + CVSS v3.1 risk scoring")
    print("  + Proof-of-concept payloads")
    print("  + Evidence chain tracking with request/response pairs")
    print("  + Confidence evolution over time")
    print("  + Diff-based detection for blind vulnerabilities")
    print("  + Multi-format reporting (JSON/HTML/Markdown)")
    print("  + Remediation guidance with code examples")
    print("  + OWASP/CWE mapping")
    print("\nActionable Improvements:")
    print("  -> 95% confidence SQL injection with full attack chain")
    print("  -> Statistical diff analysis for subtle changes")
    print("  -> Executive-ready HTML reports")
    print("  -> Developer-ready code remediation examples")


if __name__ == "__main__":
    main()
