# Quick Reference: Actionable Findings API

## Report Generation

### Generate Reports in All Formats

```python
from core.report_generator import generate_report, ReportFormat

# JSON (machine-readable)
json_report = generate_report(
    results=vulnerability_findings,
    scan_metadata={
        "scan_id": "scan_001",
        "target_url": "https://example.com",
        "duration": "5m 30s",
        "agents_used": ["sql_injection", "xss", "csrf"]
    },
    format=ReportFormat.JSON,
    output_file="report.json"  # Optional: auto-save
)

# HTML (executive-friendly)
html_report = generate_report(
    results=vulnerability_findings,
    scan_metadata=scan_metadata,
    format=ReportFormat.HTML,
    output_file="report.html"
)

# Markdown (developer-friendly)
md_report = generate_report(
    results=vulnerability_findings,
    scan_metadata=scan_metadata,
    format=ReportFormat.MARKDOWN,
    output_file="report.md"
)
```

---

## Evidence Chain Tracking

### Create and Track Evidence

```python
from core.evidence_tracker import get_evidence_tracker, DetectionMethod
from models.vulnerability import VulnerabilityType

# In your agent class
tracker = get_evidence_tracker()

# Create evidence chain
chain = self.create_evidence_chain(
    url="https://example.com/api/users",
    parameter="id",
    vuln_type=VulnerabilityType.SQL_INJECTION,
    detection_method=DetectionMethod.TIME_BASED
)

# Set baseline (normal response)
chain.set_baseline(
    request={"method": "GET", "params": {"id": "1"}},
    response={"text": "User profile data...", "status": 200},
    response_time_ms=145.3,
    status_code=200
)

# Add test interaction
chain.add_interaction(
    request={"method": "GET", "params": {"id": "' OR SLEEP(3)--"}},
    response={"text": "User profile data...", "status": 200},
    response_time_ms=3142.7,
    status_code=200,
    note="3-second delay detected - statistical significance"
)

# Track confidence evolution
chain.update_confidence(50.0, "Baseline established")
chain.update_confidence(75.0, "Delayed response detected")
chain.update_confidence(95.0, "Confirmed with alternative payload")

# Document attack steps
chain.add_attack_step("Establishing baseline response times")
chain.add_attack_step("Testing with time-based SQL injection payload")
chain.add_attack_step("Confirming with different delay value")

# Correlate with other findings
chain.correlate_with("finding_002", "Same vulnerable endpoint")

# Export evidence
evidence_data = chain.to_dict()
```

### Retrieve Evidence Chains

```python
# Get specific chain
chain = tracker.get_chain("vulnerability_id_here")

# Get all high-confidence findings
high_conf = tracker.get_high_confidence_chains(threshold=80.0)

# Get chains by detection method
time_based = tracker.get_chains_by_method(DetectionMethod.TIME_BASED)

# Export all evidence
all_evidence = tracker.export_all()
```

---

## Diff-Based Detection

### Compare Responses

```python
from core.diff_detector import DiffDetector, compare_responses

detector = DiffDetector(
    significance_threshold=0.95,  # Similarity below this is significant
    min_byte_diff=10               # Minimum bytes different
)

# Simple comparison
diff = detector.compare_responses(
    baseline_response="<html>Normal response</html>",
    test_response="<html>SQL error: syntax near...</html>",
    normalize=True  # Remove timestamps, IDs, etc.
)

# Check results
if diff.is_significant:
    print(f"Similarity: {diff.similarity_ratio:.2%}")
    print(f"Byte diff: {diff.byte_diff_count}")
    print(f"Reasons: {diff.significance_reasons}")
    print(f"Added lines: {diff.added_lines}")
    print(f"Removed lines: {diff.removed_lines}")
```

### Boolean-Based Detection

```python
# Test for boolean-based blind vulnerabilities
analysis = detector.detect_boolean_based(
    baseline="<html>Login page</html>",
    true_response="<html>Welcome Admin!</html>",
    false_response="<html>Invalid credentials</html>"
)

if analysis["is_boolean_based"]:
    print("Boolean-based vulnerability detected!")
    print(f"Recommendation: {analysis['recommendation']}")
```

### Response Grouping

```python
# Group similar responses
responses = [response1.text, response2.text, response3.text]
groups = detector.find_unique_responses(responses, normalize=True)

# Results: {hash: [indices]}
# Example: {"abc123": [0, 2], "def456": [1]}
# Responses 0 and 2 are identical, response 1 is unique
```

### Calculate Response Hash

```python
# Quick response comparison via hashing
hash1 = detector.calculate_response_hash(response1.text, normalize=True)
hash2 = detector.calculate_response_hash(response2.text, normalize=True)

if hash1 == hash2:
    print("Responses are identical (after normalization)")
```

---

## Integration in Custom Agents

```python
from agents.base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType
from core.evidence_tracker import DetectionMethod

class MyCustomAgent(BaseSecurityAgent):
    agent_name = "my_custom_agent"
    
    async def scan(self, target_url, endpoints, **kwargs):
        results = []
        
        for endpoint in endpoints:
            # Create evidence chain
            chain = self.create_evidence_chain(
                url=endpoint["url"],
                parameter="test_param",
                vuln_type=VulnerabilityType.SQL_INJECTION,
                detection_method=DetectionMethod.ERROR_BASED
            )
            
            # Get baseline
            baseline_response = await self.make_request(
                endpoint["url"],
                params={"test_param": "normal"}
            )
            
            if baseline_response:
                self.set_baseline(
                    chain=chain,
                    request={"params": {"test_param": "normal"}},
                    response_text=baseline_response.text,
                    response_time_ms=150.0,
                    status_code=baseline_response.status_code
                )
                chain.update_confidence(50.0, "Baseline established")
            
            # Test with payload
            test_response = await self.make_request(
                endpoint["url"],
                params={"test_param": "' OR 1=1--"}
            )
            
            if test_response:
                # Add to evidence chain
                self.add_evidence(
                    chain=chain,
                    request={"params": {"test_param": "' OR 1=1--"}},
                    response_text=test_response.text,
                    response_time_ms=160.0,
                    status_code=test_response.status_code,
                    note="Testing SQL injection payload"
                )
                
                # Compare responses
                diff = self.compare_responses(
                    baseline_response.text,
                    test_response.text
                )
                
                if diff.is_significant:
                    chain.update_confidence(85.0, f"Significant change: {diff.significance_reasons}")
                    
                    # Create vulnerability finding
                    result = self.create_result(
                        vulnerability_type=VulnerabilityType.SQL_INJECTION,
                        is_vulnerable=True,
                        severity=Severity.HIGH,
                        confidence=85.0,
                        url=endpoint["url"],
                        parameter="test_param",
                        method="GET",
                        title="SQL Injection Detected",
                        description="Significant response changes indicate SQL injection",
                        evidence=f"Diff: {diff.significance_reasons}",
                        remediation="Use parameterized queries",
                        owasp_category="A03:2021 – Injection",
                        cwe_id="CWE-89",
                        evidence_chain_id=chain.vulnerability_id
                    )
                    results.append(result)
        
        return results
```

---

## CVSS Scoring

CVSS scores are automatically calculated based on vulnerability characteristics:

```python
# The report generator calculates CVSS automatically
# But you can also access it directly:

from core.report_generator import ReportGenerator

generator = ReportGenerator()

# Calculate CVSS for a finding
cvss = generator._calculate_cvss(agent_result)

print(f"CVSS Vector: {cvss.to_vector_string()}")
print(f"Base Score: {cvss.base_score}")
print(f"Rating: {cvss.severity_rating}")

# Example output:
# CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
# Base Score: 9.8
# Rating: Critical
```

---

## Complete Workflow Example

```python
async def complete_scan_with_evidence():
    from agents.sql_injection_agent import SQLInjectionAgent
    from core.report_generator import generate_report, ReportFormat
    from core.evidence_tracker import get_evidence_tracker, reset_evidence_tracker
    
    # Reset evidence tracker for new scan
    reset_evidence_tracker()
    
    # Initialize agent
    agent = SQLInjectionAgent()
    
    # Run scan
    endpoints = [
        {"url": "https://example.com/api/users", "method": "GET", "params": {"id": "1"}}
    ]
    
    results = await agent.scan(
        target_url="https://example.com",
        endpoints=endpoints
    )
    
    # Generate reports
    scan_metadata = {
        "scan_id": "scan_20241224_001",
        "target_url": "https://example.com",
        "duration": "2m 15s",
        "agents_used": ["sql_injection"]
    }
    
    # JSON for automation
    json_report = generate_report(
        results=results,
        scan_metadata=scan_metadata,
        format=ReportFormat.JSON,
        output_file="scan_results.json"
    )
    
    # HTML for executives
    html_report = generate_report(
        results=results,
        scan_metadata=scan_metadata,
        format=ReportFormat.HTML,
        output_file="executive_report.html"
    )
    
    # Markdown for developers
    md_report = generate_report(
        results=results,
        scan_metadata=scan_metadata,
        format=ReportFormat.MARKDOWN,
        output_file="developer_report.md"
    )
    
    # Export all evidence chains
    tracker = get_evidence_tracker()
    all_evidence = tracker.export_all()
    
    with open("evidence_chains.json", "w") as f:
        import json
        json.dump(all_evidence, f, indent=2)
    
    print(f"Generated {len(results)} findings")
    print(f"Reports saved: JSON, HTML, Markdown")
    print(f"Evidence chains exported: {all_evidence['total_chains']} chains")
```

---

## API Endpoints (Future Integration)

```python
# Example FastAPI endpoint for report generation

from fastapi import APIRouter
from core.report_generator import generate_report, ReportFormat

router = APIRouter()

@router.get("/scans/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    format: str = "json"  # json, html, markdown
):
    # Fetch scan results from database
    scan = await get_scan_by_id(scan_id)
    results = scan.vulnerabilities
    
    # Generate report
    report_format = ReportFormat(format.lower())
    report = generate_report(
        results=results,
        scan_metadata={
            "scan_id": scan.id,
            "target_url": scan.target_url,
            "duration": str(scan.duration),
            "agents_used": scan.agents_used
        },
        format=report_format
    )
    
    if report_format == ReportFormat.JSON:
        return JSONResponse(content=report)
    elif report_format == ReportFormat.HTML:
        return HTMLResponse(content=report)
    else:
        return PlainTextResponse(content=report)

@router.get("/scans/{scan_id}/evidence/{chain_id}")
async def get_evidence_chain(scan_id: str, chain_id: str):
    tracker = get_evidence_tracker()
    chain = tracker.get_chain(chain_id)
    
    if not chain:
        raise HTTPException(status_code=404, detail="Evidence chain not found")
    
    return chain.to_dict()
```

---

## Testing

```python
# Run the demonstration
python demo_actionable_findings.py

# Expected output:
# - Evidence chain tracking demo
# - Diff-based detection demo
# - Report generation in 3 formats
# - Files generated:
#   * security_report.json
#   * security_report.html
#   * security_report.md
```

---

## Key Classes Reference

### ReportGenerator
- `generate_report(results, scan_metadata, format)` - Main entry point
- `_generate_json(results, scan_metadata)` - JSON report
- `_generate_html(results, scan_metadata)` - HTML report
- `_generate_markdown(results, scan_metadata)` - Markdown report
- `_calculate_cvss(result)` - CVSS scoring

### EvidenceChain
- `set_baseline(request, response, response_time_ms, status_code)` - Set baseline
- `add_interaction(request, response, response_time_ms, status_code, note)` - Add test
- `update_confidence(score, reason)` - Track confidence
- `add_attack_step(description)` - Document attack progression
- `correlate_with(finding_id, relationship)` - Link findings
- `to_dict()` - Export evidence

### DiffDetector
- `compare_responses(baseline, test, normalize)` - Compare two responses
- `detect_boolean_based(baseline, true, false)` - Boolean blind detection
- `find_unique_responses(responses, normalize)` - Group similar responses
- `calculate_response_hash(response, normalize)` - Hash for comparison

### BaseSecurityAgent (New Methods)
- `create_evidence_chain(url, parameter, vuln_type, detection_method)` - Create chain
- `add_evidence(chain, request, response_text, response_time_ms, status_code, note)` - Add evidence
- `set_baseline(chain, request, response_text, response_time_ms, status_code)` - Set baseline
- `compare_responses(baseline, test, normalize)` - Diff detection
- `detect_boolean_based(baseline, true, false)` - Boolean detection
