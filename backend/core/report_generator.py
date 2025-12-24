"""
Report Generator - Creates actionable security reports in multiple formats.

Supports:
- JSON (machine-readable, API integration)
- HTML (human-readable, executive summaries)
- Markdown (documentation, GitHub issues)
"""
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, asdict
import base64

from models.vulnerability import Severity, VulnerabilityType
from agents.base_agent import AgentResult


class ReportFormat(str, Enum):
    """Supported report formats."""
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"


@dataclass
class CVSSScore:
    """CVSS v3.1 scoring components."""
    # Base metrics
    attack_vector: str  # N (Network), A (Adjacent), L (Local), P (Physical)
    attack_complexity: str  # L (Low), H (High)
    privileges_required: str  # N (None), L (Low), H (High)
    user_interaction: str  # N (None), R (Required)
    scope: str  # U (Unchanged), C (Changed)
    confidentiality: str  # N (None), L (Low), H (High)
    integrity: str  # N (None), L (Low), H (High)
    availability: str  # N (None), L (Low), H (High)
    
    # Calculated scores
    base_score: float  # 0.0 - 10.0
    severity_rating: str  # None, Low, Medium, High, Critical
    
    def to_vector_string(self) -> str:
        """Generate CVSS vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/A:{self.availability}"
        )


class ReportGenerator:
    """
    Generate actionable security reports in multiple formats.
    
    Features:
    - CVSS v3.1 risk scoring
    - Proof-of-concept payloads
    - Evidence chains with request/response pairs
    - Remediation guidance with code examples
    - Executive summaries
    """
    
    def __init__(self):
        self.report_metadata = {
            "generated_at": datetime.utcnow().isoformat(),
            "generator": "Matrix Security Scanner v2.0",
            "format_version": "1.0"
        }
    
    def generate_report(
        self,
        results: List[AgentResult],
        scan_metadata: Dict[str, Any],
        format: ReportFormat = ReportFormat.JSON
    ) -> str:
        """
        Generate comprehensive security report.
        
        Args:
            results: List of vulnerability findings
            scan_metadata: Scan context (target, duration, etc.)
            format: Output format
            
        Returns:
            Formatted report string
        """
        if format == ReportFormat.JSON:
            return self._generate_json(results, scan_metadata)
        elif format == ReportFormat.HTML:
            return self._generate_html(results, scan_metadata)
        elif format == ReportFormat.MARKDOWN:
            return self._generate_markdown(results, scan_metadata)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_json(self, results: List[AgentResult], scan_metadata: Dict[str, Any]) -> str:
        """Generate JSON report."""
        findings = []
        
        for result in results:
            cvss = self._calculate_cvss(result)
            
            finding = {
                "id": f"VULN-{hash(result.url + (result.parameter or ''))}",
                "title": result.title,
                "description": result.description,
                "severity": result.severity.value,
                "confidence": result.confidence,
                "vulnerability_type": result.vulnerability_type.value,
                
                # Risk scoring
                "risk_score": {
                    "cvss_vector": cvss.to_vector_string(),
                    "cvss_base_score": cvss.base_score,
                    "cvss_rating": cvss.severity_rating,
                    "likelihood": result.likelihood,
                    "impact": result.impact,
                    "exploitability": result.exploitability_rationale
                },
                
                # Location
                "location": {
                    "url": result.url,
                    "parameter": result.parameter,
                    "method": result.method
                },
                
                # Evidence
                "evidence": {
                    "description": result.evidence,
                    "proof_of_concept": {
                        "payload": result.request_data.get("payload", ""),
                        "request": result.request_data,
                        "response_snippet": result.response_snippet
                    },
                    "ai_analysis": result.ai_analysis,
                    "detected_by": result.agent_name,
                    "detected_at": result.detected_at.isoformat() if hasattr(result, 'detected_at') else None
                },
                
                # Remediation
                "remediation": {
                    "summary": result.remediation,
                    "code_example": result.remediation_code or None,
                    "references": result.reference_links
                },
                
                # Standards mapping
                "standards": {
                    "owasp": result.owasp_category,
                    "cwe": result.cwe_id
                }
            }
            
            findings.append(finding)
        
        # Generate executive summary
        summary = self._generate_executive_summary(results)
        
        report = {
            "metadata": {
                **self.report_metadata,
                "scan_id": scan_metadata.get("scan_id"),
                "target": scan_metadata.get("target_url"),
                "scan_duration": scan_metadata.get("duration"),
                "agents_used": scan_metadata.get("agents_used", [])
            },
            "executive_summary": summary,
            "findings": findings,
            "statistics": self._calculate_statistics(results)
        }
        
        return json.dumps(report, indent=2)
    
    def _generate_html(self, results: List[AgentResult], scan_metadata: Dict[str, Any]) -> str:
        """Generate HTML report."""
        summary = self._generate_executive_summary(results)
        stats = self._calculate_statistics(results)
        
        # Group findings by severity
        by_severity = {s: [] for s in Severity}
        for result in results:
            by_severity[result.severity].append(result)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {scan_metadata.get('target_url', 'Unknown')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; margin-bottom: 30px; border-radius: 8px; }}
        h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .metadata {{ opacity: 0.9; font-size: 0.9em; }}
        .summary {{ background: white; padding: 30px; margin-bottom: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-card h3 {{ font-size: 2em; margin-bottom: 5px; }}
        .stat-card.critical {{ background: #fee; color: #c00; }}
        .stat-card.high {{ background: #fef0e5; color: #d97706; }}
        .stat-card.medium {{ background: #fef9e5; color: #ca8a04; }}
        .stat-card.low {{ background: #eff6ff; color: #2563eb; }}
        .findings {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .finding {{ border-left: 4px solid #ddd; padding: 20px; margin-bottom: 20px; background: #fafafa; }}
        .finding.critical {{ border-left-color: #dc2626; background: #fef2f2; }}
        .finding.high {{ border-left-color: #ea580c; background: #fff7ed; }}
        .finding.medium {{ border-left-color: #f59e0b; background: #fffbeb; }}
        .finding.low {{ border-left-color: #3b82f6; background: #eff6ff; }}
        .finding h3 {{ margin-bottom: 10px; color: #1f2937; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; font-weight: 600; text-transform: uppercase; }}
        .badge.critical {{ background: #dc2626; color: white; }}
        .badge.high {{ background: #ea580c; color: white; }}
        .badge.medium {{ background: #f59e0b; color: white; }}
        .badge.low {{ background: #3b82f6; color: white; }}
        .evidence {{ background: #f9fafb; padding: 15px; margin: 15px 0; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.9em; }}
        .remediation {{ background: #ecfdf5; padding: 15px; margin: 15px 0; border-radius: 4px; border-left: 3px solid #10b981; }}
        pre {{ overflow-x: auto; }}
        code {{ background: #1f2937; color: #10b981; padding: 2px 6px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Scan Report</h1>
            <div class="metadata">
                <p><strong>Target:</strong> {scan_metadata.get('target_url', 'Unknown')}</p>
                <p><strong>Generated:</strong> {self.report_metadata['generated_at']}</p>
                <p><strong>Scanner:</strong> {self.report_metadata['generator']}</p>
            </div>
        </header>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <p style="margin: 15px 0;">{summary['summary_text']}</p>
            
            <div class="stats">
                <div class="stat-card critical">
                    <h3>{stats['by_severity'].get('critical', 0)}</h3>
                    <p>Critical</p>
                </div>
                <div class="stat-card high">
                    <h3>{stats['by_severity'].get('high', 0)}</h3>
                    <p>High</p>
                </div>
                <div class="stat-card medium">
                    <h3>{stats['by_severity'].get('medium', 0)}</h3>
                    <p>Medium</p>
                </div>
                <div class="stat-card low">
                    <h3>{stats['by_severity'].get('low', 0)}</h3>
                    <p>Low</p>
                </div>
            </div>
        </div>
        
        <div class="findings">
            <h2>Detailed Findings</h2>
"""
        
        # Add findings grouped by severity
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            findings = by_severity.get(severity, [])
            if not findings:
                continue
            
            for finding in findings:
                cvss = self._calculate_cvss(finding)
                html += f"""
            <div class="finding {severity.value}">
                <h3>
                    <span class="badge {severity.value}">{severity.value}</span>
                    {finding.title}
                </h3>
                <p><strong>Location:</strong> <code>{finding.method} {finding.url}</code></p>
                {f'<p><strong>Parameter:</strong> <code>{finding.parameter}</code></p>' if finding.parameter else ''}
                <p><strong>CVSS Score:</strong> {cvss.base_score} ({cvss.severity_rating}) - {cvss.to_vector_string()}</p>
                <p><strong>Confidence:</strong> {finding.confidence}%</p>
                
                <h4>Description</h4>
                <p>{finding.description}</p>
                
                <h4>Evidence</h4>
                <div class="evidence">
                    <pre>{finding.evidence}</pre>
                </div>
                
                <h4>Remediation</h4>
                <div class="remediation">
                    <p>{finding.remediation}</p>
                </div>
                
                <p style="margin-top: 15px; font-size: 0.9em; color: #6b7280;">
                    <strong>Standards:</strong> {finding.owasp_category} | {finding.cwe_id} | 
                    Detected by: {finding.agent_name}
                </p>
            </div>
"""
        
        html += """
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def _generate_markdown(self, results: List[AgentResult], scan_metadata: Dict[str, Any]) -> str:
        """Generate Markdown report."""
        summary = self._generate_executive_summary(results)
        stats = self._calculate_statistics(results)
        
        md = f"""# Security Scan Report

**Target:** {scan_metadata.get('target_url', 'Unknown')}  
**Generated:** {self.report_metadata['generated_at']}  
**Scanner:** {self.report_metadata['generator']}

---

## Executive Summary

{summary['summary_text']}

### Statistics

| Severity | Count |
|----------|-------|
| Critical | {stats['by_severity'].get('critical', 0)} |
| High     | {stats['by_severity'].get('high', 0)} |
| Medium   | {stats['by_severity'].get('medium', 0)} |
| Low      | {stats['by_severity'].get('low', 0)} |
| Info     | {stats['by_severity'].get('info', 0)} |
| **Total** | **{stats['total_findings']}** |

**High Confidence Findings:** {stats['high_confidence_findings']}  
**Average Confidence:** {stats['average_confidence']:.1f}%

---

## Detailed Findings

"""
        
        # Group by severity
        by_severity = {s: [] for s in Severity}
        for result in results:
            by_severity[result.severity].append(result)
        
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            findings = by_severity.get(severity, [])
            if not findings:
                continue
            
            md += f"\n### {severity.value.upper()} Severity\n\n"
            
            for i, finding in enumerate(findings, 1):
                cvss = self._calculate_cvss(finding)
                
                md += f"""#### {i}. {finding.title}

**Severity:** {severity.value.upper()}  
**CVSS Score:** {cvss.base_score} ({cvss.severity_rating})  
**Vector:** `{cvss.to_vector_string()}`  
**Confidence:** {finding.confidence}%  
**Location:** `{finding.method} {finding.url}`  
"""
                if finding.parameter:
                    md += f"**Parameter:** `{finding.parameter}`  \n"
                
                md += f"""
**Description:**  
{finding.description}

**Evidence:**
```
{finding.evidence}
```

**Proof of Concept:**
```json
{json.dumps(finding.request_data, indent=2)}
```

**Remediation:**  
{finding.remediation}

**Standards Mapping:**
- **OWASP:** {finding.owasp_category}
- **CWE:** {finding.cwe_id}

**References:**
"""
                for ref in finding.reference_links:
                    md += f"- {ref}\n"
                
                md += f"\n**Detected by:** {finding.agent_name}\n\n---\n\n"
        
        return md
    
    def _calculate_cvss(self, result: AgentResult) -> CVSSScore:
        """Calculate CVSS v3.1 score from vulnerability details."""
        # Base metric defaults based on vulnerability type and context
        av = "N"  # Network (most common for web apps)
        ac = "L"  # Low complexity
        pr = "N"  # No privileges required
        ui = "N"  # No user interaction
        s = "U"   # Scope unchanged
        c = "H"   # High confidentiality impact
        i = "H"   # High integrity impact
        a = "N"   # No availability impact
        
        # Adjust based on vulnerability characteristics
        if result.vulnerability_type in [VulnerabilityType.XSS_REFLECTED, VulnerabilityType.XSS_STORED]:
            ui = "R"  # Requires user interaction
            c = "L"   # Lower confidentiality impact
            i = "L"   # Lower integrity impact
            a = "N"
        
        elif result.vulnerability_type == VulnerabilityType.SQL_INJECTION:
            c = "H"   # High confidentiality
            i = "H"   # High integrity
            a = "H"   # High availability (can delete data)
        
        elif result.vulnerability_type == VulnerabilityType.CSRF:
            ui = "R"  # Requires user to click
            pr = "N"
            c = "L"
            i = "H"   # Can modify data
        
        elif result.vulnerability_type == VulnerabilityType.SSRF:
            c = "H"
            i = "L"
            a = "L"
        
        elif result.vulnerability_type == VulnerabilityType.COMMAND_INJECTION:
            c = "H"
            i = "H"
            a = "H"
        
        # Calculate base score (simplified formula)
        base_score = self._calculate_cvss_base_score(av, ac, pr, ui, s, c, i, a)
        
        # Map to severity rating
        if base_score == 0.0:
            rating = "None"
        elif base_score < 4.0:
            rating = "Low"
        elif base_score < 7.0:
            rating = "Medium"
        elif base_score < 9.0:
            rating = "High"
        else:
            rating = "Critical"
        
        return CVSSScore(
            attack_vector=av,
            attack_complexity=ac,
            privileges_required=pr,
            user_interaction=ui,
            scope=s,
            confidentiality=c,
            integrity=i,
            availability=a,
            base_score=base_score,
            severity_rating=rating
        )
    
    def _calculate_cvss_base_score(
        self, av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str
    ) -> float:
        """Simplified CVSS v3.1 base score calculation."""
        # Impact subscore
        impact_values = {"N": 0.0, "L": 0.22, "H": 0.56}
        isc_base = 1 - ((1 - impact_values[c]) * (1 - impact_values[i]) * (1 - impact_values[a]))
        
        if s == "U":
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)
        
        # Exploitability subscore
        av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_values = {"L": 0.77, "H": 0.44}
        pr_values = {"N": 0.85, "L": 0.62 if s == "U" else 0.68, "H": 0.27 if s == "U" else 0.50}
        ui_values = {"N": 0.85, "R": 0.62}
        
        exploitability = 8.22 * av_values[av] * ac_values[ac] * pr_values[pr] * ui_values[ui]
        
        # Base score
        if impact <= 0:
            return 0.0
        
        if s == "U":
            base_score = min(impact + exploitability, 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)
        
        # Round up to 1 decimal
        return round(base_score * 10) / 10
    
    def _generate_executive_summary(self, results: List[AgentResult]) -> Dict[str, Any]:
        """Generate executive summary."""
        if not results:
            return {
                "summary_text": "No vulnerabilities were detected during this scan.",
                "risk_level": "Low",
                "critical_count": 0,
                "high_count": 0
            }
        
        stats = self._calculate_statistics(results)
        critical = stats['by_severity'].get('critical', 0)
        high = stats['by_severity'].get('high', 0)
        
        if critical > 0:
            risk_level = "Critical"
            summary = f"The security scan identified {stats['total_findings']} vulnerabilities, including {critical} CRITICAL and {high} HIGH severity findings that require immediate attention."
        elif high > 0:
            risk_level = "High"
            summary = f"The security scan identified {stats['total_findings']} vulnerabilities, including {high} HIGH severity findings that should be addressed urgently."
        else:
            risk_level = "Medium"
            summary = f"The security scan identified {stats['total_findings']} vulnerabilities of varying severity levels that should be reviewed and remediated."
        
        return {
            "summary_text": summary,
            "risk_level": risk_level,
            "critical_count": critical,
            "high_count": high
        }
    
    def _calculate_statistics(self, results: List[AgentResult]) -> Dict[str, Any]:
        """Calculate report statistics."""
        by_severity = {}
        by_type = {}
        confidences = []
        
        for result in results:
            # By severity
            severity_key = result.severity.value
            by_severity[severity_key] = by_severity.get(severity_key, 0) + 1
            
            # By type
            type_key = result.vulnerability_type.value
            by_type[type_key] = by_type.get(type_key, 0) + 1
            
            # Confidence
            confidences.append(result.confidence)
        
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0
        high_confidence = len([c for c in confidences if c >= 80])
        
        return {
            "total_findings": len(results),
            "by_severity": by_severity,
            "by_type": by_type,
            "average_confidence": avg_confidence,
            "high_confidence_findings": high_confidence
        }


# Convenience function
def generate_report(
    results: List[AgentResult],
    scan_metadata: Dict[str, Any],
    format: ReportFormat = ReportFormat.JSON,
    output_file: Optional[str] = None
) -> str:
    """
    Generate and optionally save a security report.
    
    Args:
        results: Vulnerability findings
        scan_metadata: Scan context
        format: Output format
        output_file: Optional file path to save report
        
    Returns:
        Report content as string
    """
    generator = ReportGenerator()
    report = generator.generate_report(results, scan_metadata, format)
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"[REPORT] Saved {format.value.upper()} report to {output_file}")
    
    return report
