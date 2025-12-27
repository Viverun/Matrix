"""
Report Generator - Creates actionable security reports in multiple formats.

Supports:
- JSON (machine-readable, API integration)
- HTML (human-readable, executive summaries)
- Markdown (documentation, GitHub issues)
"""
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.base_agent import AgentResult
from core.logger import get_logger
from core.report_templates import (
    FINDING_TEMPLATE,
    HTML_REPORT_TEMPLATE,
    MARKDOWN_FINDING_TEMPLATE,
    MARKDOWN_HEADER_TEMPLATE,
    SEVERITY_CARD_TEMPLATE,
)
from models.vulnerability import Severity, VulnerabilityType

logger = get_logger(__name__)


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
        """
        Generate CVSS vector string.
        
        Returns:
            CVSS v3.1 vector string
        """
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
    
    def __init__(self) -> None:
        """Initialize the report generator."""
        self.report_metadata = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "Matrix Security Scanner v2.0",
            "format_version": "1.0"
        }
        logger.info("Report generator initialized")
    
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
            format: Output format (JSON, HTML, or Markdown)
            
        Returns:
            Formatted report string
        
        Raises:
            ValueError: If unsupported format is specified
        """
        logger.info(
            f"Generating {format.value} report with {len(results)} findings",
            extra={
                "format": format.value,
                "findings_count": len(results),
                "target": scan_metadata.get("target_url")
            }
        )
        
        if format == ReportFormat.JSON:
            return self._generate_json(results, scan_metadata)
        elif format == ReportFormat.HTML:
            return self._generate_html(results, scan_metadata)
        elif format == ReportFormat.MARKDOWN:
            return self._generate_markdown(results, scan_metadata)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_json(
        self,
        results: List[AgentResult],
        scan_metadata: Dict[str, Any]
    ) -> str:
        """
        Generate JSON report.
        
        Args:
            results: Vulnerability findings
            scan_metadata: Scan context
        
        Returns:
            JSON-formatted report string
        """
        logger.debug("Building JSON report structure")
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
                    "detected_at": (
                        result.detected_at.isoformat()
                        if hasattr(result, 'detected_at') and result.detected_at
                        else None
                    )
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
        
        logger.info("JSON report generated successfully")
        return json.dumps(report, indent=2)
    
    def _generate_html(
        self,
        results: List[AgentResult],
        scan_metadata: Dict[str, Any]
    ) -> str:
        """
        Generate HTML report using templates.
        
        Args:
            results: Vulnerability findings
            scan_metadata: Scan context
        
        Returns:
            HTML-formatted report string
        """
        logger.debug("Building HTML report from templates")
        summary = self._generate_executive_summary(results)
        stats = self._calculate_statistics(results)
        
        # Group findings by severity
        by_severity = {s: [] for s in Severity}
        for result in results:
            by_severity[result.severity].append(result)
        
        # Generate severity cards
        severity_cards_html = ""
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = stats['by_severity'].get(severity.value, 0)
            severity_cards_html += SEVERITY_CARD_TEMPLATE.format(
                severity_class=severity.value,
                count=count,
                severity_label=severity.value.capitalize()
            )
        
        # Generate findings HTML
        findings_html = ""
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            findings_list = by_severity.get(severity, [])
            if not findings_list:
                continue
            
            for finding in findings_list:
                cvss = self._calculate_cvss(finding)
                
                parameter_row = ""
                if finding.parameter:
                    parameter_row = f"""
                    <div class="info-row">
                        <span class="info-label">Parameter:</span>
                        <span class="info-value"><code>{finding.parameter}</code></span>
                    </div>
                    """
                
                findings_html += FINDING_TEMPLATE.format(
                    severity_class=severity.value,
                    severity_label=severity.value.upper(),
                    title=finding.title,
                    method=finding.method,
                    url=finding.url,
                    parameter_row=parameter_row,
                    cvss_score=cvss.base_score,
                    cvss_rating=cvss.severity_rating,
                    cvss_vector=cvss.to_vector_string(),
                    confidence=finding.confidence,
                    description=finding.description,
                    evidence=finding.evidence,
                    remediation=finding.remediation,
                    owasp_category=finding.owasp_category,
                    cwe_id=finding.cwe_id,
                    agent_name=finding.agent_name
                )
        
        # Format scan duration if available
        scan_duration_html = ""
        if scan_metadata.get("duration"):
            scan_duration_html = f"<p><strong>Duration:</strong> {scan_metadata['duration']:.2f}s</p>"
        
        # Generate final HTML
        html = HTML_REPORT_TEMPLATE.format(
            target_url=scan_metadata.get('target_url', 'Unknown'),
            generated_at=self.report_metadata['generated_at'],
            generator=self.report_metadata['generator'],
            scan_duration=scan_duration_html,
            summary_text=summary['summary_text'],
            severity_cards=severity_cards_html,
            findings_content=findings_html if findings_html else "<p>No vulnerabilities detected.</p>"
        )
        
        logger.info("HTML report generated successfully")
        return html
    
    def _generate_markdown(
        self,
        results: List[AgentResult],
        scan_metadata: Dict[str, Any]
    ) -> str:
        """
        Generate Markdown report.
        
        Args:
            results: Vulnerability findings
            scan_metadata: Scan context
        
        Returns:
            Markdown-formatted report string
        """
        logger.debug("Building Markdown report")
        summary = self._generate_executive_summary(results)
        stats = self._calculate_statistics(results)
        
        # Format scan duration
        scan_duration_md = ""
        if scan_metadata.get("duration"):
            scan_duration_md = f"**Duration:** {scan_metadata['duration']:.2f}s  "
        
        # Generate header
        md = MARKDOWN_HEADER_TEMPLATE.format(
            target_url=scan_metadata.get('target_url', 'Unknown'),
            generated_at=self.report_metadata['generated_at'],
            generator=self.report_metadata['generator'],
            scan_duration=scan_duration_md,
            summary_text=summary['summary_text'],
            critical_count=stats['by_severity'].get('critical', 0),
            high_count=stats['by_severity'].get('high', 0),
            medium_count=stats['by_severity'].get('medium', 0),
            low_count=stats['by_severity'].get('low', 0),
            info_count=stats['by_severity'].get('info', 0),
            total_count=stats['total_findings'],
            high_confidence_findings=stats['high_confidence_findings'],
            average_confidence=stats['average_confidence']
        )
        
        # Group by severity
        by_severity = {s: [] for s in Severity}
        for result in results:
            by_severity[result.severity].append(result)
        
        # Generate findings
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            findings_list = by_severity.get(severity, [])
            if not findings_list:
                continue
            
            md += f"\n### {severity.value.upper()} Severity\n\n"
            
            for i, finding in enumerate(findings_list, 1):
                cvss = self._calculate_cvss(finding)
                
                parameter_line = ""
                if finding.parameter:
                    parameter_line = f"**Parameter:** `{finding.parameter}`  "
                
                references = "\n".join(f"- {ref}" for ref in finding.reference_links)
                if not references:
                    references = "- No external references"
                
                md += MARKDOWN_FINDING_TEMPLATE.format(
                    number=i,
                    title=finding.title,
                    severity=severity.value.upper(),
                    cvss_score=cvss.base_score,
                    cvss_rating=cvss.severity_rating,
                    cvss_vector=cvss.to_vector_string(),
                    confidence=finding.confidence,
                    method=finding.method,
                    url=finding.url,
                    parameter_line=parameter_line,
                    description=finding.description,
                    evidence=finding.evidence,
                    request_data=json.dumps(finding.request_data, indent=2),
                    remediation=finding.remediation,
                    owasp_category=finding.owasp_category,
                    cwe_id=finding.cwe_id,
                    references=references,
                    agent_name=finding.agent_name
                )
        
        logger.info("Markdown report generated successfully")
        return md
    
    def _calculate_cvss(self, result: AgentResult) -> CVSSScore:
        """
        Calculate CVSS v3.1 score from vulnerability details.
        
        Args:
            result: Vulnerability finding
        
        Returns:
            CVSSScore object with calculated metrics
        """
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
        
        elif result.vulnerability_type == VulnerabilityType.OS_COMMAND_INJECTION:
            c = "H"
            i = "H"
            a = "H"
        
        # Calculate base score
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
        """
        CVSS v3.1 base score calculation.
        
        Args:
            av: Attack Vector
            ac: Attack Complexity
            pr: Privileges Required
            ui: User Interaction
            s: Scope
            c: Confidentiality Impact
            i: Integrity Impact
            a: Availability Impact
        
        Returns:
            Base score (0.0-10.0)
        """
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
        """
        Generate executive summary.
        
        Args:
            results: Vulnerability findings
        
        Returns:
            Dictionary with summary information
        """
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
            summary = (
                f"The security scan identified {stats['total_findings']} vulnerabilities, "
                f"including {critical} CRITICAL and {high} HIGH severity findings that "
                f"require immediate attention."
            )
        elif high > 0:
            risk_level = "High"
            summary = (
                f"The security scan identified {stats['total_findings']} vulnerabilities, "
                f"including {high} HIGH severity findings that should be addressed urgently."
            )
        else:
            risk_level = "Medium"
            summary = (
                f"The security scan identified {stats['total_findings']} vulnerabilities "
                f"of varying severity levels that should be reviewed and remediated."
            )
        
        return {
            "summary_text": summary,
            "risk_level": risk_level,
            "critical_count": critical,
            "high_count": high
        }
    
    def _calculate_statistics(self, results: List[AgentResult]) -> Dict[str, Any]:
        """
        Calculate report statistics.
        
        Args:
            results: Vulnerability findings
        
        Returns:
            Dictionary with statistical information
        """
        by_severity: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        confidences: List[int] = []
        
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
        scan_metadata: Scan context information
        format: Output format (JSON, HTML, or Markdown)
        output_file: Optional file path to save report
        
    Returns:
        Report content as string
    """
    generator = ReportGenerator()
    report = generator.generate_report(results, scan_metadata, format)
    
    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report, encoding='utf-8')
        logger.info(
            f"Report saved to {output_file}",
            extra={"format": format.value, "file": output_file}
        )
    
    return report