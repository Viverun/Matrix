"""
HTML templates for security scan reports.
"""

# Complete HTML template with embedded CSS
HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {target_url}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            background: #f5f5f5; 
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        
        header {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 40px 20px; 
            margin-bottom: 30px; 
            border-radius: 8px; 
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        header h1 {{ font-size: 2.5em; margin-bottom: 10px; font-weight: 700; }}
        .metadata {{ opacity: 0.9; font-size: 0.9em; }}
        .metadata p {{ margin: 5px 0; }}
        
        .summary {{ 
            background: white; 
            padding: 30px; 
            margin-bottom: 30px; 
            border-radius: 8px; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.1); 
        }}
        .summary h2 {{ color: #2d3748; margin-bottom: 15px; font-size: 1.8em; }}
        .summary-text {{ margin: 15px 0; font-size: 1.1em; color: #4a5568; line-height: 1.8; }}
        
        .stats {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin: 20px 0; 
        }}
        .stat-card {{ 
            padding: 25px; 
            border-radius: 8px; 
            text-align: center; 
            transition: transform 0.2s;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-card:hover {{ transform: translateY(-2px); }}
        .stat-card h3 {{ font-size: 2.5em; margin-bottom: 8px; font-weight: 700; }}
        .stat-card p {{ font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }}
        .stat-card.critical {{ background: #fee; color: #991b1b; border-left: 4px solid #dc2626; }}
        .stat-card.high {{ background: #fff7ed; color: #9a3412; border-left: 4px solid #ea580c; }}
        .stat-card.medium {{ background: #fefce8; color: #854d0e; border-left: 4px solid #f59e0b; }}
        .stat-card.low {{ background: #eff6ff; color: #1e40af; border-left: 4px solid #3b82f6; }}
        
        .findings {{ 
            background: white; 
            padding: 30px; 
            border-radius: 8px; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.1); 
        }}
        .findings h2 {{ color: #2d3748; margin-bottom: 25px; font-size: 1.8em; }}
        
        .finding {{ 
            border-left: 4px solid #ddd; 
            padding: 25px; 
            margin-bottom: 25px; 
            background: #fafafa; 
            border-radius: 4px;
            transition: box-shadow 0.2s;
        }}
        .finding:hover {{ box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
        .finding.critical {{ border-left-color: #dc2626; background: #fef2f2; }}
        .finding.high {{ border-left-color: #ea580c; background: #fff7ed; }}
        .finding.medium {{ border-left-color: #f59e0b; background: #fffbeb; }}
        .finding.low {{ border-left-color: #3b82f6; background: #eff6ff; }}
        .finding.info {{ border-left-color: #8b5cf6; background: #faf5ff; }}
        
        .finding h3 {{ 
            margin-bottom: 15px; 
            color: #1f2937; 
            font-size: 1.4em; 
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .finding-content {{ margin-top: 15px; }}
        .finding-content p {{ margin: 10px 0; color: #4a5568; }}
        .finding-content h4 {{ 
            margin: 20px 0 10px 0; 
            color: #2d3748; 
            font-size: 1.1em;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 5px;
        }}
        
        .badge {{ 
            display: inline-block; 
            padding: 6px 14px; 
            border-radius: 16px; 
            font-size: 0.75em; 
            font-weight: 700; 
            text-transform: uppercase; 
            letter-spacing: 0.5px;
        }}
        .badge.critical {{ background: #dc2626; color: white; }}
        .badge.high {{ background: #ea580c; color: white; }}
        .badge.medium {{ background: #f59e0b; color: white; }}
        .badge.low {{ background: #3b82f6; color: white; }}
        .badge.info {{ background: #8b5cf6; color: white; }}
        
        .evidence {{ 
            background: #1f2937; 
            color: #e5e7eb; 
            padding: 15px; 
            margin: 15px 0; 
            border-radius: 6px; 
            font-family: 'Courier New', 'Consolas', monospace; 
            font-size: 0.9em; 
            overflow-x: auto;
            border: 1px solid #374151;
        }}
        .evidence pre {{ 
            margin: 0; 
            white-space: pre-wrap; 
            word-wrap: break-word; 
        }}
        
        .remediation {{ 
            background: #ecfdf5; 
            padding: 20px; 
            margin: 15px 0; 
            border-radius: 6px; 
            border-left: 4px solid #10b981; 
        }}
        .remediation-title {{ 
            font-weight: 700; 
            color: #065f46; 
            margin-bottom: 10px; 
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .remediation-title::before {{ 
            content: "✓"; 
            background: #10b981; 
            color: white; 
            width: 24px; 
            height: 24px; 
            border-radius: 50%; 
            display: inline-flex; 
            align-items: center; 
            justify-content: center; 
            font-weight: bold;
        }}
        .remediation p {{ color: #047857; line-height: 1.8; }}
        
        code {{ 
            background: #1f2937; 
            color: #10b981; 
            padding: 3px 8px; 
            border-radius: 4px; 
            font-family: 'Courier New', 'Consolas', monospace;
            font-size: 0.9em;
        }}
        
        .info-row {{ 
            display: flex; 
            gap: 10px; 
            margin: 8px 0; 
            font-size: 0.95em;
        }}
        .info-label {{ 
            font-weight: 600; 
            color: #4b5563; 
            min-width: 120px;
        }}
        .info-value {{ color: #1f2937; }}
        
        .standards {{ 
            margin-top: 20px; 
            padding-top: 15px; 
            border-top: 1px solid #e5e7eb; 
            font-size: 0.9em; 
            color: #6b7280; 
        }}
        
        footer {{ 
            background: white; 
            padding: 20px; 
            margin-top: 30px; 
            border-radius: 8px; 
            text-align: center; 
            color: #6b7280; 
            font-size: 0.9em;
        }}
        
        @media print {{
            body {{ background: white; }}
            .container {{ max-width: 100%; }}
            header {{ background: #667eea; print-color-adjust: exact; }}
            .finding:hover {{ box-shadow: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Security Scan Report</h1>
            <div class="metadata">
                <p><strong>Target:</strong> {target_url}</p>
                <p><strong>Generated:</strong> {generated_at}</p>
                <p><strong>Scanner:</strong> {generator}</p>
                {scan_duration}
            </div>
        </header>
        
        <div class="summary">
            <h2>📊 Executive Summary</h2>
            <div class="summary-text">{summary_text}</div>
            
            <div class="stats">
                {severity_cards}
            </div>
        </div>
        
        <div class="findings">
            <h2>🔍 Detailed Findings</h2>
            {findings_content}
        </div>
        
        <footer>
            <p>Generated by {generator} | Report Format Version 1.0</p>
            <p>For questions or support, please contact your security team.</p>
        </footer>
    </div>
</body>
</html>
"""

# Severity card template
SEVERITY_CARD_TEMPLATE = """
<div class="stat-card {severity_class}">
    <h3>{count}</h3>
    <p>{severity_label}</p>
</div>
"""

# Individual finding template
FINDING_TEMPLATE = """
<div class="finding {severity_class}">
    <h3>
        <span class="badge {severity_class}">{severity_label}</span>
        {title}
    </h3>
    
    <div class="finding-content">
        <div class="info-row">
            <span class="info-label">Location:</span>
            <span class="info-value"><code>{method} {url}</code></span>
        </div>
        {parameter_row}
        <div class="info-row">
            <span class="info-label">CVSS Score:</span>
            <span class="info-value">{cvss_score} ({cvss_rating}) - <code>{cvss_vector}</code></span>
        </div>
        <div class="info-row">
            <span class="info-label">Confidence:</span>
            <span class="info-value">{confidence}%</span>
        </div>
        
        <h4>📝 Description</h4>
        <p>{description}</p>
        
        <h4>🔬 Evidence</h4>
        <div class="evidence">
            <pre>{evidence}</pre>
        </div>
        
        <h4>💡 Remediation</h4>
        <div class="remediation">
            <div class="remediation-title">Recommended Fix</div>
            <p>{remediation}</p>
        </div>
        
        <div class="standards">
            <strong>Standards Mapping:</strong> {owasp_category} | {cwe_id} | 
            <strong>Detected by:</strong> {agent_name}
        </div>
    </div>
</div>
"""

# Markdown report template
MARKDOWN_HEADER_TEMPLATE = """# 🔒 Security Scan Report

**Target:** {target_url}  
**Generated:** {generated_at}  
**Scanner:** {generator}  
{scan_duration}

---

## 📊 Executive Summary

{summary_text}

### Vulnerability Statistics

| Severity | Count |
|----------|-------|
| 🔴 Critical | {critical_count} |
| 🟠 High     | {high_count} |
| 🟡 Medium   | {medium_count} |
| 🔵 Low      | {low_count} |
| ⚪ Info     | {info_count} |
| **Total** | **{total_count}** |

**High Confidence Findings:** {high_confidence_findings}  
**Average Confidence:** {average_confidence}%

---

## 🔍 Detailed Findings

"""

# Markdown finding template
MARKDOWN_FINDING_TEMPLATE = """#### {number}. {title}

**Severity:** {severity}  
**CVSS Score:** {cvss_score} ({cvss_rating})  
**Vector:** `{cvss_vector}`  
**Confidence:** {confidence}%  
**Location:** `{method} {url}`  
{parameter_line}

**Description:**  
{description}

**Evidence:**
```
{evidence}
```

**Proof of Concept:**
```json
{request_data}
```

**Remediation:**  
{remediation}

**Standards Mapping:**
- **OWASP:** {owasp_category}
- **CWE:** {cwe_id}

**References:**
{references}

**Detected by:** {agent_name}

---

"""