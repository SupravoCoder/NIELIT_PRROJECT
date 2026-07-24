"""Executive and Technical report generation engine (HTML and ReportLab PDF)."""

import os
from datetime import datetime
from typing import List, Tuple
from app.utils.schemas import ScanAssessmentSummary, VulnerabilityFinding


class SecurityReportGenerator:
    """Generates Executive and Technical Security Assessment Reports in HTML & PDF formats."""

    @staticmethod
    def generate_html_report(summary: ScanAssessmentSummary) -> str:
        """Generate formatted HTML Executive and Technical Security Report."""
        findings_html = ""
        for f in summary.findings:
            findings_html += f"""
            <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 10px; font-weight: bold; color: #38bdf8;">{f.cve.cve_id}</td>
                <td style="padding: 10px;">{f.product} {f.version} (Port {f.port})</td>
                <td style="padding: 10px; text-align: center;">
                    <span style="background: #1e293b; padding: 4px 8px; border-radius: 4px; font-weight: bold;">{f.risk_score}</span>
                </td>
                <td style="padding: 10px; font-weight: bold; color: {'#f87171' if f.severity in ['CRITICAL', 'HIGH'] else '#fbbf24'};">{f.severity.value}</td>
                <td style="padding: 10px; font-size: 0.9em;">{f.remediation_guidance or 'Upgrade package to stable release.'}</td>
            </tr>
            """

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>VulnSense AI Security Assessment Report — {summary.target}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
                .container {{ max-width: 1000px; margin: 0 auto; background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
                .header {{ border-bottom: 2px solid #38bdf8; padding-bottom: 15px; margin-bottom: 25px; }}
                h1 {{ color: #38bdf8; margin: 0; font-size: 28px; }}
                .meta {{ color: #94a3b8; font-size: 14px; margin-top: 5px; }}
                .summary-cards {{ display: flex; gap: 15px; margin-bottom: 30px; }}
                .card {{ flex: 1; background: #0f172a; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #334155; }}
                .card-val {{ font-size: 24px; font-weight: bold; color: #38bdf8; margin-top: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
                th {{ background: #0f172a; padding: 12px; text-align: left; border-bottom: 2px solid #334155; color: #94a3b8; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ VulnSense AI — Security Assessment Report</h1>
                    <div class="meta">Target: <strong>{summary.target}</strong> | Scan ID: {summary.scan_id} | Generated: {summary.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
                </div>

                <h2>Executive Summary</h2>
                <div class="summary-cards">
                    <div class="card"><div>Services Scanned</div><div class="card-val">{summary.total_services_scanned}</div></div>
                    <div class="card"><div>Vulnerabilities</div><div class="card-val">{summary.total_vulnerabilities_found}</div></div>
                    <div class="card"><div>Max CVSS Risk</div><div class="card-val">{summary.max_cvss_score}</div></div>
                </div>

                <h2>Detailed Technical Vulnerability Matrix</h2>
                <table>
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Service / Version</th>
                            <th>CVSS Score</th>
                            <th>Severity</th>
                            <th>Recommended Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {findings_html if summary.findings else '<tr><td colspan="5" style="padding: 15px; text-align: center;">No critical vulnerabilities detected.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        return html_content
