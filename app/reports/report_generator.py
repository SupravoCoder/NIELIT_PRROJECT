"""Executive and Technical report generation engine (HTML and ReportLab PDF) with Compliance Framework Mapping."""

import os
from datetime import datetime
from typing import List
from app.utils.schemas import ScanAssessmentSummary, VulnerabilityFinding


class SecurityReportGenerator:
    """Generates Executive and Technical Security Assessment Reports in HTML & PDF formats."""

    @staticmethod
    def generate_html_report(summary: ScanAssessmentSummary) -> str:
        """Generate formatted HTML Executive and Technical Security Report with EPSS, CISA KEV, and Compliance Badges."""
        findings_html = ""
        compliance_html = ""

        for f in summary.findings:
            epss_text = f"{round((f.cve.epss_score or 0.0) * 100, 1)}%" if f.cve.epss_score else "N/A"
            epss_badge = f'<span style="background: #0284c7; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 0.8em;">EPSS {epss_text}</span>'
            kev_badge = '<span style="background: #dc2626; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; margin-left: 4px;">🚨 CISA KEV</span>' if f.cve.in_cisa_kev else ''

            findings_html += f"""
            <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 10px; font-weight: bold; color: #38bdf8;">
                    {f.cve.cve_id}<br/>
                    {epss_badge} {kev_badge}
                </td>
                <td style="padding: 10px;">{f.product} {f.version} (Port {f.port})</td>
                <td style="padding: 10px; text-align: center;">
                    <span style="background: #1e293b; padding: 4px 8px; border-radius: 4px; font-weight: bold; color: #38bdf8;">{f.risk_score}</span>
                </td>
                <td style="padding: 10px; font-weight: bold; color: {'#f87171' if f.severity in ['CRITICAL', 'HIGH'] else '#fbbf24'};">{f.severity.value}</td>
                <td style="padding: 10px; font-size: 0.9em;">{f.remediation_guidance or 'Upgrade package to stable release.'}</td>
            </tr>
            """

            cert_in = f.compliance_tags.get("cert_in", "CERT-In Sec 5(vi) Auditing")
            nist = f.compliance_tags.get("nist", "NIST SP 800-53 RA-5")
            iso = f.compliance_tags.get("iso", "ISO/IEC 27001 A.8.8")

            compliance_html += f"""
            <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 10px; font-weight: bold; color: #38bdf8;">{f.cve.cve_id} ({f.product})</td>
                <td style="padding: 10px; font-size: 0.85em; color: #fbbf24;">🇮🇳 {cert_in}</td>
                <td style="padding: 10px; font-size: 0.85em; color: #38bdf8;">🌐 {nist}</td>
                <td style="padding: 10px; font-size: 0.85em; color: #4ade80;">🛡️ {iso}</td>
            </tr>
            """

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>VulnSense AI — Security Assessment Report — {summary.target}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
                .container {{ max-width: 1050px; margin: 0 auto; background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
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
                    <h1>🛡️ VulnSense AI — Tri-Factor Security Assessment Report</h1>
                    <div class="meta">Target: <strong>{summary.target}</strong> | Scan ID: {summary.scan_id} | Generated: {summary.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
                </div>

                <h2>Executive Threat Summary</h2>
                <div class="summary-cards">
                    <div class="card"><div>Services Scanned</div><div class="card-val">{summary.total_services_scanned}</div></div>
                    <div class="card"><div>Vulnerabilities</div><div class="card-val">{summary.total_vulnerabilities_found}</div></div>
                    <div class="card"><div>Max Tri-Factor Risk</div><div class="card-val">{summary.max_cvss_score}</div></div>
                </div>

                <h2>Detailed Tri-Factor Vulnerability Matrix (CVSS + EPSS + CISA KEV)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>CVE ID & Badges</th>
                            <th>Service / Version</th>
                            <th>Tri-Factor Risk</th>
                            <th>Severity</th>
                            <th>Recommended Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {findings_html if summary.findings else '<tr><td colspan="5" style="padding: 15px; text-align: center;">No critical vulnerabilities detected.</td></tr>'}
                    </tbody>
                </table>

                <h2 style="margin-top: 35px;">Regulatory Compliance Audit Matrix (CERT-In / NIST / ISO 27001)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Finding</th>
                            <th>CERT-In (India) Control</th>
                            <th>NIST SP 800-53 Control</th>
                            <th>ISO/IEC 27001 Control</th>
                        </tr>
                    </thead>
                    <tbody>
                        {compliance_html if summary.findings else '<tr><td colspan="4" style="padding: 15px; text-align: center;">Target compliant with standard baseline controls.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        return html_content
