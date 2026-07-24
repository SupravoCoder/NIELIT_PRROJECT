"""Comprehensive end-to-end integration tests for VulnSense AI pipeline."""

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_full_vulnerability_assessment_pipeline() -> None:
    """Test full vulnerability scan pipeline over REST API."""
    payload = {
        "target": "192.168.1.10",
        "scan_arguments": "-sV -T4 -F",
        "use_mock_fallback": True,
    }

    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["target"] == "192.168.1.10"
    assert data["total_services_scanned"] > 0
    assert data["total_vulnerabilities_found"] > 0
    assert data["max_cvss_score"] > 0.0
    assert "CRITICAL" in data["risk_distribution"]

    # Verify findings enrichment
    findings = data["findings"]
    assert len(findings) > 0
    first_finding = findings[0]
    assert "cve" in first_finding
    assert "llm_explanation" in first_finding
    assert "remediation_guidance" in first_finding


def test_html_report_generation() -> None:
    """Test HTML report generation endpoint."""
    scan_payload = {
        "target": "127.0.0.1",
        "scan_arguments": "-sV",
        "use_mock_fallback": True,
    }

    scan_resp = client.post("/api/v1/scan", json=scan_payload)
    assert scan_resp.status_code == 200

    summary_data = scan_resp.json()

    report_resp = client.post("/api/v1/reports/html", json=summary_data)
    assert report_resp.status_code == 200
    assert "text/html" in report_resp.headers["content-type"]
    assert "VulnSense AI — Security Assessment Report" in report_resp.text
