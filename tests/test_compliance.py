"""Unit tests for CERT-In, NIST SP 800-53, and ISO/IEC 27001 Compliance Mapper."""

from app.utils.compliance import ComplianceMapper
from app.risk_engine.risk_engine import RiskEngine
from app.utils.schemas import CVERecord, HostScanResult, RiskSeverity


def test_compliance_mapper_critical_cve() -> None:
    """Test compliance control tags for a critical severity CVE."""
    tags = ComplianceMapper.map_finding(
        port=80,
        service_name="http",
        product="Apache Nginx",
        severity="CRITICAL",
        cvss_score=9.8,
        in_cisa_kev=True,
    )

    assert "cert_in" in tags
    assert "CERT-In Sec 5(ii)" in tags["cert_in"]
    assert "NIST SP 800-53 SI-2" in tags["nist"]
    assert "ISO/IEC 27001 A.8.8" in tags["iso"]


def test_compliance_mapper_ssh_service() -> None:
    """Test compliance control tags for SSH service exposure."""
    tags = ComplianceMapper.map_finding(
        port=22,
        service_name="ssh",
        product="OpenSSH",
        severity="MEDIUM",
        cvss_score=5.3,
        in_cisa_kev=False,
    )

    assert "cert_in" in tags
    assert "NIST SP 800-53 IA-5" in tags["nist"]


def test_risk_engine_compliance_tag_integration() -> None:
    """Test that RiskEngine enriches findings with compliance_tags."""
    scan_result = HostScanResult(scan_id="comp-test-1", target="10.0.0.1")

    cve = CVERecord(
        cve_id="CVE-2021-44228",
        description="Log4j RCE",
        cvss_score=10.0,
        cvss_severity=RiskSeverity.CRITICAL,
    )

    cve_matches = [(8080, "http-alt", "Apache Log4j", cve)]
    findings = RiskEngine.prioritize_findings(scan_result, cve_matches)

    assert len(findings) == 1
    f = findings[0]
    assert "cert_in" in f.compliance_tags
    assert "nist" in f.compliance_tags
    assert "iso" in f.compliance_tags
