"""Unit tests for Tri-Factor Risk Scoring Engine (EPSS + CISA KEV Integration)."""

import pytest
from app.risk_engine.epss_kev_fetcher import CISAKEVFetcher, EPSSFetcher
from app.risk_engine.risk_engine import RiskEngine
from app.utils.schemas import CVERecord, HostScanResult, RiskSeverity


def test_epss_fetcher_offline_seed() -> None:
    """Test EPSS fetcher score retrieval for seed CVE."""
    scores = EPSSFetcher.get_epss_scores(["CVE-2021-44228", "CVE-9999-0000"])
    assert "CVE-2021-44228" in scores
    epss, percentile = scores["CVE-2021-44228"]
    assert epss >= 0.9  # High probability for Log4Shell
    assert percentile >= 0.9

    # Unknown CVE should receive baseline low score
    assert "CVE-9999-0000" in scores
    assert scores["CVE-9999-0000"][0] == 0.01


def test_cisa_kev_fetcher_seed() -> None:
    """Test CISA KEV catalog fetcher for seed CVE."""
    assert CISAKEVFetcher.is_in_kev("CVE-2021-44228") is True
    assert CISAKEVFetcher.is_in_kev("CVE-2017-0144") is True
    assert CISAKEVFetcher.is_in_kev("CVE-2000-0000") is False


def test_tri_factor_risk_scoring() -> None:
    """Test Tri-Factor composite risk scoring calculation."""
    scan_result = HostScanResult(scan_id="test-123", target="192.168.1.5")

    log4j_cve = CVERecord(
        cve_id="CVE-2021-44228",
        description="Log4j RCE vulnerability",
        cvss_score=10.0,
        cvss_severity=RiskSeverity.CRITICAL,
        affected_product="Apache Log4j",
        affected_version="2.14.1",
    )

    cve_matches = [(8080, "http-alt", "Apache Log4j", log4j_cve)]

    findings = RiskEngine.prioritize_findings(scan_result, cve_matches)

    assert len(findings) == 1
    f = findings[0]

    assert f.cve.epss_score is not None
    assert f.cve.epss_score >= 0.9
    assert f.cve.in_cisa_kev is True
    assert f.tri_factor_score == 10.0  # Capped at max 10.0
    assert f.severity == RiskSeverity.CRITICAL
