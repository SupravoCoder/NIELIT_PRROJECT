"""Risk calculation and vulnerability prioritization engine."""

import uuid
from typing import List
from app.utils.schemas import CVERecord, HostScanResult, RiskSeverity, VulnerabilityFinding


class RiskEngine:
    """Calculates prioritized risk scores and orders vulnerabilities by severity impact."""

    # Exposed port critical weights
    HIGH_EXPOSURE_PORTS = {22, 80, 443, 3306, 5432, 8080, 8443}

    @staticmethod
    def prioritize_findings(scan_result: HostScanResult, cve_matches: List[tuple[int, str, str, CVERecord]]) -> List[VulnerabilityFinding]:
        """Convert raw CVE matches into prioritized vulnerability findings."""
        findings: List[VulnerabilityFinding] = []

        for port, service_name, product, cve in cve_matches:
            # Composite risk calculation
            exposure_multiplier = 1.2 if port in RiskEngine.HIGH_EXPOSURE_PORTS else 1.0
            composite_score = min(10.0, round(cve.cvss_score * exposure_multiplier, 1))

            severity = RiskEngine._derive_severity(composite_score)

            finding = VulnerabilityFinding(
                finding_id=str(uuid.uuid4())[:8],
                host=scan_result.target,
                port=port,
                service_name=service_name,
                product=product,
                version=cve.affected_version or "Unknown",
                cve=cve,
                risk_score=composite_score,
                severity=severity,
            )
            findings.append(finding)

        # Sort findings descending by risk score
        findings.sort(key=lambda x: x.risk_score, reverse=True)
        return findings

    @staticmethod
    def _derive_severity(score: float) -> RiskSeverity:
        """Map CVSS/composite score to severity tier."""
        if score >= 9.0:
            return RiskSeverity.CRITICAL
        if score >= 7.0:
            return RiskSeverity.HIGH
        if score >= 4.0:
            return RiskSeverity.MEDIUM
        if score > 0.0:
            return RiskSeverity.LOW
        return RiskSeverity.INFO
