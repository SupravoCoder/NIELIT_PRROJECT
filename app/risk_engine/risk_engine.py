"""Risk calculation and vulnerability prioritization engine using CVSS, EPSS, CISA KEV, and Compliance Mapping."""

import uuid
from typing import List, Tuple
from app.risk_engine.epss_kev_fetcher import CISAKEVFetcher, EPSSFetcher
from app.utils.compliance import ComplianceMapper
from app.utils.schemas import CVERecord, HostScanResult, RiskSeverity, VulnerabilityFinding


class RiskEngine:
    """Calculates prioritized tri-factor risk scores and maps findings to compliance standards."""

    # Exposed port critical weights
    HIGH_EXPOSURE_PORTS = {22, 80, 443, 3306, 5432, 8080, 8443, 21, 23, 389, 636, 3389}

    @staticmethod
    def prioritize_findings(
        scan_result: HostScanResult,
        cve_matches: List[Tuple[int, str, str, CVERecord]]
    ) -> List[VulnerabilityFinding]:
        """Convert raw CVE matches into prioritized tri-factor vulnerability findings with compliance tags."""
        findings: List[VulnerabilityFinding] = []

        if not cve_matches:
            return findings

        # Extract unique CVE IDs for batch threat intelligence fetch
        cve_ids = [cve.cve_id for _, _, _, cve in cve_matches]
        epss_map = EPSSFetcher.get_epss_scores(cve_ids)

        for port, service_name, product, cve in cve_matches:
            # 1. Fetch EPSS probability score
            epss_score, epss_percentile = epss_map.get(cve.cve_id, (0.01, 0.10))
            cve.epss_score = epss_score
            cve.epss_percentile = epss_percentile

            # 2. Check CISA Known Exploited Vulnerabilities catalog
            in_cisa_kev = CISAKEVFetcher.is_in_kev(cve.cve_id)
            cve.in_cisa_kev = in_cisa_kev
            if in_cisa_kev:
                cve.cisa_kev_due_date = "IMMEDIATE (Active Exploit)"

            # 3. Tri-Factor Composite Risk Calculation
            exposure_multiplier = 1.2 if port in RiskEngine.HIGH_EXPOSURE_PORTS else 1.0
            kev_multiplier = 1.3 if in_cisa_kev else 1.0

            raw_tri_score = cve.cvss_score * (1.0 + epss_score) * kev_multiplier * exposure_multiplier
            tri_factor_score = min(10.0, round(raw_tri_score, 1))

            severity = RiskEngine._derive_severity(tri_factor_score)

            # 4. Map Compliance Framework Controls (CERT-In, NIST SP 800-53, ISO 27001)
            compliance_tags = ComplianceMapper.map_finding(
                port=port,
                service_name=service_name,
                product=product,
                severity=severity.value,
                cvss_score=cve.cvss_score,
                in_cisa_kev=in_cisa_kev,
            )

            finding = VulnerabilityFinding(
                finding_id=str(uuid.uuid4())[:8],
                host=scan_result.target,
                port=port,
                service_name=service_name,
                product=product,
                version=cve.affected_version or "Unknown",
                cve=cve,
                risk_score=tri_factor_score,
                tri_factor_score=tri_factor_score,
                epss_score=epss_score,
                in_cisa_kev=in_cisa_kev,
                compliance_tags=compliance_tags,
                severity=severity,
            )
            findings.append(finding)

        # Sort findings descending by Tri-Factor risk score
        findings.sort(key=lambda x: x.risk_score, reverse=True)
        return findings

    @staticmethod
    def _derive_severity(score: float) -> RiskSeverity:
        """Map Tri-Factor score to severity tier."""
        if score >= 9.0:
            return RiskSeverity.CRITICAL
        if score >= 7.0:
            return RiskSeverity.HIGH
        if score >= 4.0:
            return RiskSeverity.MEDIUM
        if score > 0.0:
            return RiskSeverity.LOW
        return RiskSeverity.INFO
