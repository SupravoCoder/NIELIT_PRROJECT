"""CERT-In, NIST SP 800-53, and ISO/IEC 27001 Compliance Framework Mapping Module."""

from typing import Dict


class ComplianceMapper:
    """Maps network vulnerability findings to national and international cybersecurity compliance frameworks."""

    @staticmethod
    def map_finding(
        port: int,
        service_name: str,
        product: str,
        severity: str,
        cvss_score: float,
        in_cisa_kev: bool = False,
    ) -> Dict[str, str]:
        """Generate compliance framework tags for a vulnerability finding."""
        
        # 1. CERT-In Cyber Security Directions (India)
        if severity in ["CRITICAL", "HIGH"] or in_cisa_kev:
            cert_in_tag = "CERT-In Sec 5(ii) — Mandated Flaw Remediation within 48h"
        elif port in {22, 80, 443, 3306, 5432, 8080, 8443}:
            cert_in_tag = "CERT-In Sec 5(iv) — Perimeter Boundary & Exposed Service Audit"
        else:
            cert_in_tag = "CERT-In Sec 5(vi) — System Log & Event Auditing"

        # 2. NIST SP 800-53 Rev. 5 Controls
        if severity in ["CRITICAL", "HIGH"]:
            nist_tag = "NIST SP 800-53 SI-2 — Flaw Remediation & Emergency Patching"
        elif service_name.lower() in ["ssh", "rdp", "ftp", "telnet"]:
            nist_tag = "NIST SP 800-53 IA-5 — Authenticator & Remote Access Management"
        elif port in {80, 443, 8080, 8443}:
            nist_tag = "NIST SP 800-53 SC-7 — Boundary Protection & Gateway Control"
        else:
            nist_tag = "NIST SP 800-53 RA-5 — Vulnerability Monitoring & Assessment"

        # 3. ISO/IEC 27001:2022 Annex A Controls
        if severity in ["CRITICAL", "HIGH"]:
            iso_tag = "ISO/IEC 27001 A.8.8 — Technical Vulnerability Management"
        else:
            iso_tag = "ISO/IEC 27001 A.8.20 — Network Security & Port Controls"

        return {
            "cert_in": cert_in_tag,
            "nist": nist_tag,
            "iso": iso_tag,
        }
