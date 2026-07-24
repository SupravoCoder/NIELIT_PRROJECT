"""AI explanation and remediation generation layer for security findings."""

import os
import logging
from typing import Optional
from app.utils.schemas import CVERecord, LLMAnalysisRequest, LLMAnalysisResponse

logger = logging.getLogger(__name__)


class LLMExplainer:
    """Generates plain-language vulnerability explanations and patch recommendations."""

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")

    def explain_vulnerability(self, request: LLMAnalysisRequest) -> LLMAnalysisResponse:
        """Generate structured security explanation and remediation steps."""

        # Template-based expert security advisor generator
        plain_expl = (
            f"The software '{request.product}' version {request.version} contains a known security flaw ({request.cve_id}). "
            f"Specifically, {request.description}"
        )
        
        biz_impact = (
            f"Exploitation of {request.cve_id} on critical service {request.product} could lead to unexpected downtime, "
            f"unauthorized system access, or data exposure affecting business operational integrity."
        )

        tech_impact = (
            f"Technical risk rated at CVSS {request.cvss_score} ({request.severity}). "
            f"Impact includes possible input validation bypass, buffer boundary violations, or remote command processing."
        )

        remediations = [
            f"Upgrade {request.product} from version {request.version} to the latest stable vendor release immediately.",
            f"Restrict network ingress access on affected ports using local firewall rules (iptables/Windows Firewall).",
            f"Apply strict security context boundaries and principle of least privilege.",
        ]

        patch_rec = (
            f"Review official vendor advisory for {request.product}. "
            f"For Debian/Ubuntu systems: `sudo apt-get update && sudo apt-get --only-upgrade install {request.product.lower().replace(' ', '')}`"
        )

        return LLMAnalysisResponse(
            cve_id=request.cve_id,
            plain_explanation=plain_expl,
            business_impact=biz_impact,
            technical_impact=tech_impact,
            remediation_steps=remediations,
            patch_recommendations=patch_rec,
        )
