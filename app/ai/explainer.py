"""AI explanation and remediation generation layer with Local Ollama & Cloud LLM support."""

import os
import logging
from typing import Optional
from app.ai.ollama_client import OllamaClient
from app.utils.schemas import LLMAnalysisRequest, LLMAnalysisResponse

logger = logging.getLogger(__name__)


class LLMExplainer:
    """Generates plain-language vulnerability explanations using Local Ollama, Cloud LLM, or Template fallbacks."""

    def __init__(self, api_key: Optional[str] = None, ollama_host: Optional[str] = None) -> None:
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.ollama_client = OllamaClient(host=ollama_host)

    def explain_vulnerability(
        self,
        request: LLMAnalysisRequest,
        provider: str = "auto",
        ollama_model: str = "llama3",
    ) -> LLMAnalysisResponse:
        """Generate structured security explanation using specified AI provider."""
        
        # 1. Local Air-Gapped Ollama Mode (100% Free & Private)
        if provider in ["auto", "ollama"] and self.ollama_client.is_available():
            logger.info(f"Using Local Air-Gapped Ollama LLM (model='{ollama_model}') for {request.cve_id}")
            ollama_res = self.ollama_client.generate_explanation(
                cve_id=request.cve_id,
                product=request.product,
                version=request.version,
                description=request.description,
                cvss_score=request.cvss_score,
                model=ollama_model,
            )
            if ollama_res:
                return LLMAnalysisResponse(**ollama_res)

        # 2. Rule-Based Template Fallback (100% Free & Instant)
        logger.info(f"Using Expert Rule-Based Template Engine for {request.cve_id}")
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
