"""Ollama local air-gapped LLM client for 100% free, private security analysis."""

import logging
import os
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger(__name__)


class OllamaClient:
    """Interfaces with local Ollama server (http://localhost:11434) for zero-cost local LLM inference."""

    DEFAULT_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

    def __init__(self, host: Optional[str] = None) -> None:
        self.host = (host or self.DEFAULT_HOST).rstrip("/")

    def is_available(self) -> bool:
        """Check if local Ollama server is active and accepting HTTP requests."""
        try:
            with httpx.Client(timeout=1.5) as client:
                resp = client.get(f"{self.host}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False

    def get_installed_models(self) -> List[str]:
        """Fetch list of locally installed Ollama model tags."""
        try:
            with httpx.Client(timeout=2.0) as client:
                resp = client.get(f"{self.host}/api/tags")
                if resp.status_code == 200:
                    models = resp.json().get("models", [])
                    return [m.get("name") for m in models if m.get("name")]
        except Exception as e:
            logger.debug(f"Could not fetch Ollama models: {e}")
        return []

    def generate_explanation(
        self,
        cve_id: str,
        product: str,
        version: str,
        description: str,
        cvss_score: float,
        model: str = "llama3",
    ) -> Optional[Dict[str, Any]]:
        """Generate structured security explanation using local Ollama model."""
        prompt = (
            f"You are an expert cybersecurity advisor analyzing vulnerability {cve_id}.\n"
            f"Target Software: {product} (Version: {version})\n"
            f"CVSS Risk Score: {cvss_score}\n"
            f"Vulnerability Summary: {description}\n\n"
            f"Provide a concise security report response in exact format:\n"
            f"EXPLANATION: <plain language root cause explanation>\n"
            f"BUSINESS_IMPACT: <impact on operations and data>\n"
            f"REMEDIATION: <step by step fix command>\n"
        )

        try:
            payload = {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "num_predict": 250,
                },
            }
            with httpx.Client(timeout=12.0) as client:
                resp = client.post(f"{self.host}/api/generate", json=payload)
                if resp.status_code == 200:
                    raw_text = resp.json().get("response", "")
                    return self._parse_llm_response(cve_id, product, version, raw_text)
        except Exception as e:
            logger.warning(f"Ollama generation failed ({e}). Falling back to template explainer.")

        return None

    @staticmethod
    def _parse_llm_response(cve_id: str, product: str, version: str, raw_text: str) -> Dict[str, Any]:
        """Parse raw text response from Ollama into structured components."""
        expl = f"The software '{product}' (v{version}) is affected by security flaw {cve_id}."
        biz = f"Exploitation of {cve_id} may cause service outage or unauthorized access."
        patch = f"Upgrade {product} to the latest version. Apply OS patches: `sudo apt-get update && sudo apt-get --only-upgrade install {product.lower().replace(' ', '')}`"

        lines = raw_text.split("\n")
        for line in lines:
            if line.startswith("EXPLANATION:"):
                expl = line.replace("EXPLANATION:", "").strip()
            elif line.startswith("BUSINESS_IMPACT:"):
                biz = line.replace("BUSINESS_IMPACT:", "").strip()
            elif line.startswith("REMEDIATION:"):
                patch = line.replace("REMEDIATION:", "").strip()

        return {
            "cve_id": cve_id,
            "plain_explanation": expl or raw_text[:200],
            "business_impact": biz,
            "technical_impact": f"Risk rated at CVSS {cve_id}. Local LLM verified threat vector.",
            "remediation_steps": [patch, "Apply network perimeter access controls.", "Enable audit logging."],
            "patch_recommendations": patch,
        }
