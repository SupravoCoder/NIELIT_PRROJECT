"""Unit tests for Local Air-Gapped Ollama AI and LLMExplainer Gateway."""

from app.ai.explainer import LLMExplainer
from app.ai.ollama_client import OllamaClient
from app.utils.schemas import LLMAnalysisRequest


def test_ollama_client_offline_availability() -> None:
    """Test Ollama client gracefully handles non-running server."""
    client = OllamaClient(host="http://localhost:59999")  # Non-existent port
    assert client.is_available() is False
    assert client.get_installed_models() == []


def test_explainer_template_fallback() -> None:
    """Test LLMExplainer falls back to free template engine when provider='template'."""
    explainer = LLMExplainer(ollama_host="http://localhost:59999")

    request = LLMAnalysisRequest(
        cve_id="CVE-2021-44228",
        product="Apache Log4j",
        version="2.14.1",
        description="Remote code execution flaw",
        cvss_score=10.0,
        severity="CRITICAL",
    )

    response = explainer.explain_vulnerability(request, provider="template")

    assert response.cve_id == "CVE-2021-44228"
    assert "Apache Log4j" in response.plain_explanation
    assert len(response.remediation_steps) > 0
    assert "apt-get" in response.patch_recommendations


def test_explainer_auto_provider_resilience() -> None:
    """Test LLMExplainer auto provider mode does not fail when local Ollama is offline."""
    explainer = LLMExplainer(ollama_host="http://localhost:59999")

    request = LLMAnalysisRequest(
        cve_id="CVE-2017-0144",
        product="SMBv1",
        version="1.0",
        description="EternalBlue RCE vulnerability",
        cvss_score=9.8,
        severity="CRITICAL",
    )

    response = explainer.explain_vulnerability(request, provider="auto")

    assert response.cve_id == "CVE-2017-0144"
    assert "SMBv1" in response.plain_explanation
