"""API router for network service scanning and automated vulnerability assessment."""

from fastapi import APIRouter, HTTPException, Query
from app.scanner.scanner import NmapScannerEngine
from app.cve_engine.cve_engine import NVDCVEEngine
from app.risk_engine.risk_engine import RiskEngine
from app.ai.explainer import LLMExplainer
from app.utils.schemas import (
    HostScanResult,
    LLMAnalysisRequest,
    PortScanRequest,
    ScanAssessmentSummary,
    VulnerabilityFinding,
)

router = APIRouter(prefix="/scan", tags=["vulnerability-scan"])

scanner_engine = NmapScannerEngine()
cve_engine = NVDCVEEngine()
llm_explainer = LLMExplainer()


@router.post("", response_model=ScanAssessmentSummary, summary="Run automated vulnerability assessment")
async def run_vulnerability_assessment(request: PortScanRequest) -> ScanAssessmentSummary:
    """Execute network discovery, parse software versions, match CVEs, calculate CVSS risk, and generate remediation guidance."""
    try:
        # Step 1: Execute discovery scan
        scan_result: HostScanResult = scanner_engine.execute_scan(
            target=request.target,
            arguments=request.scan_arguments,
            allow_fallback=request.use_mock_fallback,
        )

        raw_cve_matches = []
        
        # Step 2: Match detected services against NVD CVE engine
        for s in scan_result.services:
            prod_name = s.product or s.service_name
            if prod_name and prod_name.lower() != "unknown":
                cves = cve_engine.search_cves_for_service(
                    product=prod_name,
                    version=s.version,
                    use_local_fallback=request.use_mock_fallback,
                )
                for c in cves:
                    raw_cve_matches.append((s.port, s.service_name, prod_name, c))

        # Step 3: Compute prioritized risk scores
        findings: list[VulnerabilityFinding] = RiskEngine.prioritize_findings(scan_result, raw_cve_matches)

        # Step 4: Enrich findings with AI explanations & remediation steps
        enriched_findings = []
        max_score = 0.0
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for f in findings:
            max_score = max(max_score, f.risk_score)
            risk_counts[f.severity.value] = risk_counts.get(f.severity.value, 0) + 1

            analysis = llm_explainer.explain_vulnerability(
                LLMAnalysisRequest(
                    cve_id=f.cve.cve_id,
                    product=f.product,
                    version=f.version,
                    description=f.cve.description,
                    cvss_score=f.cve.cvss_score,
                    severity=f.severity.value,
                )
            )

            f.llm_explanation = analysis.plain_explanation
            f.remediation_guidance = analysis.patch_recommendations
            enriched_findings.append(f)

        exec_summary = (
            f"Assessment completed for target host '{request.target}'. Scanned {len(scan_result.services)} services "
            f"and identified {len(enriched_findings)} vulnerability findings. Peak CVSS Risk: {max_score}."
        )

        return ScanAssessmentSummary(
            scan_id=scan_result.scan_id,
            target=request.target,
            total_services_scanned=len(scan_result.services),
            total_vulnerabilities_found=len(enriched_findings),
            max_cvss_score=max_score,
            risk_distribution=risk_counts,
            findings=enriched_findings,
            executive_summary=exec_summary,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Assessment engine error: {str(e)}")
