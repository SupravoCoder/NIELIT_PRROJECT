"""API router for HTML/PDF security assessment report generation."""

from fastapi import APIRouter, Response
from app.reports.report_generator import SecurityReportGenerator
from app.utils.schemas import ScanAssessmentSummary

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/html", summary="Generate HTML security report")
async def generate_html_report_endpoint(summary: ScanAssessmentSummary) -> Response:
    """Generate interactive HTML Executive & Technical security assessment report."""
    html_str = SecurityReportGenerator.generate_html_report(summary)
    return Response(content=html_str, media_type="text/html")
