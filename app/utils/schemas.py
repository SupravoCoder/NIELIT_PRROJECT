"""Pydantic data models and API request/response schemas for VulnSense AI."""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class RiskSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PortScanRequest(BaseModel):
    target: str = Field(..., description="Target IP address or domain hostname (e.g., 127.0.0.1 or 192.168.1.10)")
    scan_arguments: str = Field(default="-sV -T4 -F", description="Nmap scan argument string")
    use_mock_fallback: bool = Field(default=True, description="Enable simulated scan fallback if Nmap binary is absent")
    ai_provider: str = Field(default="auto", description="AI Provider: 'auto', 'ollama', 'openai', or 'template'")
    ollama_model: str = Field(default="llama3", description="Model tag if using Ollama (e.g. 'llama3', 'mistral')")


class ServiceInfo(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: str = "unknown"
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    banner: Optional[str] = None


class HostScanResult(BaseModel):
    scan_id: str
    target: str
    host_status: str = "up"
    services: List[ServiceInfo] = Field(default_factory=list)
    scan_time: datetime = Field(default_factory=datetime.utcnow)
    scan_duration_seconds: float = 0.0


class CVERecord(BaseModel):
    cve_id: str
    description: str
    cvss_score: float = 0.0
    cvss_severity: RiskSeverity = RiskSeverity.INFO
    published_date: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    affected_product: Optional[str] = None
    affected_version: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    in_cisa_kev: bool = False
    cisa_kev_due_date: Optional[str] = None


class VulnerabilityFinding(BaseModel):
    finding_id: str
    host: str
    port: int
    service_name: str
    product: str
    version: str
    cve: CVERecord
    risk_score: float
    severity: RiskSeverity
    tri_factor_score: float = 0.0
    epss_score: Optional[float] = None
    in_cisa_kev: bool = False
    compliance_tags: dict[str, str] = Field(default_factory=dict)
    llm_explanation: Optional[str] = None
    remediation_guidance: Optional[str] = None


class ScanAssessmentSummary(BaseModel):
    scan_id: str
    target: str
    total_services_scanned: int
    total_vulnerabilities_found: int
    max_cvss_score: float
    risk_distribution: dict[str, int]
    findings: List[VulnerabilityFinding]
    executive_summary: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class LLMAnalysisRequest(BaseModel):
    cve_id: str
    product: str
    version: str
    description: str
    cvss_score: float
    severity: str


class LLMAnalysisResponse(BaseModel):
    cve_id: str
    plain_explanation: str
    business_impact: str
    technical_impact: str
    remediation_steps: List[str]
    patch_recommendations: str
