"""NVD Vulnerability Database client and local CVE matching engine."""

import logging
from typing import List, Optional

import requests
from app.utils.schemas import CVERecord, RiskSeverity

logger = logging.getLogger(__name__)


# Local fallback offline database for guaranteed demonstration stability
LOCAL_CVE_SEED = [
    CVERecord(
        cve_id="CVE-2021-41773",
        description="A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives.",
        cvss_score=7.5,
        cvss_severity=RiskSeverity.HIGH,
        published_date="2021-10-05",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
        affected_product="Apache HTTP Server",
        affected_version="2.4.49",
    ),
    CVERecord(
        cve_id="CVE-2021-42013",
        description="It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was incomplete. Path traversal and remote code execution could occur if mod_cgi is enabled.",
        cvss_score=9.8,
        cvss_severity=RiskSeverity.CRITICAL,
        published_date="2021-10-07",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
        affected_product="Apache HTTP Server",
        affected_version="2.4.49",
    ),
    CVERecord(
        cve_id="CVE-2018-15473",
        description="OpenSSH through 7.7 is prone to an enumeration vulnerability due to differing responses during user authentication.",
        cvss_score=5.3,
        cvss_severity=RiskSeverity.MEDIUM,
        published_date="2018-08-17",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"],
        affected_product="OpenSSH",
        affected_version="7.4p1",
    ),
    CVERecord(
        cve_id="CVE-2021-3711",
        description="SM2 Decryption Buffer Overflow vulnerability in OpenSSL 1.1.1 series before 1.1.1l.",
        cvss_score=7.5,
        cvss_severity=RiskSeverity.HIGH,
        published_date="2021-08-24",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-3711"],
        affected_product="OpenSSL",
        affected_version="1.1.1k",
    ),
    CVERecord(
        cve_id="CVE-2020-14867",
        description="Vulnerability in MySQL Server (component: Server: DDL) allows high-privileged attacker to cause a hang or crash via network protocols, resulting in denial of service.",
        cvss_score=4.4,
        cvss_severity=RiskSeverity.MEDIUM,
        published_date="2020-10-21",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-14867"],
        affected_product="MySQL",
        affected_version="5.7.31",
    ),
    CVERecord(
        cve_id="CVE-2021-23017",
        description="A 1-byte memory overwrite flaw was found in Nginx resolver. A remote attacker could cause a worker process crash or potential arbitrary code execution.",
        cvss_score=8.1,
        cvss_severity=RiskSeverity.HIGH,
        published_date="2021-05-25",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"],
        affected_product="Nginx",
        affected_version="1.20.0",
    ),
    CVERecord(
        cve_id="CVE-2019-9193",
        description="Command execution vulnerability in PostgreSQL COPY FROM PROGRAM allows authenticated database users to execute arbitrary operating system commands.",
        cvss_score=8.8,
        cvss_severity=RiskSeverity.HIGH,
        published_date="2019-04-01",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-9193"],
        affected_product="PostgreSQL",
        affected_version="11.2",
    ),
]


class NVDCVEEngine:
    """Queries NVD API v2 or local cache to match product versions against known CVEs."""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key

    def search_cves_for_service(
        self, product: str, version: Optional[str] = None, use_local_fallback: bool = True
    ) -> List[CVERecord]:
        """Search CVEs by software product and version string."""
        if not product:
            return []

        logger.info(f"Searching CVE database for product='{product}' version='{version}'")

        # In mock/fallback mode, use the local seed database first for reliable results
        if use_local_fallback:
            local_matches = self._match_local_seed_cves(product, version)
            if local_matches:
                logger.info(f"Local seed matched {len(local_matches)} CVEs for '{product}'")
                return local_matches

        # Try live NVD API lookup
        try:
            live_cves = self._query_nvd_api(product, version)
            if live_cves:
                return live_cves
        except Exception as e:
            logger.warning(f"NVD API request failed/timed out: {e}. Using seed fallback database.")

        # Final fallback to local seed if nothing else worked
        if use_local_fallback:
            return self._match_local_seed_cves(product, version)

        return []

    def _query_nvd_api(self, product: str, version: Optional[str]) -> List[CVERecord]:
        """Execute request to NVD API v2."""
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        keyword = f"{product} {version}" if version else product
        params = {"keywordSearch": keyword, "resultsPerPage": 10}

        resp = requests.get(self.NVD_API_URL, headers=headers, params=params, timeout=4)
        if resp.status_code != 200:
            raise RuntimeError(f"NVD API returned HTTP {resp.status_code}")

        data = resp.json()
        results = []
        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:
            cve_dict = item.get("cve", {})
            cve_id = cve_dict.get("id", "CVE-UNKNOWN")
            
            # Extract description
            descriptions = cve_dict.get("descriptions", [])
            desc_text = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description available.")

            # Extract metrics
            cvss_score = 0.0
            severity = RiskSeverity.INFO
            metrics = cve_dict.get("metrics", {})
            
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                v31_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = float(v31_data.get("baseScore", 0.0))
                sev_str = v31_data.get("baseSeverity", "INFO").upper()
                severity = getattr(RiskSeverity, sev_str, RiskSeverity.INFO)

            results.append(
                CVERecord(
                    cve_id=cve_id,
                    description=desc_text,
                    cvss_score=cvss_score,
                    cvss_severity=severity,
                    published_date=cve_dict.get("published", "")[:10],
                    references=[r.get("url") for r in cve_dict.get("references", [])[:3]],
                    affected_product=product,
                    affected_version=version,
                )
            )
        return results

    def _match_local_seed_cves(self, product: str, version: Optional[str]) -> List[CVERecord]:
        """Perform match against offline seed dataset."""
        matched = []
        prod_lower = product.lower()

        for cve in LOCAL_CVE_SEED:
            if not cve.affected_product:
                continue
            cve_prod_lower = cve.affected_product.lower()
            # Match if product names overlap (e.g., 'apache' in 'apache http server' or vice-versa)
            if cve_prod_lower in prod_lower or prod_lower in cve_prod_lower:
                if version and cve.affected_version:
                    # Match exact version or partial version prefix
                    if version.strip() == cve.affected_version.strip() or version.strip().startswith(cve.affected_version.strip()):
                        matched.append(cve)
                else:
                    matched.append(cve)

        # Fallback: if version specified but no exact version match, return product matches
        if not matched and version:
            for cve in LOCAL_CVE_SEED:
                if not cve.affected_product:
                    continue
                cve_prod_lower = cve.affected_product.lower()
                if cve_prod_lower in prod_lower or prod_lower in cve_prod_lower:
                    matched.append(cve)

        return matched
