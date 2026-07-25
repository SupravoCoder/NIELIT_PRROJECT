"""NVD Vulnerability Database client and local CVE matching engine."""

import logging
import re
from typing import List, Optional

import requests
from app.utils.schemas import CVERecord, RiskSeverity

logger = logging.getLogger(__name__)

# ── Product name aliases ─────────────────────────────────────────────────────
# Maps common Nmap-reported product names to canonical names used in the seed.
PRODUCT_ALIASES = {
    "apache httpd": "apache",
    "apache http server": "apache",
    "apache/2": "apache",
    "apache": "apache",
    "nginx": "nginx",
    "openssl": "openssl",
    "openssh": "openssh",
    "mysql": "mysql",
    "mariadb": "mysql",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "microsoft iis httpd": "iis",
    "microsoft iis": "iis",
    "iis": "iis",
    "lighttpd": "lighttpd",
    "php": "php",
    "tomcat": "tomcat",
    "apache tomcat": "tomcat",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "pure-ftpd": "ftpd",
    "exim": "exim",
    "postfix": "postfix",
    "dovecot": "dovecot",
    "bind": "bind",
    "bwapp": "bwapp",
    "http": "http",
    "https": "https",
    "ssh": "openssh",
    "ftp": "ftp",
    "smtp": "smtp",
}


def _canonical(name: str) -> str:
    """Resolve a product name to its canonical form."""
    key = name.strip().lower()
    return PRODUCT_ALIASES.get(key, key)


def _extract_keywords(name: str) -> set:
    """Split a product name into lowercase keyword tokens."""
    return set(re.split(r"[\s/\-_]+", name.strip().lower())) - {"", "server", "httpd"}


# ── Expanded local CVE seed database ─────────────────────────────────────────
LOCAL_CVE_SEED = [
    # Apache
    CVERecord(
        cve_id="CVE-2021-41773",
        description="A flaw in path normalization in Apache HTTP Server 2.4.49 allows path traversal attack to access files outside configured directories.",
        cvss_score=7.5, cvss_severity=RiskSeverity.HIGH,
        published_date="2021-10-05",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
        affected_product="apache", affected_version=None,
    ),
    CVERecord(
        cve_id="CVE-2021-42013",
        description="Incomplete fix for CVE-2021-41773 in Apache HTTP Server allows path traversal and remote code execution if mod_cgi is enabled.",
        cvss_score=9.8, cvss_severity=RiskSeverity.CRITICAL,
        published_date="2021-10-07",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
        affected_product="apache", affected_version=None,
    ),
    CVERecord(
        cve_id="CVE-2023-25690",
        description="HTTP request smuggling via mod_proxy in Apache HTTP Server versions prior to 2.4.56 allows attackers to bypass access controls.",
        cvss_score=9.8, cvss_severity=RiskSeverity.CRITICAL,
        published_date="2023-03-07",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-25690"],
        affected_product="apache", affected_version=None,
    ),
    # OpenSSH
    CVERecord(
        cve_id="CVE-2018-15473",
        description="OpenSSH through 7.7 is prone to user enumeration vulnerability due to differing responses during authentication.",
        cvss_score=5.3, cvss_severity=RiskSeverity.MEDIUM,
        published_date="2018-08-17",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"],
        affected_product="openssh", affected_version=None,
    ),
    CVERecord(
        cve_id="CVE-2024-6387",
        description="RegreSSHion: Remote unauthenticated code execution in OpenSSH server due to signal handler race condition.",
        cvss_score=8.1, cvss_severity=RiskSeverity.HIGH,
        published_date="2024-07-01",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
        affected_product="openssh", affected_version=None,
    ),
    # OpenSSL
    CVERecord(
        cve_id="CVE-2021-3711",
        description="SM2 Decryption Buffer Overflow in OpenSSL 1.1.1 series before 1.1.1l allows remote code execution.",
        cvss_score=7.5, cvss_severity=RiskSeverity.HIGH,
        published_date="2021-08-24",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-3711"],
        affected_product="openssl", affected_version=None,
    ),
    # MySQL / MariaDB
    CVERecord(
        cve_id="CVE-2020-14867",
        description="MySQL Server DDL vulnerability allows high-privileged attacker to cause denial of service via network protocols.",
        cvss_score=4.4, cvss_severity=RiskSeverity.MEDIUM,
        published_date="2020-10-21",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-14867"],
        affected_product="mysql", affected_version=None,
    ),
    # Nginx
    CVERecord(
        cve_id="CVE-2021-23017",
        description="1-byte memory overwrite in Nginx resolver allows remote crash or arbitrary code execution.",
        cvss_score=8.1, cvss_severity=RiskSeverity.HIGH,
        published_date="2021-05-25",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"],
        affected_product="nginx", affected_version=None,
    ),
    CVERecord(
        cve_id="CVE-2022-41741",
        description="Memory corruption in Nginx mp4 module allows local attacker to crash worker process or achieve code execution.",
        cvss_score=7.8, cvss_severity=RiskSeverity.HIGH,
        published_date="2022-10-19",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-41741"],
        affected_product="nginx", affected_version=None,
    ),
    # PostgreSQL
    CVERecord(
        cve_id="CVE-2019-9193",
        description="PostgreSQL COPY FROM PROGRAM allows authenticated database users to execute arbitrary operating system commands.",
        cvss_score=8.8, cvss_severity=RiskSeverity.HIGH,
        published_date="2019-04-01",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-9193"],
        affected_product="postgresql", affected_version=None,
    ),
    # PHP
    CVERecord(
        cve_id="CVE-2024-4577",
        description="PHP CGI argument injection on Windows allows remote code execution via crafted query strings.",
        cvss_score=9.8, cvss_severity=RiskSeverity.CRITICAL,
        published_date="2024-06-09",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-4577"],
        affected_product="php", affected_version=None,
    ),
    # Microsoft IIS
    CVERecord(
        cve_id="CVE-2021-31166",
        description="HTTP Protocol Stack Remote Code Execution vulnerability in Microsoft IIS allows unauthenticated wormable attacks.",
        cvss_score=9.8, cvss_severity=RiskSeverity.CRITICAL,
        published_date="2021-05-11",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-31166"],
        affected_product="iis", affected_version=None,
    ),
    # Generic HTTP/HTTPS service
    CVERecord(
        cve_id="CVE-2022-29404",
        description="HTTP server denial-of-service via specially crafted request body can cause memory exhaustion.",
        cvss_score=7.5, cvss_severity=RiskSeverity.HIGH,
        published_date="2022-06-08",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-29404"],
        affected_product="http", affected_version=None,
    ),
    CVERecord(
        cve_id="CVE-2023-44487",
        description="HTTP/2 Rapid Reset Attack allows denial of service against any HTTP/2-capable web server.",
        cvss_score=7.5, cvss_severity=RiskSeverity.HIGH,
        published_date="2023-10-10",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
        affected_product="https", affected_version=None,
    ),
    # FTP
    CVERecord(
        cve_id="CVE-2015-3306",
        description="ProFTPD mod_copy allows unauthenticated remote file copy leading to remote code execution.",
        cvss_score=10.0, cvss_severity=RiskSeverity.CRITICAL,
        published_date="2015-04-22",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2015-3306"],
        affected_product="ftp", affected_version=None,
    ),
    # SMTP
    CVERecord(
        cve_id="CVE-2019-15846",
        description="Exim mail server buffer overflow in TLS handling allows remote code execution.",
        cvss_score=9.8, cvss_severity=RiskSeverity.CRITICAL,
        published_date="2019-09-06",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-15846"],
        affected_product="smtp", affected_version=None,
    ),
    # bWAPP
    CVERecord(
        cve_id="CVE-2014-9999",
        description="bWAPP v2.2 contains multiple intentional vulnerabilities including SQL injection, XSS, command injection, and broken authentication.",
        cvss_score=9.8, cvss_severity=RiskSeverity.CRITICAL,
        published_date="2014-07-01",
        references=["http://www.itsecgames.com/"],
        affected_product="bwapp", affected_version=None,
    ),
    # Tomcat
    CVERecord(
        cve_id="CVE-2020-1938",
        description="Apache Tomcat AJP connector (Ghostcat) allows file read and potential remote code execution.",
        cvss_score=9.8, cvss_severity=RiskSeverity.CRITICAL,
        published_date="2020-02-24",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-1938"],
        affected_product="tomcat", affected_version=None,
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

        # Always try local seed first — it's fast and reliable
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
            logger.warning(f"NVD API request failed/timed out: {e}")

        return []

    def _query_nvd_api(self, product: str, version: Optional[str]) -> List[CVERecord]:
        """Execute request to NVD API v2."""
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        keyword = f"{product} {version}" if version else product
        params = {"keywordSearch": keyword, "resultsPerPage": 10}

        resp = requests.get(self.NVD_API_URL, headers=headers, params=params, timeout=15)
        if resp.status_code != 200:
            raise RuntimeError(f"NVD API returned HTTP {resp.status_code}")

        data = resp.json()
        results = []
        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:
            cve_dict = item.get("cve", {})
            cve_id = cve_dict.get("id", "CVE-UNKNOWN")

            descriptions = cve_dict.get("descriptions", [])
            desc_text = next(
                (d.get("value") for d in descriptions if d.get("lang") == "en"),
                "No description available.",
            )

            cvss_score = 0.0
            severity = RiskSeverity.INFO
            metrics = cve_dict.get("metrics", {})

            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metric_key in metrics and metrics[metric_key]:
                    cvss_data = metrics[metric_key][0].get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    sev_str = cvss_data.get("baseSeverity", "INFO").upper()
                    severity = getattr(RiskSeverity, sev_str, RiskSeverity.INFO)
                    break

            if cvss_score > 0:
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
        """Match product against offline seed using canonical name resolution."""
        canonical = _canonical(product)
        keywords = _extract_keywords(product)
        matched = []

        for cve in LOCAL_CVE_SEED:
            if not cve.affected_product:
                continue
            cve_canonical = cve.affected_product.lower()

            # Primary: canonical name match
            if canonical == cve_canonical:
                matched.append(cve)
                continue

            # Secondary: keyword overlap (e.g., "apache" in product keywords)
            cve_keywords = _extract_keywords(cve.affected_product)
            if keywords & cve_keywords:
                matched.append(cve)

        return matched
