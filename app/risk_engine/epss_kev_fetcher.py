"""EPSS (Exploit Prediction Scoring System) and CISA KEV (Known Exploited Vulnerabilities) Threat Intelligence Fetcher."""

import logging
from typing import Dict, List, Optional, Set, Tuple
import httpx

logger = logging.getLogger(__name__)

# Fallback offline seed for CISA KEV catalog
OFFLINE_CISA_KEV_SEED: Set[str] = {
    "CVE-2021-44228",  # Log4Shell
    "CVE-2017-0144",   # EternalBlue
    "CVE-2014-0160",   # Heartbleed
    "CVE-2014-6271",   # Shellshock
    "CVE-2017-5638",   # Apache Struts2
    "CVE-2019-19781",  # Citrix ADC
    "CVE-2020-0688",   # Microsoft Exchange
    "CVE-2021-26855",  # ProxyLogon
    "CVE-2023-38606",  # Triangulation
}

# Fallback offline seed for EPSS scores (cve_id -> (score, percentile))
OFFLINE_EPSS_SEED: Dict[str, Tuple[float, float]] = {
    "CVE-2021-44228": (0.975, 0.999),
    "CVE-2017-0144": (0.973, 0.998),
    "CVE-2014-0160": (0.965, 0.995),
    "CVE-2014-6271": (0.958, 0.992),
    "CVE-2017-5638": (0.961, 0.993),
    "CVE-2019-19781": (0.942, 0.989),
}


class EPSSFetcher:
    """Fetches EPSS exploit probability scores from FIRST.org API with local caching."""

    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    _cache: Dict[str, Tuple[float, float]] = dict(OFFLINE_EPSS_SEED)

    @classmethod
    def get_epss_scores(cls, cve_ids: List[str]) -> Dict[str, Tuple[float, float]]:
        """Fetch EPSS score and percentile for a list of CVE IDs."""
        results: Dict[str, Tuple[float, float]] = {}
        missing_cves = [cve for cve in cve_ids if cve not in cls._cache]

        # Use cached scores where available
        for cve in cve_ids:
            if cve in cls._cache:
                results[cve] = cls._cache[cve]

        if not missing_cves:
            return results

        # Fetch missing scores from FIRST.org API
        try:
            cve_param = ",".join(missing_cves[:50])  # Batch limit
            with httpx.Client(timeout=3.0) as client:
                response = client.get(cls.EPSS_API_URL, params={"cve": cve_param})
                if response.status_code == 200:
                    data = response.json().get("data", [])
                    for item in data:
                        cve_id = item.get("cve")
                        epss = float(item.get("epss", 0.0))
                        percentile = float(item.get("percentile", 0.0))
                        cls._cache[cve_id] = (epss, percentile)
                        results[cve_id] = (epss, percentile)
        except Exception as e:
            logger.warning(f"EPSS API fetch failed ({e}). Using offline seed scores.")

        # Default non-found CVEs to 0.01 baseline probability
        for cve in missing_cves:
            if cve not in results:
                results[cve] = (0.01, 0.10)

        return results


class CISAKEVFetcher:
    """Fetches and caches the CISA Known Exploited Vulnerabilities (KEV) catalog."""

    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    _kev_set: Optional[Set[str]] = None

    @classmethod
    def get_kev_set(cls) -> Set[str]:
        """Get set of active CISA KEV CVE IDs."""
        if cls._kev_set is not None:
            return cls._kev_set

        cls._kev_set = set(OFFLINE_CISA_KEV_SEED)

        try:
            with httpx.Client(timeout=3.0) as client:
                response = client.get(cls.CISA_KEV_URL)
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    fetched_set = {v.get("cveID") for v in vulnerabilities if v.get("cveID")}
                    if fetched_set:
                        cls._kev_set.update(fetched_set)
                        logger.info(f"Loaded {len(cls._kev_set)} CISA KEV catalog entries.")
        except Exception as e:
            logger.warning(f"CISA KEV catalog fetch failed ({e}). Using offline seed set.")

        return cls._kev_set

    @classmethod
    def is_in_kev(cls, cve_id: str) -> bool:
        """Check if a CVE is in CISA KEV catalog."""
        kev_set = cls.get_kev_set()
        return cve_id in kev_set
