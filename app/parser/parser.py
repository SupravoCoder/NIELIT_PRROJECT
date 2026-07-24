"""Parser and normalization engine for service names and CPE product identifiers."""

import re
from typing import Dict, Optional, Tuple


class SoftwareNormalizer:
    """Normalizes raw scan service strings into query-ready vendor and product tuples."""

    @staticmethod
    def normalize_service(product: Optional[str], version: Optional[str], service_name: str) -> Dict[str, Optional[str]]:
        """Normalize product name and software version into standardized search terms."""
        if not product:
            product = service_name or "unknown"
        
        cleaned_product = product.strip()
        cleaned_version = version.strip() if version else None

        # Standard vendor mappings
        vendor, cpe_product = SoftwareNormalizer._infer_vendor_and_product(cleaned_product)

        return {
            "raw_product": product,
            "raw_version": version,
            "normalized_vendor": vendor,
            "normalized_product": cpe_product,
            "normalized_version": cleaned_version,
            "cpe_keyword": f"{vendor}:{cpe_product}" if vendor else cpe_product,
        }

    @staticmethod
    def _infer_vendor_and_product(product_str: str) -> Tuple[Optional[str], str]:
        """Infer common vendor and product names for CPE queries."""
        p_lower = product_str.lower()

        if "apache" in p_lower and "http" in p_lower:
            return "apache", "http_server"
        if "openssh" in p_lower or "ssh" in p_lower:
            return "openbsd", "openssh"
        if "openssl" in p_lower:
            return "openssl", "openssl"
        if "mysql" in p_lower:
            return "oracle", "mysql"
        if "nginx" in p_lower:
            return "f5", "nginx"
        if "postgres" in p_lower:
            return "postgresql", "postgresql"

        # Fallback: clean string
        clean_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", p_lower)
        return None, clean_name
