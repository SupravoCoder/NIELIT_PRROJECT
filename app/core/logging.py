"""Logging configuration helpers for VulnSense AI."""

import logging

from app.core.settings import Settings


def configure_logging(settings: Settings) -> None:
    """Configure process-wide logging once at startup."""

    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
