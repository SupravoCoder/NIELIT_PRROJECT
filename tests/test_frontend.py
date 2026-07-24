"""Tests for Streamlit frontend helper functions."""

from app.frontend.app import check_backend_health


def test_backend_health_check_disconnected(monkeypatch):
    """Test that check_backend_health returns False when backend is unreachable."""

    def mock_get(*args, **kwargs):
        raise Exception("Connection refused")

    import requests

    monkeypatch.setattr(requests, "get", mock_get)

    assert check_backend_health() is False
