"""Unit tests for URL Risk Analyzer & SSRF Guard."""

from backend.schemas.scan_schemas import ThreatType
from backend.security.ssrf_guard import is_private_or_restricted_ip
from backend.services.url_analyzer import url_analyzer


def test_ssrf_private_and_metadata_ip():
    assert is_private_or_restricted_ip("127.0.0.1") is True
    assert is_private_or_restricted_ip("192.168.1.1") is True
    assert is_private_or_restricted_ip("10.0.0.5") is True
    assert is_private_or_restricted_ip("169.254.169.254") is True  # Cloud metadata
    assert is_private_or_restricted_ip("8.8.8.8") is False


def test_url_analyzer_ssrf_detection():
    url = "http://169.254.169.254/latest/meta-data/"
    res = url_analyzer.analyze(url)
    assert res["deterministic_score"] >= 85
    assert res["safe_res"]["is_private_ssrf"] is True
    assert res["primary_threat"] == ThreatType.MALICIOUS_URL


def test_url_analyzer_userinfo_obfuscation():
    url = "https://paypal.com@attacker-site.com/login"
    res = url_analyzer.analyze(url)
    assert res["safe_res"]["has_userinfo"] is True
    assert res["deterministic_score"] >= 60
    assert any("userinfo" in ind.name.lower() for ind in res["indicators"])


def test_url_analyzer_lookalike_domain():
    url = "http://paypa1.com/verify-account"
    res = url_analyzer.analyze(url)
    assert res["safe_res"]["homograph_check"]["is_lookalike"] is True
    assert res["deterministic_score"] >= 60


def test_url_analyzer_open_redirect():
    url = "https://safe-domain.com/login?redirect=http://evil-tracker.buzz/download"
    res = url_analyzer.analyze(url)
    assert len(res["safe_res"]["open_redirect_params"]) > 0
    assert res["deterministic_score"] >= 30


def test_url_analyzer_benign_url():
    url = "https://www.google.com/search?q=cybersecurity"
    res = url_analyzer.analyze(url)
    assert res["deterministic_score"] < 25
    assert res["primary_threat"] == ThreatType.BENIGN
