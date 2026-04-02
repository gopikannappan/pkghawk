import json

import httpx
import pytest
import respx

from pkghawk_client.client import PkgHawk

BASE = "https://pkghawk.dev"


@respx.mock
def test_check_clean():
    respx.get(f"{BASE}/latest").mock(return_value=httpx.Response(200, json=[]))
    hawk = PkgHawk()
    result = hawk.check("clean-pkg", "npm")
    assert result == []


@respx.mock
def test_check_alert():
    events = [
        {"package": "axios", "ecosystem": "npm", "severity": "critical", "summary": "Malware"},
        {"package": "other", "ecosystem": "npm", "severity": "low", "summary": "Bug"},
    ]
    respx.get(f"{BASE}/latest").mock(return_value=httpx.Response(200, json=events))
    hawk = PkgHawk()
    result = hawk.check("axios", "npm")
    assert len(result) == 1
    assert result[0]["package"] == "axios"


@respx.mock
def test_check_case_insensitive():
    events = [{"package": "Axios", "ecosystem": "npm", "severity": "high", "summary": "test"}]
    respx.get(f"{BASE}/latest").mock(return_value=httpx.Response(200, json=events))
    hawk = PkgHawk()
    result = hawk.check("axios", "npm")
    assert len(result) == 1


@respx.mock
def test_latest():
    events = [{"id": "1"}, {"id": "2"}]
    respx.get(f"{BASE}/latest").mock(return_value=httpx.Response(200, json=events))
    hawk = PkgHawk()
    result = hawk.latest(n=10, ecosystem="npm")
    assert len(result) == 2


@respx.mock
def test_health():
    data = {"status": "ok", "sources": {"osv.dev": {"status": "ok"}}}
    respx.get(f"{BASE}/health").mock(return_value=httpx.Response(200, json=data))
    hawk = PkgHawk()
    result = hawk.health()
    assert result["status"] == "ok"


@respx.mock
def test_stats():
    data = {"events_24h": 42, "sources_active": 3}
    respx.get(f"{BASE}/stats").mock(return_value=httpx.Response(200, json=data))
    hawk = PkgHawk()
    result = hawk.stats()
    assert result["events_24h"] == 42


@respx.mock
def test_custom_base_url():
    respx.get("http://localhost:8000/latest").mock(
        return_value=httpx.Response(200, json=[])
    )
    hawk = PkgHawk(base_url="http://localhost:8000")
    result = hawk.latest()
    assert result == []


@respx.mock
def test_check_http_error():
    respx.get(f"{BASE}/latest").mock(return_value=httpx.Response(500))
    hawk = PkgHawk()
    with pytest.raises(httpx.HTTPStatusError):
        hawk.check("pkg", "npm")
