import pytest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create test client with mocked Redis."""
    with patch("pkghawk.redis_client.get_redis", new_callable=AsyncMock), \
         patch("pkghawk.main.get_redis", new_callable=AsyncMock), \
         patch("pkghawk.main.poll_osv", new_callable=AsyncMock), \
         patch("pkghawk.main.poll_github_advisory", new_callable=AsyncMock), \
         patch("pkghawk.main.poll_pypi_new_packages", new_callable=AsyncMock), \
         patch("pkghawk.main.poll_socket_blog", new_callable=AsyncMock), \
         patch("pkghawk.main.poll_cisa_kev", new_callable=AsyncMock), \
         patch("pkghawk.main.poll_grok", new_callable=AsyncMock):
        from pkghawk.main import app
        yield TestClient(app)


def test_health(client):
    with patch("pkghawk.main.get_sources_health", new_callable=AsyncMock) as mock:
        mock.return_value = {"osv.dev": {"status": "ok", "last_check": 1000}}
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"


def test_stats(client):
    with patch("pkghawk.main.get_event_count_24h", new_callable=AsyncMock) as mock_count, \
         patch("pkghawk.main.get_sources_health", new_callable=AsyncMock) as mock_sources, \
         patch("pkghawk.main.get_latest_events", new_callable=AsyncMock) as mock_events:
        mock_count.return_value = 42
        mock_sources.return_value = {"osv.dev": {"status": "ok"}}
        mock_events.return_value = []
        resp = client.get("/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["events_24h"] == 42
        assert data["sources_active"] == 1


def test_latest(client):
    with patch("pkghawk.main.get_latest_events", new_callable=AsyncMock) as mock:
        mock.return_value = [{"id": "ph-test", "package": "test"}]
        resp = client.get("/latest?n=10")
        assert resp.status_code == 200
        assert len(resp.json()) == 1


def test_latest_invalid_ecosystem(client):
    resp = client.get("/latest?ecosystem=invalid")
    assert resp.status_code == 400
    assert "Invalid ecosystem" in resp.json()["detail"]


def test_latest_invalid_severity(client):
    resp = client.get("/latest?severity=extreme")
    assert resp.status_code == 400
    assert "Invalid severity" in resp.json()["detail"]


def test_latest_invalid_type(client):
    resp = client.get("/latest?type=fake")
    assert resp.status_code == 400


def test_latest_invalid_confidence(client):
    resp = client.get("/latest?confidence=maybe")
    assert resp.status_code == 400


def test_latest_valid_filters(client):
    with patch("pkghawk.main.get_latest_events", new_callable=AsyncMock) as mock:
        mock.return_value = []
        resp = client.get("/latest?ecosystem=npm,pypi&severity=critical&type=malicious&confidence=high")
        assert resp.status_code == 200


def test_status_page(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "pkghawk" in resp.text.lower()
