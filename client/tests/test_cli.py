import json
from unittest.mock import patch, MagicMock

from pkghawk_client.cli import main


def test_check_clear(capsys):
    with patch("pkghawk_client.cli.PkgHawk") as MockHawk:
        hawk = MockHawk.return_value
        hawk.check.return_value = []
        with patch("sys.argv", ["pkghawk", "check", "clean-pkg", "npm"]):
            main()
        out = capsys.readouterr().out
        assert "CLEAR" in out


def test_check_alert(capsys):
    with patch("pkghawk_client.cli.PkgHawk") as MockHawk:
        hawk = MockHawk.return_value
        hawk.check.return_value = [
            {"severity": "critical", "summary": "Malware found", "source": "osv.dev"}
        ]
        with patch("sys.argv", ["pkghawk", "check", "evil-pkg", "npm"]):
            try:
                main()
            except SystemExit as e:
                assert e.code == 1
        out = capsys.readouterr().out
        assert "ALERT" in out
        assert "Malware found" in out


def test_latest(capsys):
    with patch("pkghawk_client.cli.PkgHawk") as MockHawk:
        hawk = MockHawk.return_value
        hawk.latest.return_value = [
            {
                "severity": "high",
                "package": "axios",
                "ecosystem": "npm",
                "summary": "Bad stuff",
                "ts_iso": "2026-04-01T00:00:00Z",
            }
        ]
        with patch("sys.argv", ["pkghawk", "latest", "-n", "5"]):
            main()
        out = capsys.readouterr().out
        assert "axios" in out


def test_health(capsys):
    with patch("pkghawk_client.cli.PkgHawk") as MockHawk:
        hawk = MockHawk.return_value
        hawk.health.return_value = {
            "status": "ok",
            "sources": {"osv.dev": {"status": "ok"}},
        }
        with patch("sys.argv", ["pkghawk", "health"]):
            main()
        out = capsys.readouterr().out
        assert "ok" in out


def test_stats(capsys):
    with patch("pkghawk_client.cli.PkgHawk") as MockHawk:
        hawk = MockHawk.return_value
        hawk.stats.return_value = {
            "events_24h": 42,
            "sources_active": 3,
            "last_event": "2026-04-01T00:00:00Z",
        }
        with patch("sys.argv", ["pkghawk", "stats"]):
            main()
        out = capsys.readouterr().out
        assert "42" in out
