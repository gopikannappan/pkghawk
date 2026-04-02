"""Core client for pkghawk API."""

from __future__ import annotations

from typing import Any, Callable, Iterator

import httpx

DEFAULT_BASE_URL = "https://pkghawk.dev"


class PkgHawk:
    """Client for the pkghawk real-time package threat feed.

    Usage:
        from pkghawk_client import PkgHawk

        hawk = PkgHawk()
        alerts = hawk.check("axios", "npm")
        if alerts:
            print(f"ALERT: {alerts[0]['summary']}")
    """

    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout: float = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def check(
        self,
        package: str,
        ecosystem: str,
        version: str | None = None,
    ) -> list[dict[str, Any]]:
        """Check if a package has active security alerts.

        Returns a list of alert events, empty if clean.
        """
        params: dict[str, str] = {"ecosystem": ecosystem}
        if version:
            params["version"] = version
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(f"{self.base_url}/latest", params={"n": 500, **params})
            resp.raise_for_status()
            events = resp.json()
        return [e for e in events if e.get("package", "").lower() == package.lower()]

    def latest(
        self,
        n: int = 20,
        ecosystem: str | None = None,
        severity: str | None = None,
        event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get the latest threat events."""
        params: dict[str, Any] = {"n": n}
        if ecosystem:
            params["ecosystem"] = ecosystem
        if severity:
            params["severity"] = severity
        if event_type:
            params["type"] = event_type
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(f"{self.base_url}/latest", params=params)
            resp.raise_for_status()
            return resp.json()

    def subscribe(
        self,
        callback: Callable[[dict[str, Any]], None],
        ecosystem: str | None = None,
        severity: str | None = None,
    ) -> None:
        """Subscribe to the SSE feed. Blocks and calls callback for each event.

        Usage:
            def on_alert(event):
                print(f"[{event['severity']}] {event['package']}: {event['summary']}")

            hawk = PkgHawk()
            hawk.subscribe(on_alert, ecosystem="npm", severity="critical")
        """
        params: dict[str, str] = {}
        if ecosystem:
            params["ecosystem"] = ecosystem
        if severity:
            params["severity"] = severity

        with httpx.Client(timeout=None) as client:
            with client.stream("GET", f"{self.base_url}/feed", params=params) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if line.startswith("data:"):
                        import json

                        event = json.loads(line[5:])
                        callback(event)

    def health(self) -> dict[str, Any]:
        """Get feed health status."""
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(f"{self.base_url}/health")
            resp.raise_for_status()
            return resp.json()

    def stats(self) -> dict[str, Any]:
        """Get feed statistics."""
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(f"{self.base_url}/stats")
            resp.raise_for_status()
            return resp.json()


# --- Module-level convenience functions ---

_default = PkgHawk()


def check_package(
    package: str, ecosystem: str, version: str | None = None
) -> list[dict[str, Any]]:
    """Check if a package has active security alerts."""
    return _default.check(package, ecosystem, version)


def latest(
    n: int = 20,
    ecosystem: str | None = None,
    severity: str | None = None,
) -> list[dict[str, Any]]:
    """Get the latest threat events."""
    return _default.latest(n=n, ecosystem=ecosystem, severity=severity)


def subscribe(
    callback: Callable[[dict[str, Any]], None],
    ecosystem: str | None = None,
    severity: str | None = None,
) -> None:
    """Subscribe to the SSE feed."""
    _default.subscribe(callback, ecosystem=ecosystem, severity=severity)
