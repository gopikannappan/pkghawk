"""CLI for pkghawk — check packages and watch the feed from your terminal."""

from __future__ import annotations

import argparse
import json
import sys

from pkghawk_client.client import PkgHawk


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="pkghawk",
        description="Real-time package threat feed client",
    )
    parser.add_argument(
        "--url", default="https://pkghawk.dev", help="pkghawk server URL"
    )
    sub = parser.add_subparsers(dest="command")

    # check
    check_p = sub.add_parser("check", help="Check a package for active alerts")
    check_p.add_argument("package", help="Package name (e.g. axios)")
    check_p.add_argument("ecosystem", help="Ecosystem (npm, pypi, go, etc.)")
    check_p.add_argument("--version", help="Specific version to check")

    # latest
    latest_p = sub.add_parser("latest", help="Show latest threat events")
    latest_p.add_argument("-n", type=int, default=10, help="Number of events")
    latest_p.add_argument("--ecosystem", help="Filter by ecosystem")
    latest_p.add_argument("--severity", help="Filter by severity")
    latest_p.add_argument("--type", help="Filter by event type")
    latest_p.add_argument("--json", action="store_true", dest="as_json", help="Output raw JSON")

    # watch
    watch_p = sub.add_parser("watch", help="Watch the live feed")
    watch_p.add_argument("--ecosystem", help="Filter by ecosystem")
    watch_p.add_argument("--severity", help="Filter by severity")

    # health
    sub.add_parser("health", help="Check feed health")

    # stats
    sub.add_parser("stats", help="Show feed statistics")

    args = parser.parse_args()
    hawk = PkgHawk(base_url=args.url)

    if args.command == "check":
        _cmd_check(hawk, args)
    elif args.command == "latest":
        _cmd_latest(hawk, args)
    elif args.command == "watch":
        _cmd_watch(hawk, args)
    elif args.command == "health":
        _cmd_health(hawk)
    elif args.command == "stats":
        _cmd_stats(hawk)
    else:
        parser.print_help()


def _cmd_check(hawk: PkgHawk, args: argparse.Namespace) -> None:
    alerts = hawk.check(args.package, args.ecosystem, args.version)
    if not alerts:
        print(f"CLEAR: {args.package} ({args.ecosystem}) — no active alerts")
        return
    print(f"ALERT: {len(alerts)} active alert(s) for {args.package} ({args.ecosystem})")
    for a in alerts:
        sev = a.get("severity", "unknown").upper()
        summary = a.get("summary", "")
        source = a.get("source", "")
        print(f"  [{sev}] {summary} (via {source})")
    sys.exit(1)


def _cmd_latest(hawk: PkgHawk, args: argparse.Namespace) -> None:
    events = hawk.latest(
        n=args.n,
        ecosystem=args.ecosystem,
        severity=args.severity,
        event_type=getattr(args, "type", None),
    )
    if args.as_json:
        print(json.dumps(events, indent=2))
        return
    if not events:
        print("No events")
        return
    for e in events:
        sev = e.get("severity", "?").upper()
        pkg = e.get("package", "?")
        eco = e.get("ecosystem", "?")
        summary = e.get("summary", "")[:80]
        ts = e.get("ts_iso", "")
        print(f"[{sev:8s}] {eco}/{pkg} — {summary} ({ts})")


def _cmd_watch(hawk: PkgHawk, args: argparse.Namespace) -> None:
    print(f"Watching pkghawk feed... (Ctrl+C to stop)")

    def on_event(e: dict) -> None:
        sev = e.get("severity", "?").upper()
        pkg = e.get("package", "?")
        eco = e.get("ecosystem", "?")
        summary = e.get("summary", "")[:80]
        print(f"[{sev}] {eco}/{pkg} — {summary}")

    try:
        hawk.subscribe(on_event, ecosystem=args.ecosystem, severity=args.severity)
    except KeyboardInterrupt:
        print("\nStopped")


def _cmd_health(hawk: PkgHawk) -> None:
    data = hawk.health()
    status = data.get("status", "unknown")
    print(f"Feed: {status}")
    for name, info in data.get("sources", {}).items():
        s = info.get("status", "unknown")
        print(f"  {name}: {s}")


def _cmd_stats(hawk: PkgHawk) -> None:
    data = hawk.stats()
    print(f"Events (24h): {data.get('events_24h', 0)}")
    print(f"Sources active: {data.get('sources_active', 0)}")
    print(f"Last event: {data.get('last_event', 'none')}")


if __name__ == "__main__":
    main()
