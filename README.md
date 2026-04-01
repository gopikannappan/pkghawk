# pkghawk

Real-time package threat feed for AI agents.

A free, open-source service that aggregates supply chain attack signals across npm, PyPI, and Go — normalized into a single schema, consumable via SSE, WebSocket, REST, and MCP.

## Why

Supply chain attacks are accelerating and AI coding agents make it worse — they suggest and install packages at speed without auditing changelogs or maintainer history. The current tooling response (CVE databases, Dependabot) lags by hours to days.

pkghawk fills the gap: a **real-time, machine-readable feed** that an AI agent can subscribe to and act on before installing a compromised package.

## Quick Start

```bash
git clone https://github.com/gopikannappan/pkghawk.git
cd pkghawk
cp .env.example .env
docker compose up
```

Feed is live at `http://localhost:8000/feed`. Status page at `http://localhost:8000/`.

## API

### SSE Feed (primary — for agents)

```bash
curl -N https://pkghawk.dev/feed
curl -N https://pkghawk.dev/feed?ecosystem=npm&severity=critical
```

### WebSocket

```
wscat -c wss://pkghawk.dev/ws?ecosystem=npm
```

### REST

```bash
# Latest events
curl https://pkghawk.dev/latest?n=20&ecosystem=npm

# Health check
curl https://pkghawk.dev/health

# Stats
curl https://pkghawk.dev/stats
```

### Filters (all endpoints)

| Parameter    | Values                                              |
|-------------|-----------------------------------------------------|
| `ecosystem` | `npm`, `pypi`, `go`, `maven`, `cargo`, `rubygems`, `nuget` |
| `severity`  | `critical`, `high`, `medium`, `low`                 |
| `type`      | `malicious`, `vuln`, `hijack`, `typosquat`, `suspicious` |
| `confidence`| `critical`, `high`, `medium`, `low`                 |
| `since`     | Unix timestamp                                       |
| `n`         | Integer, max 500                                     |

## MCP Server — AI Agent Integration

pkghawk exposes an MCP server so AI coding agents can check packages natively.

### Tools

| Tool | Description |
|------|-------------|
| `pkghawk_check_package(package, ecosystem, version?)` | Check if a package has active alerts. **Call before installing.** |
| `pkghawk_latest(ecosystem?, n?, severity?)` | Get recent threat events. Use at session start for context. |
| `pkghawk_stats()` | Feed health and 24h event counts. |

### Configure Claude Code

Add to `~/.claude/mcp_config.json`:

```json
{
  "mcpServers": {
    "pkghawk": {
      "url": "https://pkghawk.dev/mcp/"
    }
  }
}
```

### What happens

```
Developer: "Add axios to my project"

Agent calls: pkghawk_check_package("axios", "npm")
Response:    ALERT — Malware in axios 1.14.1 (maintainer hijacked, RAT dropper)

Agent:       "axios 1.14.1 was compromised. Use 1.13.1 instead."
```

No human watches a dashboard. The agent watches the feed.

## Event Schema

```json
{
  "id": "ph-20260331-a3f9c821",
  "type": "malicious",
  "ecosystem": "npm",
  "package": "axios",
  "affected_versions": ["= 1.14.1"],
  "safe_version": "1.13.1",
  "severity": "critical",
  "confidence": "high",
  "source": "github-advisory",
  "sources_confirmed": ["github-advisory", "osv.dev"],
  "summary": "Maintainer account hijacked. RAT dropper in setup.js.",
  "ref_urls": ["https://github.com/advisories/GHSA-xxxx"],
  "cve_id": null,
  "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
  "ts": 1743400000,
  "ts_iso": "2026-03-31T10:00:00Z",
  "first_seen": 1743399600,
  "pkghawk_version": "1"
}
```

## Signal Sources

| Source | Type | Latency | Cost |
|--------|------|---------|------|
| [OSV.dev](https://osv.dev) | CVEs + malware across all ecosystems | ~2 min | Free |
| [GitHub Advisory DB](https://github.com/advisories) | Malware advisories | ~5 min | Free |
| [PyPI RSS](https://pypi.org/rss/packages.xml) | Typosquat detection on new packages | ~2 min | Free |
| [Socket.dev blog](https://socket.dev/blog) | Supply chain attack writeups | Hours | Free |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Actively exploited vulns | Daily | Free |
| Grok / X | Community intelligence via live search | ~15 min | ~$5-8/mo |

Events from multiple sources are deduplicated and confidence-scored. A signal confirmed by 2+ sources gets `confidence: high`.

## Architecture

```
INGEST              PROCESS                    SERVE
─────────────       ─────────────────          ─────────────
OSV.dev    ──┐      Normalizer                 SSE /feed
GitHub Adv ──┤      ↓                          WebSocket /ws
PyPI RSS   ──┼───→  Deduplicator (Redis SET)   REST /latest
Socket.dev ──┤      ↓                          MCP /mcp
CISA KEV   ──┤      Confidence Scorer
Grok/X     ──┘      ↓
                     Redis Pub/Sub ──────────→  Subscribers
```

| Component | Technology |
|-----------|-----------|
| API server | FastAPI (Python) |
| Message bus | Redis pub/sub |
| Polling | APScheduler (in-process) |
| Deduplication | Redis SET + 24h TTL |
| Persistence | Redis sorted set (last 10k events) |
| MCP server | FastMCP (mounted at /mcp) |

## Self-Hosting

```bash
git clone https://github.com/gopikannappan/pkghawk.git
cd pkghawk
cp .env.example .env
# Optional: add GITHUB_TOKEN (higher rate limits), XAI_API_KEY (Grok/X poller)
docker compose up -d
```

No API keys required for the core feed. 4 of 6 sources work without any keys.

## Client Examples

### Python

```python
import httpx, json

with httpx.stream("GET", "https://pkghawk.dev/feed?ecosystem=pypi") as r:
    for line in r.iter_lines():
        if line.startswith("data:"):
            event = json.loads(line[5:])
            print(f"[{event['severity']}] {event['package']}: {event['summary']}")
```

### Node.js

```javascript
const es = new EventSource("https://pkghawk.dev/feed?ecosystem=npm");
es.onmessage = (e) => {
  const event = JSON.parse(e.data);
  console.log(`[${event.severity}] ${event.package}: ${event.summary}`);
};
```

### CI — Block compromised packages

```bash
RESULT=$(curl -s "https://pkghawk.dev/latest?ecosystem=npm" | \
  jq --arg pkg "$PACKAGE" '[.[] | select(.package == $pkg and .severity == "critical")]')

if [ "$(echo $RESULT | jq length)" -gt "0" ]; then
  echo "BLOCKED: $PACKAGE has active critical alerts"
  exit 1
fi
```

## License

MIT

## Contributing

Issues and PRs welcome. If you discover a supply chain attack, you can submit a signal via `POST /report` (coming soon) or open an issue.
