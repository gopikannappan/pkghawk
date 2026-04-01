# pkghawk
## Real-Time Package Threat Feed for AI Agents

**Domain:** `pkghawk.dev` | **GitHub:** `github.com/yourusername/pkghawk`

> A community-run, free, open-source WebSocket/SSE feed aggregating supply chain attack signals across npm, PyPI, and Go — normalized into a single schema, consumable by AI coding agents, CI pipelines, and developers.

---

## Table of Contents

1. [The Problem](#1-the-problem)
2. [What pkghawk Is](#2-what-pkghawk-is)
3. [What pkghawk Is Not](#3-what-pkghawk-is-not)
4. [The Gap in the Current Landscape](#4-the-gap-in-the-current-landscape)
5. [Signal Sources](#5-signal-sources)
6. [System Architecture](#6-system-architecture)
7. [Event Schema](#7-event-schema)
8. [API Interfaces](#8-api-interfaces)
9. [Grok / X Integration](#9-grok--x-integration)
10. [MCP Server — Agent Integration](#10-mcp-server--agent-integration)
11. [Build Plan](#11-build-plan)
12. [Infrastructure & Cost](#12-infrastructure--cost)
    - [Hetzner vs Fly.io](#hetzner-vs-flyio)
    - [Global Users & Cloudflare](#global-users--cloudflare)
    - [Scaling Architecture](#scaling-architecture)
13. [Open Source Strategy](#13-open-source-strategy)
14. [Community & Growth](#14-community--growth)
15. [Name & Domain](#15-name--domain)
16. [Risks & Mitigations](#16-risks--mitigations)

---

## 1. The Problem

Supply chain attacks on open source packages are accelerating and the attack window is shrinking.

- **March 2026:** axios (100M weekly npm downloads) — maintainer account hijacked, RAT dropper embedded in `setup.js`, self-destructs post-execution to avoid detection.
- **March 2026:** Telnyx Python SDK on PyPI — multi-stage credential-stealing malware delivered via a compromised version.
- **2025:** SHA1-Hulud npm malware campaign — 69% increase in npm malware advisories vs 2024.

The pattern is consistent: a package gets compromised, lives on the registry for hours to days, and gets pulled into thousands of projects before removal. The axios `plain-crypto-js@4.2.1` dependency existed for less than 24 hours before the attack completed.

**AI-assisted coding makes this dramatically worse.** Coding agents like Claude Code, Cursor, and Codex suggest and install packages at speed. Developers accept suggestions without auditing changelogs, version diffs, or maintainer history. The attack surface grows with every agent-assisted `npm install`.

The current tooling response is too slow:

| Layer | Lag |
|---|---|
| NVD / CVE database | 3–7 days after disclosure |
| GitHub Advisory Database | Hours to days |
| Dependabot alerts | After CVE is published |
| Security researcher tweets | Minutes — but unstructured, no API |
| Socket.dev detection | Near real-time — but commercial, no public feed |

There is no free, machine-readable, real-time stream that an AI agent can subscribe to and act on.

---

## 2. What pkghawk Is

pkghawk is a **public utility feed** — a lightweight aggregation and normalization service that:

- Polls multiple free and commercial vulnerability and malware data sources continuously
- Enriches signals with community intelligence via Grok's live X search
- Normalizes everything into a single event schema
- Serves events over SSE (Server-Sent Events), WebSocket, and REST
- Wraps as an MCP server so AI coding agents get live alerts injected into context

It is **not a product**. It is infrastructure — like a DNS server or a public NTP pool. Free to use, free to self-host, open source.

---

## 3. What pkghawk Is Not

- **Not a vulnerability scanner** — it does not scan your codebase
- **Not a SaaS** — no accounts, no billing, no dashboards (a minimal status page only)
- **Not a CVE database** — it aggregates, not originates
- **Not a replacement for Snyk/Socket/Dependabot** — it is the raw feed those tools build on top of
- **Not a monitoring service** — it does not alert on your specific dependency tree

---

## 4. The Gap in the Current Landscape

### Existing tools and their limitations

| Tool | Coverage | Real-time? | Public API? | Agent-ready? | Cost |
|---|---|---|---|---|---|
| OSV.dev | CVEs, known vulns | Polling REST, ~2 min | Yes, free | Partial | Free |
| GitHub Advisory DB | CVEs + malware | RSS, ~5 min lag | Yes via GitHub API | Partial | Free |
| Socket.dev | Supply chain attacks | Near real-time | Commercial | No public feed | Paid |
| OpenCVE | CVEs | Webhook on new CVEs | Yes | No | Freemium |
| Dependabot | CVEs in your repo | After CVE published | No | No | Free (GitHub) |
| Snyk | CVEs + license | Near real-time | Commercial | Limited | Paid |
| Aikido Safe Chain | Malware | At install time | Open source tool | No | Free |
| NVD / NIST | CVEs | 3–7 day lag | Yes | No | Free |

### The gap

No tool provides all four simultaneously:

1. **Supply chain attack signals** (not just CVEs — malicious packages, hijacked maintainers, typosquats)
2. **Real-time** (minutes, not hours or days)
3. **Free public feed** (not commercial API)
4. **Agent-consumable interface** (SSE/WebSocket/MCP)

pkghawk fills this gap.

---

## 5. Signal Sources

### Tier 1 — Structured, Free, Reliable

#### OSV.dev (Google)
- REST API: `https://api.osv.dev/v1/query`
- Covers: npm, PyPI, Go, Maven, RubyGems, crates.io, NuGet, and more
- Query by ecosystem + modified timestamp to get delta updates
- Latency: ~2 min polling interval
- Cost: Free, no key required

```bash
# Example: get all npm advisories modified in last 5 minutes
POST https://api.osv.dev/v1/query
{
  "package": { "ecosystem": "npm" },
  "modified_since": "2026-03-31T10:00:00Z"
}
```

#### GitHub Advisory Database
- RSS feed: `https://github.com/advisories.atom?type=malware`
- Also queryable via GitHub REST API (`/advisories` endpoint)
- Covers malware-tagged advisories explicitly — the most relevant signal
- Latency: ~5 min
- Cost: Free, GitHub token recommended (higher rate limits)

#### PyPI RSS
- New package releases: `https://pypi.org/rss/updates.xml`
- New packages: `https://pypi.org/rss/packages.xml`
- Used for anomaly detection — new packages referencing popular names
- Latency: ~2 min
- Cost: Free

### Tier 2 — Curated, Delayed, High Quality

#### Socket.dev Blog RSS
- URL: `https://socket.dev/blog/rss.xml`
- Socket publishes detailed writeups within hours of malware discovery
- Lower volume but high signal-to-noise
- Latency: Hours
- Cost: Free

#### CISA KEV (Known Exploited Vulnerabilities)
- JSON feed: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Updated when a CVE is actively being exploited in the wild
- High severity, low volume — every event matters
- Latency: Daily
- Cost: Free

### Tier 3 — Community Intelligence (Grok / X)

#### Grok API with Live X Search
- Model: `grok-3` with built-in X search capability
- Polls every 10–15 min for breaking community signals
- Catches events before they appear in any structured database
- Latency: ~15 min from post to Grok visibility
- Cost: ~$5–8/month at 10-min polling cadence

See [Section 9](#9-grok--x-integration) for full implementation details.

### Source Priority Matrix

When the same event appears in multiple sources, confidence scoring applies:

| Sources confirming | Confidence | Action |
|---|---|---|
| 1 source (Grok only) | Low | Queue, wait for corroboration |
| 1 source (OSV / GitHub) | Medium | Emit with `confidence: medium` |
| 2 sources | High | Emit with `confidence: high` |
| 3+ sources | Critical | Emit with `confidence: critical`, flag for immediate attention |

---

## 6. System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        INGEST LAYER                         │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ OSV.dev  │  │  GitHub  │  │  PyPI    │  │  Socket  │   │
│  │  poller  │  │  Advisory│  │  RSS     │  │  blog    │   │
│  │  2 min   │  │  RSS     │  │  2 min   │  │  RSS     │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │              │              │              │         │
│  ┌────┴──────────────┴──────────────┴──────────────┴─────┐  │
│  │                   Grok / X poller (10 min)            │  │
│  └──────────────────────────────┬────────────────────────┘  │
└─────────────────────────────────┼───────────────────────────┘
                                  │
┌─────────────────────────────────▼───────────────────────────┐
│                     PROCESSING LAYER                        │
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│  │  Normalizer │───▶│ Deduplicator│───▶│ Confidence      │  │
│  │  (schema)   │    │ (Redis SET) │    │ Scorer          │  │
│  └─────────────┘    └─────────────┘    └────────┬────────┘  │
│                                                  │           │
│                                         ┌────────▼────────┐  │
│                                         │  Redis Pub/Sub  │  │
│                                         │  channel:alerts │  │
│                                         └────────┬────────┘  │
└──────────────────────────────────────────────────┼───────────┘
                                                   │
┌──────────────────────────────────────────────────▼───────────┐
│                       SERVE LAYER                            │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  SSE         │  │  WebSocket   │  │  REST            │   │
│  │  /feed       │  │  /ws         │  │  /latest         │   │
│  │  (agents)    │  │  (browsers)  │  │  /health         │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │  MCP Server  /mcp  (AI agent native integration)     │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Component | Technology | Reason |
|---|---|---|
| API server | FastAPI (Python) | Async, native SSE support, lightweight |
| Message bus | Redis pub/sub | Zero config, fast, Fly.io managed available |
| Polling workers | APScheduler (in-process) | No Celery overhead for this scale |
| Deduplication | Redis SET with TTL | Prevents same event from 3 sources = 3 alerts |
| Persistence | Redis sorted set | Last 500 events, queryable by timestamp |
| MCP server | FastAPI + MCP Python SDK | Same process, separate router |
| Deployment | Fly.io | Free tier sufficient, global edge |

---

## 7. Event Schema

Every event emitted by pkghawk conforms to this schema:

```json
{
  "id": "dw-20260331-a3f9",
  "type": "malicious | vuln | typosquat | hijack | suspicious",
  "ecosystem": "npm | pypi | go | maven | cargo | rubygems | nuget",
  "package": "axios",
  "affected_versions": ["1.14.1", "0.30.4"],
  "safe_version": "1.13.1",
  "severity": "critical | high | medium | low | unknown",
  "confidence": "critical | high | medium | low",
  "source": "osv.dev | github-advisory | socket.dev | grok-x | cisa-kev | pypi-rss",
  "sources_confirmed": ["github-advisory", "socket.dev", "grok-x"],
  "summary": "Maintainer account hijacked. RAT dropper in setup.js contacts sfrclak.com:8000. Self-deletes post-execution.",
  "ref_urls": [
    "https://socket.dev/blog/axios-npm-package-compromised",
    "https://github.com/advisories/GHSA-xxxx"
  ],
  "cve_id": "CVE-2026-XXXXX",
  "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
  "ts": 1743400000,
  "ts_iso": "2026-03-31T10:00:00Z",
  "first_seen": 1743399600,
  "pkghawk_version": "1"
}
```

### Field Notes

- `type: malicious` — active malware embedded in a published version
- `type: hijack` — legitimate maintainer account compromised
- `type: typosquat` — package name designed to mimic a popular package
- `type: vuln` — known CVE, not necessarily malicious intent
- `type: suspicious` — Grok signal only, not yet confirmed by structured source
- `safe_version` — best known clean version, populated when determinable
- `confidence` — driven by number of confirming sources (see Section 5)
- `first_seen` — Unix timestamp when pkghawk first detected the signal

---

## 8. API Interfaces

### SSE — Primary Interface

```
GET https://pkghawk.dev/feed
GET https://pkghawk.dev/feed?ecosystem=npm
GET https://pkghawk.dev/feed?ecosystem=npm,pypi
GET https://pkghawk.dev/feed?severity=critical,high
GET https://pkghawk.dev/feed?type=malicious,hijack
```

**Response format:** Standard SSE stream, each event is a JSON-encoded pkghawk event.

```
data: {"id":"dw-20260331-a3f9","type":"malicious","ecosystem":"npm",...}

data: {"id":"dw-20260331-b821","type":"hijack","ecosystem":"pypi",...}
```

SSE is preferred for AI agent integration — works with any HTTP client, no special library required, auto-reconnects.

### WebSocket

```
WS wss://pkghawk.dev/ws
WS wss://pkghawk.dev/ws?ecosystem=npm&severity=critical
```

Identical events to SSE. Use for browser-based tooling or dashboards.

### REST — Catch-Up & Context Injection

```
GET /latest
GET /latest?n=50
GET /latest?n=20&ecosystem=npm
GET /latest?since=1743399600
GET /latest?type=malicious
```

Useful for agents that need context at session start: "what happened in the last 6 hours?"

```
GET /health          → {"status":"ok","sources":{"osv":"ok","github":"ok","grok":"ok"}}
GET /stats           → {"events_24h":42,"sources_active":5,"last_event":"2026-03-31T10:00:00Z"}
POST /report         → Submit a manual community report (Phase 3)
```

### Filters (All Endpoints)

| Parameter | Values | Example |
|---|---|---|
| `ecosystem` | npm, pypi, go, maven, cargo | `?ecosystem=npm,pypi` |
| `severity` | critical, high, medium, low | `?severity=critical` |
| `type` | malicious, vuln, hijack, typosquat, suspicious | `?type=malicious,hijack` |
| `confidence` | critical, high, medium, low | `?confidence=high,critical` |
| `since` | Unix timestamp | `?since=1743399600` |
| `n` | Integer, max 500 | `?n=50` |

---

## 9. Grok / X Integration

### Why Grok Instead of X API

The X API Developer tier costs $100+/month for meaningful search access. Grok-3 has live X search built into its inference API, costing approximately $5–8/month at 10-minute polling intervals. For a community good project, this is the only viable path.

### Implementation

```python
import openai  # xAI is OpenAI-compatible
import json

xai_client = openai.Client(
    api_key=XAI_API_KEY,
    base_url="https://api.x.ai/v1"
)

GROK_PROMPT = """
You are a security signal extractor monitoring X (Twitter) for package supply chain threats.

Search X for posts in the last 30 minutes mentioning any of:
- malicious npm package
- pypi malware
- compromised package maintainer
- supply chain attack
- npm hijack
- typosquatting npm OR pypi
- [package name] compromised

Extract concrete threat signals only. Ignore speculation, commentary, and retweets of old news.

Return ONLY a JSON array. Each item:
{
  "package": "package name or null if unclear",
  "ecosystem": "npm | pypi | go | other | unknown",
  "signal": "one sentence description of the threat",
  "url": "tweet URL if available",
  "confidence": "high | medium | low",
  "raw_excerpt": "brief quote from post"
}

Return [] if no concrete new threats found. No prose. No markdown. Raw JSON array only.
"""

async def poll_grok():
    response = xai_client.chat.completions.create(
        model="grok-3",
        messages=[{"role": "user", "content": GROK_PROMPT}],
        max_tokens=1000
    )
    
    raw = response.choices[0].message.content.strip()
    signals = json.loads(raw)  # safe: prompted for raw JSON
    
    for signal in signals:
        if signal.get("confidence") in ("high", "medium"):
            await publish_event(normalize_grok_signal(signal))
```

### Confidence Gate

Grok signals are emitted as `type: suspicious` with `confidence: low` unless:
- The same package appears in OSV.dev or GitHub Advisory within 60 minutes → upgraded to `confidence: high`
- Two or more independent X posts confirm the same package → upgraded to `confidence: medium`

This prevents noise from single unverified posts reaching agent feeds.

### Rate & Cost Estimate

| Parameter | Value |
|---|---|
| Poll interval | Every 10 minutes |
| Tokens per call (est.) | ~800 input + ~300 output |
| Calls per day | 144 |
| Daily token usage | ~158,400 |
| Monthly token usage | ~4.75M |
| Cost at $5/M tokens | ~$24/month worst case |
| Typical cost (most calls return `[]`) | ~$5–8/month |

---

## 10. MCP Server — Agent Integration

The MCP server is the primary value-add for AI coding agents. It wraps the pkghawk feed as a set of tools that any Claude Code, Cursor, or Codex agent can call natively.

### Tools Exposed

```
pkghawk_latest(ecosystem?, n?, severity?)
  → Returns last N events, optionally filtered
  → Use at agent session start for context

pkghawk_check_package(package, ecosystem, version?)
  → Check if a specific package/version has active alerts
  → Use before suggesting install

pkghawk_subscribe(callback_url)
  → Register a webhook for push notifications
  → For persistent agent processes

pkghawk_stats()
  → Feed health + 24h event counts
```

### Agent Usage Pattern

```
Developer: "Add axios to my project"

Agent calls: pkghawk_check_package("axios", "npm", "1.14.1")
Response: {
  "status": "ALERT",
  "events": [{
    "type": "malicious",
    "severity": "critical",
    "summary": "Maintainer hijacked. RAT dropper in 1.14.1 and 0.30.4.",
    "safe_version": "1.13.1"
  }]
}

Agent responds: "⚠️ axios 1.14.1 was compromised 3 hours ago via a maintainer hijack.
A RAT dropper was embedded in setup.js. Use 1.13.1 instead — confirmed clean."
```

No human watches a dashboard. The agent watches the feed.

### MCP Configuration (Claude Code)

```json
{
  "mcpServers": {
    "pkghawk": {
      "url": "https://pkghawk.dev/mcp",
      "description": "Real-time package supply chain threat feed"
    }
  }
}
```

---

## 11. Build Plan

### Phase 0 — Core Feed (Days 1–3)

**Goal:** A working SSE endpoint with two live sources.

- [ ] FastAPI project scaffold with SSE endpoint `/feed`
- [ ] Redis pub/sub integration (local + Fly.io managed Redis)
- [ ] OSV.dev poller — npm + PyPI, 2-min interval
- [ ] GitHub Advisory RSS poller — malware filter
- [ ] Normalizer — map both sources to pkghawk schema
- [ ] Deduplication via Redis SET + 24h TTL
- [ ] `/latest` REST endpoint — last 200 events in sorted set
- [ ] `/health` endpoint
- [ ] Fly.io deploy — single machine, shared CPU
- [ ] Domain setup — `pkghawk.dev`

**Deliverable:** Live SSE feed, two sources, publicly accessible.

---

### Phase 1 — Signal Expansion (Days 4–10)

**Goal:** All five sources live, Grok integrated, confidence scoring working.

- [ ] Grok poller — 10-min interval, JSON extraction prompt
- [ ] PyPI RSS poller — new package anomaly detection
- [ ] Socket.dev blog RSS parser
- [ ] CISA KEV feed poller
- [ ] Confidence scoring engine — multi-source corroboration logic
- [ ] WebSocket endpoint `/ws`
- [ ] Ecosystem and severity filters on all endpoints
- [ ] Rate limiting — 100 req/min per IP on REST
- [ ] Event persistence — extend to 7 days in Redis sorted set

**Deliverable:** Full multi-source feed with Grok, filtered endpoints, WebSocket.

---

### Phase 2 — Agent Layer (Days 11–17)

**Goal:** AI agents can use pkghawk natively without any custom integration.

- [ ] MCP server — `pkghawk_latest`, `pkghawk_check_package` tools
- [ ] MCP server deployed at `/mcp`
- [ ] `pkghawk_check_package` — real-time package/version lookup against active alerts
- [ ] Status page — single HTML file, no framework, shows last 20 events + source health
- [ ] README with MCP config snippets for Claude Code, Cursor, Codex
- [ ] GitHub repo — open source, MIT license

**Deliverable:** Working MCP server, status page, public GitHub repo.

---

### Phase 3 — Community (Ongoing)

**Goal:** Self-sustaining community contribution layer.

- [ ] `POST /report` — authenticated community submission endpoint
- [ ] Webhook support — teams pipe alerts to Slack, PagerDuty, Discord
- [ ] Telegram bot — subscribe to ecosystem-filtered alerts
- [ ] Contributor leaderboard — recognize researchers who submit early signals
- [ ] `?since=` parameter — agents can request events since last check
- [ ] npm package: `pkghawk-client` — one-line integration for Node projects
- [ ] pip package: `pkghawk` — same for Python

---

## 12. Infrastructure & Cost

### Hetzner vs Fly.io

**Hetzner is the right choice.** The stress profile of pkghawk — many long-lived SSE/WebSocket connections, low CPU per connection, Redis pub/sub fan-out — maps poorly to Fly.io's billing model and well to Hetzner's flat-rate servers.

Each asyncio SSE connection costs ~1–2KB RAM. 50,000 concurrent connections = ~100MB RAM on a single CX21. Fly.io bills by memory and would force an upsize rapidly at real traffic. Hetzner doesn't care.

| Factor | Fly.io | Hetzner |
|---|---|---|
| Starting cost | $0 free tier | €4.35/mo (CX21) |
| At 10k connections | ~$40–60/mo | €4.35/mo (same machine) |
| At 100k connections | ~$150–300/mo | €20–25/mo (LB + 3 nodes) |
| Egress costs | Yes, adds up | Free within EU |
| WebSocket support | Yes, memory-billed | Native |
| Frankfurt DC | Yes | Yes |
| Familiarity | Low | High (bitsCrunch runs here) |

---

### Phase 0 — Launch (~€6/mo)

Single CX21, Frankfurt. Handles ~20,000 concurrent connections comfortably.

```
┌─────────────────────────────┐
│  CX21  €4.35/mo             │
│  Frankfurt (FSN1)           │
│  ─────────────────────────  │
│  FastAPI (SSE + WS + REST)  │
│  Redis (local)              │
│  5x ingest pollers          │
│  Nginx (TLS termination)    │
└─────────────────────────────┘
+ pkghawk.dev domain ~€1/mo
```

---

### Phase 1 — Growing (~€15/mo)

Split Redis when memory pressure appears. App and Redis on separate nodes.

```
┌─────────────────┐     ┌──────────────────┐
│  CX21  €4.35/mo │────▶│  CX11  €3.29/mo  │
│  App + Nginx    │     │  Redis only       │
└─────────────────┘     └──────────────────┘
```

---

### Phase 2 — High Traffic (~€34/mo)

Hetzner Load Balancer natively supports WebSocket and SSE with sticky sessions. Add app nodes horizontally — each subscribes to the same Redis channel, zero coordination needed.

```
                    ┌──────────────────────────┐
                    │  Hetzner Load Balancer   │
                    │  €6/mo                   │
                    │  WebSocket + SSE aware   │
                    │  SSL termination         │
                    └────────┬─────────────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
  ┌───────▼──────┐  ┌────────▼─────┐  ┌────────▼─────┐
  │  CX21        │  │  CX21        │  │  CX21        │
  │  App node 1  │  │  App node 2  │  │  App node 3  │
  │  €4.35/mo    │  │  €4.35/mo    │  │  €4.35/mo    │
  └──────────────┘  └──────────────┘  └──────────────┘
                             │
                    ┌────────▼─────────┐
                    │  CX31            │
                    │  Redis           │
                    │  €7.27/mo        │
                    └──────────────────┘
```

**Fan-out design** — each app node subscribes to the same Redis pub/sub channel at startup:

```python
async def redis_listener():
    pubsub = redis.pubsub()
    await pubsub.subscribe("channel:alerts")
    async for message in pubsub.listen():
        if message["type"] == "message":
            await broadcast_to_local_subscribers(message["data"])
```

One ingest worker publishes → Redis fans out to all nodes → each node pushes to its connected subscribers. Horizontal scaling is additive with no code changes.

---

### Global Users & Cloudflare

**Short answer: not a problem for this use case.** pkghawk is a security alert feed, not a trading platform. A user in Singapore receiving an alert 200ms later than one in Frankfurt is irrelevant — the attack already happened minutes before ingest even caught it.

However, putting Cloudflare in front of Hetzner solves three things for free:

**What Cloudflare adds:**
- SSL termination at 300+ global edge locations (`.dev` domains require HTTPS — HSTS enforced)
- REST `/latest` responses cached globally — Hetzner only hit on cache miss
- DDoS protection for a public feed
- WebSocket and SSE pass through transparently

**Two settings to enable in Cloudflare dashboard:**
```
Network → WebSockets: ON
Speed  → HTTP/2: ON
```

Cloudflare does not terminate SSE/WS connections — it proxies them to your Hetzner server. A user in Tokyo connects to Cloudflare's Tokyo PoP, which tunnels back to Frankfurt. The handshake is fast; the alert latency is the Frankfurt round-trip (~180ms). Acceptable.

**DNS setup:**
```
A    pkghawk.dev        → <hetzner-ip>    proxied (orange cloud)
A    api.pkghawk.dev    → <hetzner-ip>    proxied
```

---

### Phase 3 — True Global Scale (~€9/mo extra, if ever needed)

Add a second Hetzner node in **Ashburn, Virginia** (CAX11, €3.49/mo). Both nodes subscribe to the same Redis via a Hetzner private network tunnel. Cloudflare GeoDNS routes US/LATAM users to Ashburn, everyone else to Frankfurt.

```
Frankfurt CX21 ──── Redis (primary) ◀── replication ──▶ Redis (replica)
                                                              │
                                                     Ashburn CX11
```

Total for genuine global coverage: **~€43/mo** at Phase 3. Not needed at launch.

---

### Monthly Cost Summary

| Phase | Infra | Grok API | Domain | Total |
|---|---|---|---|---|
| 0 — Launch | €4.35 | ~€6 | ~€1 | **~€11/mo** |
| 1 — Growing | €7.64 | ~€6 | ~€1 | **~€15/mo** |
| 2 — High traffic | €27.62 | ~€8 | ~€1 | **~€37/mo** |
| 3 — Global | €34.60 | ~€10 | ~€1 | **~€46/mo** |

---

## 13. Open Source Strategy

### License
MIT. Maximally permissive — anyone can fork, self-host, embed.

### Repository Structure

```
pkghawk/
├── README.md
├── pkghawk/
│   ├── main.py              # FastAPI app, SSE + WebSocket + REST
│   ├── mcp_server.py        # MCP tools
│   ├── schema.py            # Event schema (Pydantic)
│   ├── redis_client.py      # Pub/sub + sorted set helpers
│   ├── pollers/
│   │   ├── osv.py
│   │   ├── github_advisory.py
│   │   ├── pypi_rss.py
│   │   ├── socket_blog.py
│   │   ├── cisa_kev.py
│   │   └── grok.py
│   └── processing/
│       ├── normalizer.py
│       ├── deduplicator.py
│       └── confidence.py
├── status/
│   └── index.html           # Status page, no framework
├── docs/
│   ├── agent-integration.md
│   ├── self-hosting.md
│   └── schema.md
├── fly.toml
├── Dockerfile
└── pyproject.toml
```

### Self-Hosting

The entire stack runs in a single Docker container + Redis. One `docker-compose.yml` for local dev. One `fly deploy` for production. Documentation priority: self-hosting should be <10 min.

---

## 14. Community & Growth

### Distribution

- **Hacker News** — "Show HN: pkghawk — free SSE feed for package supply chain attacks, MCP-ready" — time a launch post after the next high-profile attack (they are frequent)
- **Security researcher community** — submit to TLDR Security, Risky Biz newsletter, tldrsec.com
- **AI coding community** — post in Claude Code Discord, Cursor subreddit, Aider GitHub
- **GitHub** — list in awesome-security, awesome-mcp-servers
- **bitsCrunch** — dogfood it. Use it in Claak's dependency CI. Real customer zero.

### Contribution Model

Community submits signals via `POST /report`:

```json
{
  "package": "faker-js",
  "ecosystem": "npm",
  "signal": "New version 9.1.0 contains obfuscated eval() targeting CI environments",
  "ref_url": "https://x.com/...",
  "reporter": "optional_handle"
}
```

Manual review queue (initially just you + Saravanan) before publishing. Builds a contributor reputation layer over time.

---

## 15. Name & Domain

**Chosen: `pkghawk.dev`**

- 7 characters + `.dev` — short, memorable
- "hawk" = fast, vigilant, predatory surveillance
- `pkg` = universal developer shorthand for package
- `.dev` TLD signals developer tooling, enforces HTTPS (HSTS)
- Confirmed clear of existing products and projects
- ~€10–12/year at Cloudflare Registrar or Porkbun

**Register at:** Cloudflare Registrar (at-cost, no markup, integrates with Cloudflare proxy setup) or Porkbun (~€10.98/year, cheapest for `.dev`).

**Ruled out:**
- `pkgwatch.dev` — taken (dependency health checker)
- `depradar.dev` — taken (existing product)
- `malwatch` — taken (OSS malware scanner)
- `chainwatch` — taken (GitHub project + game)
- Anything with "vuln" or "CVE" — positions as CVE tracker, undersells the supply chain angle

---

## 16. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| False positives damage trust | Medium | High | Confidence scoring gate; `suspicious` type clearly labelled; community correction mechanism |
| Grok prompt returns garbage JSON | Low | Low | `try/except` around parse; malformed responses dropped silently; logged |
| Source goes down (OSV, GitHub RSS) | Low | Medium | Per-source health tracking; `/health` shows degraded status; alert does not fire if only 1 source down |
| Redis fills up | Low | Medium | TTL on all keys; sorted set capped at 10,000 events; Fly.io monitoring |
| Legal challenge from Socket.dev (RSS scraping) | Very low | Medium | RSS is public; we cite source on every event; we are an aggregator, not a competitor |
| Spam via `POST /report` | Medium | Low | Rate limit + simple HMAC token for reporters; manual review queue in Phase 3 |
| xAI raises Grok API prices | Medium | Low | Grok is optional enrichment; feed degrades gracefully without it; budget cap in code |
| Project abandoned | Medium | High | MIT license + self-hosting docs ensure community can fork and continue |

---

## Appendix A — Quickstart (Self-Hosting)

```bash
git clone https://github.com/yourusername/pkghawk
cd pkghawk

# Set environment variables
cp .env.example .env
# Edit .env: add XAI_API_KEY, GITHUB_TOKEN, REDIS_URL

# Run locally
docker-compose up

# Test the feed
curl -N http://localhost:8000/feed

# Test REST
curl http://localhost:8000/latest?n=10
```

## Appendix B — Agent Integration Snippets

### Claude Code (MCP)
```json
// .claude/mcp_config.json
{
  "mcpServers": {
    "pkghawk": {
      "url": "https://pkghawk.dev/mcp"
    }
  }
}
```

### Python — Subscribe to feed
```python
import httpx

with httpx.stream("GET", "https://pkghawk.dev/feed?ecosystem=pypi&severity=critical") as r:
    for line in r.iter_lines():
        if line.startswith("data:"):
            event = json.loads(line[5:])
            print(f"[{event['severity'].upper()}] {event['package']} — {event['summary']}")
```

### Node.js — Subscribe to feed
```javascript
const EventSource = require("eventsource");
const es = new EventSource("https://pkghawk.dev/feed?ecosystem=npm");

es.onmessage = (e) => {
  const event = JSON.parse(e.data);
  console.log(`[${event.severity}] ${event.package}: ${event.summary}`);
};
```

### Check package before install (CI)
```bash
# In your CI pipeline, before npm install:
RESULT=$(curl -s "https://pkghawk.dev/latest?ecosystem=npm" | \
  jq --arg pkg "axios" '[.[] | select(.package == $pkg and .severity == "critical")]')

if [ "$(echo $RESULT | jq length)" -gt "0" ]; then
  echo "⚠️ BLOCKED: $pkg has active critical security alerts"
  echo $RESULT | jq '.[].summary'
  exit 1
fi
```

---

*pkghawk — community infrastructure for the AI coding era.*
