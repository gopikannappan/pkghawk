# pkghawk — Backlog

## Done
- ~~Input validation on query params~~
- ~~Redis authentication~~
- ~~XSS in status page~~
- ~~Nginx hardening (server_tokens, security headers)~~
- ~~Rate limiting~~
- ~~Prompt injection sanitizer~~
- ~~Event volume cap~~
- ~~WebSocket idle timeout~~
- ~~Dependency lockfile~~

## Features

### POST /report endpoint
Community-submitted threat signals with HMAC token auth. Manual review queue before publishing. Phase 3 priority.

### Cross-source corroboration
When the same package appears from multiple sources within 60 minutes, automatically upgrade confidence level. Currently each source emits independently.

### Grok/X poller activation
Code exists, just needs XAI_API_KEY configured. Catches threats ~15min before structured sources.

### Event expiry cleanup
Redis sorted set grows unbounded. Add a periodic task to trim events older than 7 days.

### Webhook delivery (pkghawk_subscribe)
Allow persistent agents to register callback URLs for push notifications. Needs retry logic, URL validation, and auth.

### Telegram/Discord bot
Subscribe to ecosystem-filtered alerts via chat bot.

### npm client package (pkghawk-client)
One-liner integration for Node.js projects, similar to the Python client.

## Launch

### Show HN post
"Show HN: pkghawk — free SSE feed for package supply chain attacks, MCP-ready". Time after the next high-profile attack.

### awesome-mcp-servers listing
Submit PR to awesome-mcp-servers repo.

### Community distribution
Post in Claude Code Discord, Cursor subreddit, Aider GitHub, TLDR Security, Risky Biz newsletter.
