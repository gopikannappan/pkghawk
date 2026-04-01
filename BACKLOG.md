# pkghawk — Security Backlog

## Input validation on query params
Add enum validation for `ecosystem`, `severity`, `type`, `confidence` query parameters. Currently they're used in set-membership checks (no injection risk), but should reject invalid values with 400 instead of silently filtering nothing.

## Redis authentication
Redis is Docker-internal only (not exposed to host), safe for now. Add `requirepass` in redis.conf when scaling to multiple nodes or if Redis is moved to a separate host.

## MCP endpoint authentication
MCP tools are public (by design for a public feed). When `pkghawk_subscribe` (webhooks) ships in Phase 3, add HMAC token auth to prevent abuse.

## XSS in status page
`status/index.html` renders event data via innerHTML. A malicious advisory summary containing script tags could execute. Escape output with `textContent` or a sanitizer before rendering.

## Nginx hardening
- Add `server_tokens off` to hide Nginx version
- Add security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`
