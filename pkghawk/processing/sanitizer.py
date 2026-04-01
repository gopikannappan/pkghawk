"""Sanitize event fields to reduce prompt injection risk.

Event summaries flow from upstream sources (OSV, GitHub, Grok) directly into
MCP tool responses that AI agents consume. A malicious advisory could embed
instruction-like text to manipulate agent behavior. This module strips or
neutralizes such patterns.
"""

from __future__ import annotations

import re

# Patterns that look like prompt injection attempts in advisory text
_INJECTION_PATTERNS = [
    # Direct instructions
    re.compile(r"(?i)\b(ignore|override|disregard)\b.{0,30}\b(previous|prior|above|earlier|security|warning|alert)", re.DOTALL),
    # Commands to install/use something
    re.compile(r"(?i)\b(install|upgrade to|switch to|use)\b.{0,20}\b(immediately|now|instead|urgently)\b", re.DOTALL),
    # System prompt manipulation
    re.compile(r"(?i)(system prompt|you are|act as|pretend|role.?play|new instructions)", re.DOTALL),
    # Markdown/formatting injection to break agent parsing
    re.compile(r"```\s*(system|assistant|user)\b", re.DOTALL),
    # IMPORTANT/NOTE directives aimed at the agent
    re.compile(r"(?i)^(IMPORTANT|NOTE|INSTRUCTION|DIRECTIVE|OVERRIDE)\s*:", re.MULTILINE),
]

# Replacement marker so we don't silently swallow — the agent sees it was sanitized
_REDACTED = "[content sanitized by pkghawk]"


def sanitize_summary(text: str) -> str:
    """Remove prompt-injection-like patterns from event summaries."""
    if not text:
        return text

    result = text
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(result):
            # Replace the matched portion, not the whole string
            result = pattern.sub(_REDACTED, result)

    # Truncate to 500 chars (defense in depth against context stuffing)
    return result[:500]


def sanitize_event_dict(event: dict) -> dict:
    """Sanitize all free-text fields in a serialized event."""
    if "summary" in event:
        event["summary"] = sanitize_summary(event["summary"])
    return event