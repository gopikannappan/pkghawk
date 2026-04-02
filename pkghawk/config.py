import os


REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
XAI_API_KEY = os.getenv("XAI_API_KEY", "")
LOG_LEVEL = os.getenv("LOG_LEVEL", "info")

# Polling intervals (seconds)
OSV_POLL_INTERVAL = 120
GITHUB_POLL_INTERVAL = 300
PYPI_POLL_INTERVAL = 120
GROK_POLL_INTERVAL = 2100  # 35min — fits ~$10/mo budget with grok-3

# Redis keys
REDIS_CHANNEL = "channel:alerts"
REDIS_EVENTS_KEY = "events:sorted"
REDIS_DEDUP_PREFIX = "dedup:"
REDIS_SOURCE_HEALTH_PREFIX = "source:health:"

# Event retention
MAX_EVENTS = 10_000
DEDUP_TTL_SECONDS = 86400  # 24 hours

# Safety: max events a single poll cycle can emit (anomaly detection)
MAX_EVENTS_PER_POLL = 50
