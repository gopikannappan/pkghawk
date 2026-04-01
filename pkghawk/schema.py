from __future__ import annotations

import hashlib
import time
from enum import Enum

from pydantic import BaseModel, Field


class EventType(str, Enum):
    MALICIOUS = "malicious"
    VULN = "vuln"
    TYPOSQUAT = "typosquat"
    HIJACK = "hijack"
    SUSPICIOUS = "suspicious"


class Ecosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    GO = "go"
    MAVEN = "maven"
    CARGO = "cargo"
    RUBYGEMS = "rubygems"
    NUGET = "nuget"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PkgHawkEvent(BaseModel):
    id: str = ""
    type: EventType
    ecosystem: Ecosystem
    package: str
    affected_versions: list[str] = Field(default_factory=list)
    safe_version: str | None = None
    severity: Severity = Severity.UNKNOWN
    confidence: Confidence = Confidence.MEDIUM
    source: str
    sources_confirmed: list[str] = Field(default_factory=list)
    summary: str
    ref_urls: list[str] = Field(default_factory=list)
    cve_id: str | None = None
    ghsa_id: str | None = None
    ts: int = Field(default_factory=lambda: int(time.time()))
    ts_iso: str = ""
    first_seen: int = 0
    pkghawk_version: str = "1"

    def model_post_init(self, _context: object) -> None:
        if not self.id:
            self.id = self._generate_id()
        if not self.ts_iso:
            self.ts_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.ts))
        if not self.first_seen:
            self.first_seen = self.ts
        if self.source and self.source not in self.sources_confirmed:
            self.sources_confirmed = [self.source, *self.sources_confirmed]

    def _generate_id(self) -> str:
        raw = f"{self.ecosystem}-{self.package}-{self.source}-{self.ts}"
        short_hash = hashlib.sha256(raw.encode()).hexdigest()[:8]
        date_str = time.strftime("%Y%m%d", time.gmtime(self.ts))
        return f"ph-{date_str}-{short_hash}"

    def dedup_key(self) -> str:
        """Key for deduplication — same package+ecosystem+type = same event."""
        return f"{self.ecosystem.value}:{self.package}:{self.type.value}"
