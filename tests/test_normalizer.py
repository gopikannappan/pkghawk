from pkghawk.processing.normalizer import normalize_osv


def test_normalize_osv_malware():
    vuln = {
        "id": "MAL-2026-100",
        "summary": "Malicious code in evil-pkg (npm)",
        "aliases": ["GHSA-xxxx-yyyy-zzzz"],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "evil-pkg"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.1"}],
                    }
                ],
            }
        ],
        "references": [{"url": "https://github.com/advisories/GHSA-xxxx"}],
    }
    event = normalize_osv(vuln)
    assert event is not None
    assert event.package == "evil-pkg"
    assert event.ecosystem == "npm"
    assert event.type == "malicious"
    assert event.safe_version == "1.0.1"
    assert event.ghsa_id == "GHSA-xxxx-yyyy-zzzz"


def test_normalize_osv_regular_vuln():
    vuln = {
        "id": "GHSA-abcd-1234-5678",
        "summary": "Denial of Service in express",
        "aliases": ["CVE-2026-9999", "GHSA-abcd-1234-5678"],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "express"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "4.18.3"}],
                    }
                ],
            }
        ],
        "references": [],
    }
    event = normalize_osv(vuln)
    assert event is not None
    assert event.type == "vuln"
    assert event.cve_id == "CVE-2026-9999"


def test_normalize_osv_unsupported_ecosystem():
    vuln = {
        "id": "TEST-1",
        "summary": "Bug in something",
        "affected": [
            {"package": {"ecosystem": "Hackage", "name": "some-haskell-pkg"}}
        ],
    }
    event = normalize_osv(vuln)
    assert event is None


def test_normalize_osv_empty_affected():
    vuln = {"id": "TEST-2", "summary": "No affected", "affected": []}
    event = normalize_osv(vuln)
    assert event is None


def test_normalize_osv_typosquat():
    vuln = {
        "id": "MAL-2026-200",
        "summary": "Typosquatting package reqeusts on PyPI",
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "reqeusts"}}
        ],
        "references": [],
    }
    event = normalize_osv(vuln)
    assert event is not None
    assert event.type == "typosquat"
