# pkghawk

Python client for [pkghawk](https://pkghawk.dev) — the real-time package threat feed.

Check packages for active supply chain attacks before installing them.

## Install

```bash
pip install pkghawk
```

## Usage

### Check a package

```python
from pkghawk_client import check_package

alerts = check_package("axios", "npm")
if alerts:
    print(f"ALERT: {alerts[0]['summary']}")
else:
    print("Clean")
```

### Get latest events

```python
from pkghawk_client import latest

events = latest(n=10, ecosystem="npm", severity="critical")
for e in events:
    print(f"[{e['severity']}] {e['package']}: {e['summary']}")
```

### Subscribe to the live feed

```python
from pkghawk_client import subscribe

def on_alert(event):
    print(f"[{event['severity']}] {event['package']}: {event['summary']}")

subscribe(on_alert, ecosystem="pypi")
```

### Client class

```python
from pkghawk_client import PkgHawk

hawk = PkgHawk(base_url="https://pkghawk.dev")
hawk.check("requests", "pypi")
hawk.latest(n=20)
hawk.health()
hawk.stats()
```

## CLI

```bash
# Check a package
pkghawk check axios npm

# Latest events
pkghawk latest -n 20 --ecosystem npm --severity critical

# Watch live feed
pkghawk watch --ecosystem pypi

# Feed health
pkghawk health

# Stats
pkghawk stats
```

### CI integration — block compromised packages

```bash
pkghawk check $PACKAGE $ECOSYSTEM || exit 1
```

The `check` command exits with code 1 if alerts are found.

## Self-hosted

Point to your own pkghawk instance:

```python
hawk = PkgHawk(base_url="http://localhost:8000")
```

```bash
pkghawk --url http://localhost:8000 check axios npm
```

## License

MIT
