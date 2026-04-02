"""pkghawk — Python client for the real-time package threat feed."""

from pkghawk_client.client import PkgHawk, check_package, latest, subscribe

__all__ = ["PkgHawk", "check_package", "latest", "subscribe"]
__version__ = "0.1.0"
