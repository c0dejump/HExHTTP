#!/usr/bin/env python3
"""
HExHTTP - Real-time scan result collector.
Thread-safe, URL-keyed. Findings are stored as they arrive, not at the end.
"""
import threading
from urllib.parse import urlsplit, urlunsplit

_lock = threading.Lock()
_results: dict[str, dict] = {}  # keyed by base URL


def _resolve_url(url: str) -> str:
    """
    Resolve a URL (possibly with cache buster) to the registered base URL.
    Strips query string and tries to match against known URLs.
    """
    # Exact match first
    if url in _results:
        return url

    # Strip query string (?cb=xxx, ?CPDoS=xxx, etc.)
    parts = urlsplit(url)
    base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

    # Try base without query
    if base in _results:
        return base

    # Try base with trailing slash
    if not base.endswith("/"):
        base_slash = base + "/"
        if base_slash in _results:
            return base_slash

    # Try matching by domain+path prefix (for URLs like https://x.com/page?cb=123)
    for registered_url in _results:
        if url.startswith(registered_url.rstrip("/")) or base.startswith(registered_url.rstrip("/")):
            return registered_url

    # No match found, return as-is
    return url


def init_url(url: str, status_code: int = 0, response_size: int = 0,
             technology: str = "Unknown", cache_headers: dict | None = None) -> None:
    """Call at the start of process_modules to register the URL."""
    with _lock:
        _results[url] = {
            "url": url,
            "status_code": status_code,
            "response_size": response_size,
            "technology": technology,
            "cache_headers": cache_headers or {},
            "findings": [],
            "errors": [],
        }


def update_url(url: str, status_code: int | None = None, response_size: int | None = None,
               technology: str | None = None, cache_headers: dict | None = None) -> None:
    """Update URL metadata. Always overwrites with provided values."""
    with _lock:
        key = _resolve_url(url)
        if key not in _results:
            init_url(url, status_code or 0, response_size or 0,
                     technology or "Unknown", cache_headers)
            return
        r = _results[key]
        if status_code is not None:
            r["status_code"] = status_code
        if response_size is not None:
            r["response_size"] = response_size
        if technology is not None and technology != "Unknown":
            r["technology"] = technology
        if cache_headers is not None:
            r["cache_headers"].update(cache_headers)


def add_finding(url: str, finding: dict) -> None:
    """Add a finding to a URL. Thread-safe, real-time. Resolves cache-busted URLs."""
    with _lock:
        key = _resolve_url(url)
        if key not in _results:
            # Fallback: create entry with cleaned URL
            parts = urlsplit(url)
            clean = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
            _results[clean] = {
                "url": clean, "status_code": 0, "response_size": 0,
                "technology": "Unknown", "cache_headers": {},
                "findings": [], "errors": [],
            }
            key = clean
        _results[key]["findings"].append(finding)


def add_error(url: str, error: str) -> None:
    """Add an error to a URL."""
    with _lock:
        key = _resolve_url(url)
        if key not in _results:
            parts = urlsplit(url)
            clean = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
            _results[clean] = {
                "url": clean, "status_code": 0, "response_size": 0,
                "technology": "Unknown", "cache_headers": {},
                "findings": [], "errors": [],
            }
            key = clean
        _results[key]["errors"].append(error)


def get_results() -> list[dict]:
    """Return all results as a list for html_report."""
    with _lock:
        return list(_results.values())


def reset() -> None:
    """Clear all results."""
    with _lock:
        _results.clear()