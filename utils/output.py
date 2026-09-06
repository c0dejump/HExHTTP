#!/usr/bin/env python3
"""
HExHTTP - Live output controller for multi-URL (-f) scans.

In threaded mode every worker prints a full banner + verbose per-module output
for its URL, and all of it interleaves across threads into an unreadable mess.

This wraps sys.stdout so that, during a multi-URL scan:
  * the fixed per-URL boilerplate (banner, section headers, blank/transient
    lines) is suppressed from the console — it still goes to the HTML report;
  * every other line (i.e. everything the scan *finds*) is surfaced live,
    prefixed with its target host so it stays unambiguous across threads;
  * a progress bar stays pinned at the bottom of the terminal.

Modules keep calling print() as usual — they don't know they're being filtered.
"""
import re
import sys
import threading
from urllib.parse import urlsplit

from utils.style import Colors

# Strong finding markers (from Identify.behavior / Identify.confirmed), used to
# count vulns for the progress bar.
_BEHAVIOR = "INTERESTING BEHAVIOR"
_CONFIRMED = "VULNERABILITY CONFIRMED"

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Fixed boilerplate to hide (matched on the ANSI-stripped, stripped line).
_NOISE_PREFIXES = (
    "⟙", "⟘",                       # banner borders
    "[STARTED]", "[DONE]",
    "URL:", "URL response",          # URL: / URL response / URL response size
    "Proxy:", "Auth", "Stealth",
)

# Structural/announcement lines end with these words ("Akamai analysis",
# "Akamai S3 cache-poisoning test", ...). Real findings never do.
_NOISE_SUFFIXES = (" analysis", " test")

_BAR_WIDTH = 24


class LiveFindingsStdout:
    """stdout proxy: hides boilerplate, tags findings by host, pins a bar below."""

    def __init__(self, real, total: int):
        self._real = real
        self._lock = threading.RLock()
        self._total = max(total, 1)
        self._done = 0
        self._findings = 0
        self._fragments: dict[int, str] = {}  # thread id -> partial line
        self._hosts: dict[int, str] = {}       # thread id -> current host tag
        self._tty = getattr(real, "isatty", lambda: False)()
        self._bar_shown = False

    # -- per-thread context ----------------------------------------------
    def set_current(self, url: str) -> None:
        """Record which URL the calling thread is currently scanning."""
        host = urlsplit(url).netloc or url
        with self._lock:
            self._hosts[threading.get_ident()] = host

    # -- file-like interface ---------------------------------------------
    def write(self, data: str) -> int:
        tid = threading.get_ident()
        with self._lock:
            buf = self._fragments.get(tid, "") + data
            # A carriage return means a transient redraw (spinners); keep only
            # what follows the last one so the buffer stays bounded.
            if "\r" in buf:
                buf = buf.rsplit("\r", 1)[1]
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                self._handle_line(line, tid)
            self._fragments[tid] = buf
        return len(data)

    def flush(self) -> None:
        self._real.flush()

    def isatty(self) -> bool:
        return self._tty

    def __getattr__(self, name):
        return getattr(self._real, name)

    # -- progress control (public) ---------------------------------------
    def advance(self, n: int = 1) -> None:
        with self._lock:
            self._done += n
            self._render_bar()

    def start(self) -> None:
        with self._lock:
            self._render_bar()

    def finish(self) -> None:
        with self._lock:
            if self._tty and self._bar_shown:
                self._real.write("\n")
            self._real.flush()

    # -- internals (call under lock) -------------------------------------
    def _handle_line(self, line: str, tid: int) -> None:
        stripped = _ANSI.sub("", line).strip()
        if not stripped or stripped.startswith("├ "):  # blank or section header
            return
        if stripped.startswith(_NOISE_PREFIXES):
            return
        # Section headers ("... analysis") and test announcements ("... test")
        # are progress noise, not findings — even when they use a leaf marker.
        if stripped.endswith(_NOISE_SUFFIXES):
            return
        if _BEHAVIOR in line or _CONFIRMED in line:
            self._findings += 1
        host = self._hosts.get(tid, "")
        tag = f"{Colors.CYAN}[{host}]{Colors.RESET} " if host else ""
        self._emit_above_bar(f"{tag}{line.rstrip()}\n")

    def _bar(self) -> str:
        frac = min(self._done / self._total, 1.0)
        filled = int(_BAR_WIDTH * frac)
        bar = "█" * filled + "░" * (_BAR_WIDTH - filled)
        return (
            f"\r\033[K {Colors.MAGENTA}[{bar}]{Colors.RESET} "
            f"{self._done}/{self._total} ({int(frac * 100)}%) · "
            f"{Colors.RED}{self._findings}{Colors.RESET} findings"
        )

    def _render_bar(self) -> None:
        if self._tty:
            self._real.write(self._bar())
            self._real.flush()
            self._bar_shown = True

    def _emit_above_bar(self, text: str) -> None:
        if self._tty and self._bar_shown:
            self._real.write("\r\033[K")  # erase the bar
        self._real.write(text)
        if self._tty:
            self._render_bar()
        else:
            self._real.flush()


# Module-level singleton --------------------------------------------------
_mux: LiveFindingsStdout | None = None


def install(total: int) -> LiveFindingsStdout:
    """Replace sys.stdout with the live controller. Call once before workers."""
    global _mux
    _mux = LiveFindingsStdout(sys.stdout, total)
    sys.stdout = _mux
    _mux.start()
    return _mux


def set_current(url: str) -> None:
    """Tell the controller which URL the calling thread is scanning."""
    if _mux is not None:
        _mux.set_current(url)


def advance(n: int = 1) -> None:
    """Mark n URLs as processed and refresh the progress bar."""
    if _mux is not None:
        _mux.advance(n)


def uninstall() -> None:
    """Restore the original stdout."""
    global _mux
    if _mux is not None:
        _mux.finish()
        sys.stdout = _mux._real
        _mux = None
