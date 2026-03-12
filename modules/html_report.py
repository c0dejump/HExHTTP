#!/usr/bin/env python3
"""
HExHTTP - HTML Report Generator
Generates an interactive HTML report from scan results.
"""

import html
import json
import os
from datetime import datetime


_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RESULTS_DIR = os.path.join(_BASE_DIR, "results")


def get_default_output_path() -> str:
    os.makedirs(_RESULTS_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    return os.path.join(_RESULTS_DIR, f"{ts}_report.html")


def build_scan_meta(args=None, start_time=None) -> dict:
    import time
    meta = {}
    if start_time is not None:
        if isinstance(start_time, (int, float)):
            meta["total_duration"] = time.time() - start_time
        elif isinstance(start_time, str):
            try:
                st = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
                meta["total_duration"] = (datetime.now() - st).total_seconds()
            except ValueError:
                pass
    if args is not None:
        if hasattr(args, "threads") and args.threads:
            meta["threads"] = args.threads
        options = []
        for attr, flag in {"cache_poisoning": "-c", "cpdos": "--cpdos", "all": "--all", "only_cp": "--ocp"}.items():
            if getattr(args, attr, None):
                options.append(flag)
        if options:
            meta["options"] = options
    return meta


def generate_html_report(scan_results: list[dict], output_path: str | None = None, scan_meta: dict | None = None) -> str:
    if output_path is None:
        output_path = get_default_output_path()
    if scan_meta is None:
        scan_meta = {}

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_urls = len(scan_results)
    total_findings = sum(len(r.get("findings", [])) for r in scan_results)
    urls_with_findings = sum(1 for r in scan_results if r.get("findings"))
    urls_clean = total_urls - urls_with_findings
    urls_errors = sum(1 for r in scan_results if r.get("errors"))

    critical_count = 0
    info_count = 0
    for r in scan_results:
        for f in r.get("findings", []):
            if f.get("severity", "info").lower() == "critical":
                critical_count += 1
            else:
                info_count += 1

    url_blocks = "".join(_build_url_block(i, r) for i, r in enumerate(scan_results))
    export_json = json.dumps(scan_results, indent=2, ensure_ascii=False, default=str)

    # Collect unique filter values from all findings
    all_types = set()
    all_statuses = set()
    all_reasons = set()
    for r in scan_results:
        for f in r.get("findings", []):
            all_types.add(f.get("type", "Unknown"))
            ev = f.get("evidence", {})
            sc = ev.get("status_code")
            if sc and str(sc) != "0":
                all_statuses.add(str(sc))
            desc = f.get("description", "")
            if "STATUS-CODE" in desc:
                all_reasons.add("status-code")
            elif "RESP-LENGTH" in desc:
                all_reasons.add("resp-length")

    # Build filter tag HTML
    type_tags = "".join(f'<button class="ftag" data-fgroup="type" data-fval="{html.escape(t)}">{html.escape(t)}</button>' for t in sorted(all_types))
    status_tags = "".join(f'<button class="ftag" data-fgroup="status" data-fval="{s}">{s}</button>' for s in sorted(all_statuses, key=lambda x: int(x) if x.isdigit() else 0))
    reason_tags = "".join(f'<button class="ftag" data-fgroup="reason" data-fval="{html.escape(r)}">{html.escape(r)}</button>' for r in sorted(all_reasons))

    err_card = ""
    if urls_errors:
        err_card = f"<div class='stat-card stat-err'><span class='stat-value'>{urls_errors}</span><span class='stat-label'>Errors</span></div>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HExHTTP Report — {html.escape(now)}</title>
<style>{_get_css()}</style>
</head>
<body>
<script id="raw-data" type="application/json">{export_json.replace("</", "<\\/")}</script>

<header class="report-header">
  <div class="header-inner">
    <div class="logo-row">
      <span class="logo-hex">HEx</span><span class="logo-http">HTTP</span>
      <span class="logo-tag">REPORT</span>
    </div>
    <p class="header-date">{html.escape(now)}</p>
    {_meta_line(scan_meta)}
  </div>
</header>

<section class="stats-bar">
  <div class="stats-inner">
    <div class="stat-card"><span class="stat-value">{total_urls}</span><span class="stat-label">URLs scanned</span></div>
    <div class="stat-card stat-confirmed"><span class="stat-value">{critical_count}</span><span class="stat-label">Confirmed</span></div>
    <div class="stat-card stat-behavior"><span class="stat-value">{info_count}</span><span class="stat-label">Behavior</span></div>
    <div class="stat-card stat-clean"><span class="stat-value">{urls_clean}</span><span class="stat-label">Clean</span></div>
    {err_card}
  </div>
</section>

<section class="controls">
  <div class="controls-inner">
    <div class="export-btns">
      <button class="export-btn" id="exportJson">Export JSON</button>
      <button class="export-btn" id="exportCsv">Export CSV</button>
    </div>
    <input type="text" id="searchInput" placeholder="Filter URLs..." class="search-input" />
    <div class="bulk-btns">
      <button class="bulk-btn" id="expandAll">Expand all</button>
      <button class="bulk-btn" id="collapseAll">Collapse all</button>
      <button class="bulk-btn" id="resetFilters">Reset filters</button>
    </div>
  </div>
  <div class="filters-bar">
    <div class="filter-group">
      <span class="fg-label">Severity</span>
      <button class="ftag" data-fgroup="sev" data-fval="critical">Confirmed</button>
      <button class="ftag" data-fgroup="sev" data-fval="info">Behavior</button>
    </div>
    {f'<div class="filter-group"><span class="fg-label">Type</span>{type_tags}</div>' if type_tags else ''}
    {f'<div class="filter-group"><span class="fg-label">Status</span>{status_tags}</div>' if status_tags else ''}
    {f'<div class="filter-group"><span class="fg-label">Reason</span>{reason_tags}</div>' if reason_tags else ''}
    <div class="filter-group">
      <span class="fg-label">View</span>
      <button class="ftag" data-fgroup="view" data-fval="findings">Findings only</button>
      <button class="ftag" data-fgroup="view" data-fval="clean">Clean only</button>
    </div>
  </div>
</section>

<main class="results">{url_blocks}</main>

<footer class="report-footer">
  <div class="footer-left">
    <span>Generated by <strong>HExHTTP</strong></span>
    <span class="footer-sep">·</span>
    <a href="https://github.com/c0dejump/HExHTTP" target="_blank" rel="noopener" class="footer-link">GitHub</a>
    <span class="footer-sep">·</span>
    <a href="https://paypal.me/c0dejump" target="_blank" rel="noopener" class="footer-link">PayPal</a>
    <span class="footer-sep">·</span>
    <a href="https://ko-fi.com/c0dejump" target="_blank" rel="noopener" class="footer-link">Ko-fi</a>
  </div>
  <span>{html.escape(now)}</span>
</footer>

<script>{_get_js()}</script>
</body>
</html>"""

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path


def _meta_line(m: dict) -> str:
    parts = []
    if m.get("hexhttp_version"):
        parts.append(f"v{html.escape(str(m['hexhttp_version']))}")
    if m.get("threads"):
        parts.append(f"{m['threads']} threads")
    if m.get("options"):
        parts.append(" ".join(html.escape(o) for o in m["options"]))
    if m.get("total_duration"):
        parts.append(f"{m['total_duration']:.1f}s")
    return f'<p class="header-meta">{" · ".join(parts)}</p>' if parts else ""


def _is_critical(sev: str) -> bool:
    return sev.lower() == "critical"


def _sev_class(sev: str) -> str:
    return "sev-critical" if _is_critical(sev) else "sev-info"


def _sev_label(sev: str) -> str:
    return "CONFIRMED" if _is_critical(sev) else "BEHAVIOR"


def _format_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    return f"{b / (1024 * 1024):.1f} MB"


def _build_curl(uri: str, payload: dict) -> str:
    """Build a curl command from URI and payload headers."""
    parts = [f"curl -sk -o /dev/null -w '%{{http_code}} %{{size_download}}' \\"]
    for k, v in payload.items():
        # Escape single quotes in header values
        safe_k = str(k).replace("'", "'\\''")
        safe_v = str(v).replace("'", "'\\''")
        parts.append(f"  -H '{safe_k}: {safe_v}' \\")
    parts.append(f"  '{uri}'")
    return "\n".join(parts)


def _build_url_block(idx: int, result: dict) -> str:
    url = result.get("url", "N/A")
    status = result.get("status_code", "?")
    size = result.get("response_size", 0)
    tech = result.get("technology", "Unknown")
    findings = result.get("findings", [])
    errors = result.get("errors", [])
    duration = result.get("scan_duration")
    cache_headers = result.get("cache_headers", {})

    n_total = len(findings)
    n_crit = sum(1 for f in findings if _is_critical(f.get("severity", "info")))
    n_info = n_total - n_crit
    has_critical = n_crit > 0
    max_sev = "critical" if has_critical else "info"
    border_class = _sev_class(max_sev) if findings else "sev-clean"

    if isinstance(status, int):
        sc_class = "sc-ok" if 200 <= status < 300 else "sc-redirect" if 300 <= status < 400 else "sc-client" if 400 <= status < 500 else "sc-server"
    else:
        sc_class = "sc-unknown"

    badges = ""
    if n_crit:
        badges += f'<span class="mini-badge sev-critical">{n_crit} confirmed</span> '
    if n_info:
        badges += f'<span class="mini-badge sev-info">{n_info} behavior</span> '

    types_str = ", ".join(sorted({f.get("type", "Unknown") for f in findings}))
    size_str = _format_bytes(size) if size else "—"
    dur_str = f"{duration:.1f}s" if duration else "—"

    cache_html = ""
    if cache_headers:
        parts = [f"<span class='ch-key'>{html.escape(k)}:</span> {html.escape(str(v))}" for k, v in list(cache_headers.items())[:4]]
        cache_html = f'<div class="cache-summary">{"  ·  ".join(parts)}</div>'

    details = ""
    if findings:
        details = '<div class="findings-list">' + "".join(_build_finding_card(f) for f in findings) + '</div>'

    err_html = ""
    if errors:
        err_html = '<div class="errors-block"><h4>Errors</h4><ul>' + "".join(f"<li>{html.escape(str(e))}</li>" for e in errors) + '</ul></div>'

    if findings:
        count_badge = f'<span class="url-findings-count {_sev_class(max_sev)}">{n_total} finding{"s" if n_total != 1 else ""}</span>'
    else:
        count_badge = '<span class="url-clean-badge">Clean</span>'

    return f"""
<div class="url-card {border_class}" data-url="{html.escape(url)}" data-has-findings="{1 if findings else 0}" data-max-sev="{max_sev}">
  <div class="url-summary" onclick="toggleCard(this)">
    <div class="url-left">
      <span class="url-status {sc_class}">{status}</span>
      <span class="url-text">{html.escape(url)}</span>
    </div>
    <div class="url-right">
      <span class="url-tech">{html.escape(tech)}</span>
      <span class="url-size">{size_str}</span>
      <span class="url-dur">{dur_str}</span>
      {count_badge}
      <span class="chevron">▸</span>
    </div>
  </div>
  <div class="url-details" style="display:none;">
    <div class="details-meta">
      <div class="meta-row">{badges}{f"<span class='types-str'>{html.escape(types_str)}</span>" if types_str else ""}</div>
      {cache_html}
    </div>
    {details}
    {err_html}
  </div>
</div>"""


def _build_finding_card(finding: dict) -> str:
    ftype = finding.get("type", "Unknown")
    sev = finding.get("severity", "info")
    title = finding.get("title", ftype)
    desc = finding.get("description", "")
    payload = finding.get("payload", {})
    evidence = finding.get("evidence", {})

    # Extract status code from evidence or description
    ev_status = str(evidence.get("status_code", ""))
    # Extract reason keyword from description (e.g. "DIFFERENT STATUS-CODE 200 > 500")
    reason = ""
    if desc:
        if "STATUS-CODE" in desc:
            reason = "status-code"
        elif "RESP-LENGTH" in desc:
            reason = "resp-length"

    payload_html = ""
    if payload:
        payload_html = f'<div class="finding-payload"><span class="payload-label">Payload</span><pre class="code-block">{html.escape(json.dumps(payload, indent=2, ensure_ascii=False))}</pre></div>'

    # Clickable poisoned URI
    uri = evidence.get("uri", "")
    uri_html = ""
    if uri:
        uri_html = f'<div class="finding-uri"><span class="uri-label">Poisoned URL</span><a href="{html.escape(uri)}" target="_blank" rel="noopener" class="uri-link">{html.escape(uri)}</a></div>'

    # Build curl replay command
    curl_html = ""
    if uri and payload:
        curl_cmd = _build_curl(uri, payload)
        curl_id = f"curl-{id(finding)}-{hash(uri) & 0xFFFF}"
        curl_html = f'''<div class="finding-curl">
          <span class="curl-label">Replay</span>
          <div class="curl-block"><pre id="{curl_id}">{html.escape(curl_cmd)}</pre><button class="copy-btn" onclick="copyCurl('{curl_id}')">Copy</button></div>
        </div>'''

    ev_html = ""
    if evidence:
        parts = []
        for k, v in evidence.items():
            if k == "uri":
                continue  # already shown above
            if k == "interesting_headers" and isinstance(v, dict):
                for hk, hv in v.items():
                    parts.append(f"<div class='ev-row'><span class='ev-key'>{html.escape(hk)}</span><span class='ev-val'>{html.escape(str(hv))}</span></div>")
            elif k == "details":
                parts.append(f"<div class='ev-row ev-detail'><span class='ev-key'>Details</span><pre class='ev-pre'>{html.escape(str(v))}</pre></div>")
            else:
                parts.append(f"<div class='ev-row'><span class='ev-key'>{html.escape(str(k))}</span><span class='ev-val'>{html.escape(str(v))}</span></div>")
        ev_html = f'<div class="finding-evidence"><span class="evidence-label">Evidence</span>{"".join(parts)}</div>'

    return f"""
    <div class="finding-card {_sev_class(sev)}" data-f-sev="{html.escape(sev.lower())}" data-f-type="{html.escape(ftype)}" data-f-status="{html.escape(ev_status)}" data-f-reason="{html.escape(reason)}">
      <div class="finding-header">
        <span class="finding-sev-badge {_sev_class(sev)}">{_sev_label(sev)}</span>
        <span class="finding-type">{html.escape(ftype)}</span>
        <span class="finding-title">{html.escape(title)}</span>
      </div>
      {f'<p class="finding-desc">{html.escape(desc)}</p>' if desc else ''}
      {uri_html}
      {payload_html}
      {ev_html}
      {curl_html}
    </div>"""


def _get_css() -> str:
    return """
:root {
  --bg: #0c0e14; --surface: #13161f; --surface2: #1a1e2a;
  --border: #252a3a; --text: #c8cdd8; --text-dim: #6b7394; --text-bright: #eef0f6;
  --accent: #22c55e; --accent-dim: #16a34a; --accent-glow: rgba(34,197,94,0.12);
  --critical: #ef4444; --critical-bg: rgba(239,68,68,0.08);
  --info: #94a3b8; --info-bg: rgba(148,163,184,0.08);
  --clean: #34d399;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: 'JetBrains Mono','Fira Code','SF Mono','Cascadia Code',monospace; background:var(--bg); color:var(--text); line-height:1.6; min-height:100vh; }

.report-header { background:linear-gradient(180deg,#111422 0%,var(--bg) 100%); border-bottom:1px solid var(--border); padding:2.5rem 0 2rem; }
.header-inner { max-width:1200px; margin:0 auto; padding:0 1.5rem; }
.logo-row { display:flex; align-items:baseline; gap:0.15rem; }
.logo-hex { font-size:2rem; font-weight:800; color:var(--accent); }
.logo-http { font-size:2rem; font-weight:800; color:var(--text-bright); }
.logo-tag { font-size:0.65rem; font-weight:700; color:#000; background:var(--accent); padding:0.15rem 0.5rem; border-radius:3px; margin-left:0.75rem; letter-spacing:0.12em; position:relative; top:-0.2rem; }
.header-date { color:var(--text-dim); font-size:0.8rem; margin-top:0.5rem; }
.header-meta { color:var(--text-dim); font-size:0.75rem; margin-top:0.25rem; opacity:0.7; }

.stats-bar { background:var(--surface); border-bottom:1px solid var(--border); padding:1.5rem 0; }
.stats-inner { max-width:1200px; margin:0 auto; padding:0 1.5rem; display:flex; gap:1rem; flex-wrap:wrap; }
.stat-card { background:var(--surface2); border:1px solid var(--border); border-radius:8px; padding:1rem 1.5rem; display:flex; flex-direction:column; min-width:120px; }
.stat-value { font-size:1.75rem; font-weight:800; color:var(--text-bright); }
.stat-label { font-size:0.7rem; color:var(--text-dim); text-transform:uppercase; letter-spacing:0.08em; margin-top:0.25rem; }
.stat-confirmed .stat-value { color:var(--critical); }
.stat-behavior .stat-value { color:var(--info); }
.stat-clean .stat-value { color:var(--clean); }
.stat-err .stat-value { color:var(--critical); }

.controls { background:var(--bg); border-bottom:1px solid var(--border); padding:1rem 0; position:sticky; top:0; z-index:100; }
.controls-inner { max-width:1200px; margin:0 auto; padding:0 1.5rem; display:flex; gap:1rem; align-items:center; flex-wrap:wrap; }
.search-input { background:var(--surface2); border:1px solid var(--border); border-radius:6px; padding:0.5rem 1rem; color:var(--text-bright); font-family:inherit; font-size:0.8rem; width:260px; outline:none; transition:border-color 0.2s; }
.search-input:focus { border-color:var(--accent); }
.search-input::placeholder { color:var(--text-dim); }
.filter-btns,.export-btns { display:flex; gap:0.35rem; }
.filter-btn { background:var(--surface2); border:1px solid var(--border); border-radius:5px; padding:0.4rem 0.8rem; color:var(--text-dim); font-family:inherit; font-size:0.72rem; cursor:pointer; transition:all 0.15s; }
.filter-btn:hover { border-color:var(--accent); color:var(--text); }
.filter-btn.active { background:var(--accent-dim); border-color:var(--accent); color:#fff; }
.export-btn { background:var(--accent-glow); border:1px solid var(--accent-dim); border-radius:5px; padding:0.4rem 0.8rem; color:var(--accent); font-family:inherit; font-size:0.72rem; cursor:pointer; transition:all 0.15s; font-weight:600; }
.export-btn:hover { background:var(--accent-dim); color:#fff; }
.bulk-btns { display:flex; gap:0.35rem; margin-left:auto; }
.bulk-btn { background:transparent; border:1px solid var(--border); border-radius:5px; padding:0.4rem 0.7rem; color:var(--text-dim); font-family:inherit; font-size:0.7rem; cursor:pointer; transition:all 0.15s; }
.bulk-btn:hover { border-color:var(--text-dim); color:var(--text); }

.filters-bar { max-width:1200px; margin:0.6rem auto 0; padding:0 1.5rem; display:flex; gap:1.2rem; flex-wrap:wrap; align-items:center; }
.filter-group { display:flex; align-items:center; gap:0.3rem; }
.fg-label { font-size:0.62rem; color:var(--text-dim); text-transform:uppercase; letter-spacing:0.08em; margin-right:0.2rem; }
.ftag { background:var(--surface2); border:1px solid var(--border); border-radius:4px; padding:0.25rem 0.55rem; color:var(--text-dim); font-family:inherit; font-size:0.68rem; cursor:pointer; transition:all 0.15s; }
.ftag:hover { border-color:var(--accent); color:var(--text); }
.ftag.on { background:var(--accent-dim); border-color:var(--accent); color:#fff; }

.results { max-width:1200px; margin:0 auto; padding:1.5rem; }

.url-card { background:var(--surface); border:1px solid var(--border); border-radius:8px; margin-bottom:0.6rem; overflow:hidden; border-left:3px solid var(--border); }
.url-card.sev-critical { border-left-color:var(--critical); }
.url-card.sev-info { border-left-color:var(--info); }
.url-card.sev-clean { border-left-color:var(--clean); }
.url-summary { display:flex; justify-content:space-between; align-items:center; padding:0.85rem 1.2rem; cursor:pointer; user-select:none; transition:background 0.15s; }
.url-summary:hover { background:var(--surface2); }
.url-left { display:flex; align-items:center; gap:0.75rem; min-width:0; flex:1; }
.url-right { display:flex; align-items:center; gap:0.75rem; flex-shrink:0; }
.url-status { font-size:0.75rem; font-weight:700; padding:0.2rem 0.5rem; border-radius:4px; min-width:36px; text-align:center; }
.sc-ok { background:rgba(34,197,94,0.15); color:var(--clean); }
.sc-redirect { background:rgba(96,165,250,0.15); color:#60a5fa; }
.sc-client { background:rgba(234,179,8,0.15); color:#eab308; }
.sc-server { background:rgba(239,68,68,0.15); color:var(--critical); }
.sc-unknown { background:var(--surface2); color:var(--text-dim); }
.url-text { font-size:0.82rem; color:var(--text-bright); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.url-tech,.url-size,.url-dur { font-size:0.7rem; color:var(--text-dim); }
.url-findings-count { font-size:0.72rem; font-weight:700; padding:0.15rem 0.6rem; border-radius:10px; }
.url-findings-count.sev-critical { background:var(--critical-bg); color:var(--critical); }
.url-findings-count.sev-info { background:var(--info-bg); color:var(--info); }
.url-clean-badge { font-size:0.72rem; font-weight:600; color:var(--clean); padding:0.15rem 0.6rem; border-radius:10px; background:rgba(52,211,153,0.1); }
.chevron { font-size:0.9rem; color:var(--text-dim); transition:transform 0.25s; display:inline-block; }
.url-card.open .chevron { transform:rotate(90deg); }

.url-details { padding:0 1.2rem 1.2rem; }
.details-meta { padding:0.75rem 0; border-bottom:1px solid var(--border); margin-bottom:1rem; }
.meta-row { display:flex; gap:0.5rem; flex-wrap:wrap; align-items:center; }
.mini-badge { font-size:0.65rem; font-weight:700; padding:0.1rem 0.45rem; border-radius:3px; text-transform:uppercase; letter-spacing:0.05em; }
.mini-badge.sev-critical { background:var(--critical-bg); color:var(--critical); }
.mini-badge.sev-info { background:var(--info-bg); color:var(--info); }
.types-str { font-size:0.75rem; color:var(--text-dim); margin-left:0.5rem; }
.cache-summary { margin-top:0.5rem; font-size:0.72rem; color:var(--text-dim); }
.ch-key { color:var(--accent); }

.findings-list { display:flex; flex-direction:column; gap:0.65rem; }
.finding-card { background:var(--surface2); border:1px solid var(--border); border-radius:6px; padding:1rem 1.2rem; border-left:3px solid var(--border); }
.finding-card.sev-critical { border-left-color:var(--critical); background:var(--critical-bg); }
.finding-card.sev-info { border-left-color:var(--info); background:var(--info-bg); }
.finding-header { display:flex; align-items:center; gap:0.6rem; flex-wrap:wrap; }
.finding-sev-badge { font-size:0.62rem; font-weight:800; padding:0.15rem 0.5rem; border-radius:3px; text-transform:uppercase; letter-spacing:0.1em; color:#fff; }
.finding-sev-badge.sev-critical { background:var(--critical); }
.finding-sev-badge.sev-info { background:var(--info); }
.finding-type { font-size:0.78rem; font-weight:700; color:var(--text-bright); }
.finding-title { font-size:0.75rem; color:var(--text-dim); }
.finding-desc { font-size:0.78rem; color:var(--text); margin-top:0.6rem; line-height:1.5; }
.finding-payload { margin-top:0.75rem; }
.payload-label,.evidence-label { font-size:0.65rem; font-weight:700; color:var(--accent); text-transform:uppercase; letter-spacing:0.1em; display:block; margin-bottom:0.4rem; }
.code-block { background:#0a0c12; border:1px solid var(--border); border-radius:5px; padding:0.75rem 1rem; font-size:0.75rem; overflow-x:auto; color:var(--text-bright); white-space:pre; }
.finding-evidence { margin-top:0.75rem; }
.ev-row { display:flex; gap:0.75rem; padding:0.3rem 0; border-bottom:1px solid rgba(255,255,255,0.03); font-size:0.75rem; }
.ev-key { color:var(--accent); font-weight:600; min-width:140px; flex-shrink:0; }
.ev-val { color:var(--text); word-break:break-all; }
.ev-detail { flex-direction:column; }
.ev-pre { background:#0a0c12; border:1px solid var(--border); border-radius:4px; padding:0.5rem 0.75rem; font-size:0.72rem; overflow-x:auto; color:var(--text); margin-top:0.3rem; white-space:pre-wrap; }

.errors-block { margin-top:1rem; padding:0.75rem 1rem; background:rgba(239,68,68,0.05); border:1px solid rgba(239,68,68,0.15); border-radius:6px; }
.errors-block h4 { font-size:0.75rem; color:var(--critical); margin-bottom:0.4rem; }
.errors-block ul { list-style:none; }
.errors-block li { font-size:0.72rem; color:var(--text-dim); padding:0.15rem 0; padding-left:1rem; position:relative; }
.errors-block li::before { content:"›"; position:absolute; left:0; color:var(--critical); }

.finding-uri { margin-top:0.5rem; }
.uri-label { font-size:0.65rem; font-weight:700; color:var(--accent); text-transform:uppercase; letter-spacing:0.1em; display:block; margin-bottom:0.3rem; }
.uri-link { font-size:0.75rem; color:var(--accent); text-decoration:none; word-break:break-all; transition:color 0.15s; }
.uri-link:hover { color:var(--clean); text-decoration:underline; }

.finding-curl { margin-top:0.75rem; }
.curl-label { font-size:0.65rem; font-weight:700; color:var(--accent); text-transform:uppercase; letter-spacing:0.1em; display:block; margin-bottom:0.4rem; }
.curl-block { position:relative; background:#0a0c12; border:1px solid var(--border); border-radius:5px; padding:0.75rem 1rem; padding-right:4.5rem; }
.curl-block pre { font-size:0.72rem; color:var(--text-bright); white-space:pre-wrap; word-break:break-all; margin:0; font-family:inherit; }
.copy-btn { position:absolute; top:0.5rem; right:0.5rem; background:var(--accent-dim); color:#fff; border:none; padding:0.3rem 0.65rem; border-radius:4px; font-family:inherit; font-size:0.65rem; cursor:pointer; transition:background 0.15s; }
.copy-btn:hover { background:var(--accent); }

.report-footer { max-width:1200px; margin:2rem auto 0; padding:1.5rem; border-top:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; font-size:0.7rem; color:var(--text-dim); }
.footer-left { display:flex; align-items:center; gap:0.4rem; }
.footer-link { color:var(--accent); text-decoration:none; transition:color 0.15s; }
.footer-link:hover { color:var(--clean); text-decoration:underline; }
.footer-sep { color:var(--border); }
.url-card.hidden { display:none; }
@media (max-width:768px) {
  .url-summary { flex-direction:column; align-items:flex-start; gap:0.5rem; }
  .url-right { flex-wrap:wrap; }
  .search-input { width:100%; }
  .controls-inner { flex-direction:column; }
  .bulk-btns { margin-left:0; }
}
"""


def _get_js() -> str:
    return """
function toggleCard(el){const c=el.closest('.url-card'),d=c.querySelector('.url-details');if(c.classList.contains('open')){d.style.display='none';c.classList.remove('open')}else{d.style.display='block';c.classList.add('open')}}
function getRawData(){try{return JSON.parse(document.getElementById('raw-data').textContent)}catch(e){return[]}}
function downloadFile(c,f,m){const b=new Blob([c],{type:m}),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=f;document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(a.href)}
function copyCurl(id){const el=document.getElementById(id);if(!el)return;navigator.clipboard.writeText(el.textContent).then(()=>{const btn=el.parentElement.querySelector('.copy-btn');if(btn){btn.textContent='Copied!';setTimeout(()=>{btn.textContent='Copy'},1500)}})}

document.getElementById('exportJson').addEventListener('click',function(){
  const d=getRawData(),ts=new Date().toISOString().slice(0,16).replace(/[:\\-T]/g,'');
  downloadFile(JSON.stringify(d,null,2),'hexhttp_'+ts+'.json','application/json');
});

document.getElementById('exportCsv').addEventListener('click',function(){
  const d=getRawData(),rows=[['URL','Status','Size','Technology','Findings','Confirmed','Behavior','Types','Errors']];
  d.forEach(function(r){
    const f=r.findings||[],e=r.errors||[],types=[...new Set(f.map(x=>x.type||'Unknown'))].join('; ');
    const confirmed=f.filter(x=>(x.severity||'').toLowerCase()==='critical').length;
    rows.push([r.url||'',r.status_code||'',r.response_size||'',r.technology||'',f.length,confirmed,f.length-confirmed,types,e.join('; ')]);
    f.forEach(function(x){rows.push(['  -> '+(x.type||''),(x.severity||'').toLowerCase()==='critical'?'CONFIRMED':'BEHAVIOR',x.title||'',x.description||'',JSON.stringify(x.payload||{}),'','','',''])});
  });
  const csv=rows.map(r=>r.map(c=>{const s=String(c).replace(/"/g,'""');return'"'+s+'"'}).join(',')).join('\\n');
  const ts=new Date().toISOString().slice(0,16).replace(/[:\\-T]/g,'');
  downloadFile('\\uFEFF'+csv,'hexhttp_'+ts+'.csv','text/csv;charset=utf-8');
});

document.getElementById('searchInput').addEventListener('input',applyFilters);
document.getElementById('expandAll').addEventListener('click',function(){document.querySelectorAll('.url-card').forEach(c=>{if(!c.classList.contains('hidden')){c.classList.add('open');c.querySelector('.url-details').style.display='block'}})});
document.getElementById('collapseAll').addEventListener('click',function(){document.querySelectorAll('.url-card').forEach(c=>{c.classList.remove('open');c.querySelector('.url-details').style.display='none'})});
document.getElementById('resetFilters').addEventListener('click',function(){
  document.querySelectorAll('.ftag.on').forEach(t=>t.classList.remove('on'));
  document.getElementById('searchInput').value='';
  applyFilters();
});

// Toggle filter tags — within same group: multi-select; "view" group: exclusive
document.querySelectorAll('.ftag').forEach(tag=>{
  tag.addEventListener('click',function(){
    const group=this.dataset.fgroup;
    if(group==='view'){
      const wasOn=this.classList.contains('on');
      document.querySelectorAll('.ftag[data-fgroup="view"]').forEach(t=>t.classList.remove('on'));
      if(!wasOn) this.classList.add('on');
    }else{
      this.classList.toggle('on');
    }
    applyFilters();
  });
});

function getActiveFilters(){
  const filters={};
  document.querySelectorAll('.ftag.on').forEach(t=>{
    const g=t.dataset.fgroup, v=t.dataset.fval;
    if(!filters[g]) filters[g]=[];
    filters[g].push(v);
  });
  return filters;
}

function applyFilters(){
  const search=document.getElementById('searchInput').value.toLowerCase();
  const filters=getActiveFilters();
  const hasSevFilter=!!filters.sev;
  const hasTypeFilter=!!filters.type;
  const hasStatusFilter=!!filters.status;
  const hasReasonFilter=!!filters.reason;
  const hasView=!!filters.view;
  const hasFindingFilter=hasSevFilter||hasTypeFilter||hasStatusFilter||hasReasonFilter;

  document.querySelectorAll('.url-card').forEach(card=>{
    const url=(card.dataset.url||'').toLowerCase();
    const hasFindings=card.dataset.hasFindings==='1';
    let cardVisible=true;

    // Text search
    if(search&&!url.includes(search)) cardVisible=false;

    // View filter (findings only / clean only)
    if(hasView){
      if(filters.view.includes('findings')&&!hasFindings) cardVisible=false;
      if(filters.view.includes('clean')&&hasFindings) cardVisible=false;
    }

    // Finding-level filters: filter individual findings, show card only if any match
    const findingCards=card.querySelectorAll('.finding-card');
    if(cardVisible&&hasFindingFilter){
      if(findingCards.length===0){
        // No findings at all — hide when any finding filter is active
        cardVisible=false;
      }else{
        let anyMatch=false;
        findingCards.forEach(fc=>{
          let match=true;
          if(hasSevFilter&&!filters.sev.includes(fc.dataset.fSev||'')) match=false;
          if(hasTypeFilter&&!filters.type.includes(fc.dataset.fType||'')) match=false;
          if(hasStatusFilter&&!filters.status.includes(fc.dataset.fStatus||'')) match=false;
          if(hasReasonFilter&&!filters.reason.includes(fc.dataset.fReason||'')) match=false;
          fc.style.display=match?'':'none';
          if(match) anyMatch=true;
        });
        if(!anyMatch) cardVisible=false;
      }
    }else if(!hasFindingFilter){
      findingCards.forEach(fc=>{fc.style.display='';});
    }

    card.classList.toggle('hidden',!cardVisible);
  });
}
"""