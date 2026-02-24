#!/usr/bin/env python3
"""
http debug check - improved version with FP reduction
"""
from utils.style import Colors
from utils.utils import configure_logger, requests, random, range_exclusion, traceback, sys, human_time, random_ua
from modules.lists.debug_list import DEBUG_HEADERS

# Response headers that indicate debug mode is actually active
DEBUG_RESPONSE_INDICATORS = [
    # Exact header names (case-insensitive match)
    "x-debug", "x-debug-info", "x-debug-token", "x-debug-token-link",
    "x-symfony-debug", "x-laravel-debug", "x-django-debug",
    "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-runtime", "x-request-id", "x-trace-id",
    "server-timing", "x-cache-debug", "x-varnish-debug",
    "x-debug-mode", "x-debug-log", "x-debug-trace",
    "x-php-version", "x-generator", "x-environment",
    "x-debug-enabled", "x-profiler", "x-clockwork-id",
    "x-clockwork-version", "x-blackfire-response",
    "x-xdebug-profile-filename", "x-debug-output",
    "x-app-env", "x-app-debug", "x-dev-mode",
    "x-graphql-event-stream", "x-hasura-role",
    "x-kong-proxy-latency", "x-kong-upstream-latency",
    "x-envoy-upstream-service-time", "x-envoy-decorator-operation",
    "x-amzn-trace-id", "x-cloud-trace-context",
    "x-b3-traceid", "x-b3-spanid",
    "x-datadog-trace-id", "x-datadog-parent-id",
    "x-newrelic-app-data", "x-newrelic-transaction",
    "x-instana-t", "x-instana-s",
    "x-dynatrace", "x-elastic-product",
    "x-litespeed-cache", "x-turbo-charged-by",
]

# Substrings in response header VALUES that indicate debug info leakage
DEBUG_VALUE_INDICATORS = [
    "stacktrace", "stack_trace", "traceback", "exception",
    "debug=true", "debug=1", "development", "staging",
    "phpinfo", "xdebug", "profiler",
    "internal server", "error in", "syntax error",
    "mysql", "postgresql", "sqlite", "mongodb",
    "django.core", "laravel", "symfony",
    "node_modules", "vendor/", "gems/",
]

# Headers in the response that are NEW and likely debug-related (partial match)
DEBUG_HEADER_PREFIXES = [
    "x-debug", "x-trace", "x-profil", "x-stack",
    "x-error", "x-exception", "x-query", "x-sql",
    "x-cache-debug", "x-varnish", "x-envoy",
    "x-akamai-", "x-fastly-", "x-cloudflare-",
    "x-kong-", "x-amzn-", "x-cloud-trace",
    "x-datadog-", "x-newrelic-", "x-instana-",
    "x-dynatrace", "x-elastic-", "x-zipkin-",
    "x-honeycomb-", "x-lightstep-", "x-splunk-",
    "x-sentry-", "x-raygun-", "x-blackfire-",
    "x-clockwork", "x-xdebug", "x-runtime",
    "x-app-env", "x-app-debug", "x-dev-",
    "x-dispatcher", "server-timing",
]


def _collect_baselines(url, s, human, num_baselines=3):
    """Collect multiple baseline responses to understand normal server variance."""
    baselines = []
    for _ in range(num_baselines):
        try:
            uri = f"{url}?cb={random.randrange(99999)}"
            s.headers.update(random_ua())
            human_time(human)
            r = s.get(uri, allow_redirects=False, verify=False)
            baselines.append({
                'status': r.status_code,
                'size': len(r.content),
                'headers': set(h.lower() for h in r.headers.keys()),
                'header_count': len(r.headers),
            })
        except Exception:
            continue
    return baselines


def _compute_tolerance(baselines, main_len):
    """Compute body size tolerance based on observed variance."""
    if not baselines:
        return range_exclusion(main_len)

    sizes = [b['size'] for b in baselines] + [main_len]
    min_size = min(sizes)
    max_size = max(sizes)
    variance = max_size - min_size

    # Tolerance = observed variance + 10% of main_len + fixed margin
    margin = max(variance * 2, int(main_len * 0.10), 200)
    low = max(0, min_size - margin)
    high = max_size + margin
    return range(low, high + 1)


def _get_baseline_headers(baselines, main_head_keys):
    """Get union of all header names seen across baselines."""
    all_headers = set(h.lower() for h in main_head_keys)
    for b in baselines:
        all_headers.update(b['headers'])
    return all_headers


def _find_new_debug_headers(response_headers, baseline_headers):
    """Find response headers that are new AND look debug-related."""
    new_headers = []
    for h in response_headers:
        h_lower = h.lower()
        if h_lower not in baseline_headers:
            for prefix in DEBUG_HEADER_PREFIXES:
                if h_lower.startswith(prefix) or h_lower in DEBUG_RESPONSE_INDICATORS:
                    new_headers.append(h)
                    break
    return new_headers


# Headers that commonly contain long/noisy values - skip for debug value analysis
SKIP_VALUE_CHECK_HEADERS = {
    "content-security-policy", "content-security-policy-report-only",
    "link", "set-cookie", "strict-transport-security",
    "permissions-policy", "feature-policy", "referrer-policy",
    "access-control-allow-origin", "access-control-allow-headers",
    "access-control-allow-methods", "access-control-expose-headers",
    "cache-control", "vary", "etag", "date", "expires",
    "content-type", "content-length", "content-encoding",
    "transfer-encoding", "connection", "keep-alive",
    "accept-ranges", "age", "location", "retry-after",
    "www-authenticate", "authorization",
    "x-frame-options", "x-content-type-options", "x-xss-protection",
    "nel", "report-to", "cross-origin-opener-policy",
    "cross-origin-embedder-policy", "cross-origin-resource-policy",
    "timing-allow-origin",
}


def _check_debug_values(response_headers):
    """Check if any response header values contain debug indicators."""
    findings = []
    for h, v in response_headers.items():
        h_lower = h.lower()
        if h_lower in SKIP_VALUE_CHECK_HEADERS:
            continue
        v_lower = str(v).lower()
        for indicator in DEBUG_VALUE_INDICATORS:
            if indicator in v_lower:
                findings.append(f"{h}: {v[:100]}")
                break
    return findings


def _confirm_finding(url, s, dh, human):
    """Retry a request to confirm it's not a transient behavior."""
    try:
        uri = f"{url}?cb={random.randrange(99999)}"
        s.headers.update(random_ua())
        human_time(human)
        r = s.get(uri, headers=dh, allow_redirects=False, verify=False)
        return r
    except Exception:
        return None


def check_http_debug(url, s, main_status_code, main_len, main_head, authent, human):
    print(f"{Colors.CYAN} ├ Debug Headers analysis{Colors.RESET}")

    # Step 1: Collect multiple baselines to understand normal variance
    baselines = _collect_baselines(url, s, human, num_baselines=3)
    baseline_statuses = set(b['status'] for b in baselines)
    baseline_statuses.add(main_status_code)

    # Step 2: Compute adaptive tolerance
    size_tolerance = _compute_tolerance(baselines, main_len)
    main_head_keys = set(h.lower() for h in main_head) if isinstance(main_head, dict) else set()
    baseline_headers = _get_baseline_headers(baselines, main_head_keys if main_head_keys else [])

    # Baseline header count range
    header_counts = [b['header_count'] for b in baselines]
    if isinstance(main_head, dict):
        header_counts.append(len(main_head))
    elif isinstance(main_head, int):
        header_counts.append(main_head)
    min_hcount = min(header_counts) if header_counts else 0
    max_hcount = max(header_counts) if header_counts else 0

    behavior_groups = {}
    ignore_statuses = {403, 401, 429, 503, 502}

    for dh in DEBUG_HEADERS:
        try:
            uri = f"{url}?cb={random.randrange(99999)}"
            s.headers.update(random_ua())
            human_time(human)
            req_dh = s.get(uri, headers=dh, allow_redirects=False, verify=False)

            resp_status = req_dh.status_code
            resp_size = len(req_dh.content)
            resp_hcount = len(req_dh.headers)

            if resp_status in ignore_statuses:
                continue

            findings = []
            confidence = 0  # 0=noise, 1=low, 2=medium, 3=high

            # Check 1: New debug-related response headers (HIGH confidence)
            new_debug_h = _find_new_debug_headers(req_dh.headers, baseline_headers)
            if new_debug_h:
                findings.append(f"NEW DEBUG HEADERS: {', '.join(new_debug_h)}")
                confidence = max(confidence, 3)

            # Check 2: Debug values in response headers (HIGH confidence)
            debug_vals = _check_debug_values(req_dh.headers)
            if debug_vals:
                findings.append(f"DEBUG VALUES: {'; '.join(debug_vals[:3])}")
                confidence = max(confidence, 3)

            # Check 3: Status code change (MEDIUM confidence if not in baseline variance)
            if resp_status != main_status_code and resp_status not in baseline_statuses:
                findings.append(f"STATUS: {main_status_code} → {resp_status}")
                confidence = max(confidence, 2)

            # Check 4: Body size change (LOW confidence alone, needs confirmation)
            if resp_size not in size_tolerance:
                # Only flag if size difference is significant (>15% or >500 bytes)
                size_diff = abs(resp_size - main_len)
                pct_diff = (size_diff / max(main_len, 1)) * 100
                if pct_diff > 15 or size_diff > 500:
                    findings.append(f"BODY: {main_len}b → {resp_size}b ({pct_diff:.0f}%)")
                    confidence = max(confidence, 1)

            # Check 5: Header count (only if way outside baseline range + debug header found)
            if resp_hcount > max_hcount + 3 or resp_hcount < min_hcount - 3:
                # Only interesting if combined with another signal
                if confidence > 0:
                    findings.append(f"HEADER COUNT: {min_hcount}-{max_hcount} → {resp_hcount}")
                    confidence = max(confidence, 2)

            # Skip low confidence findings that are body-only changes
            if confidence < 2 and len(findings) == 1 and "BODY:" in findings[0]:
                continue

            # Always add body + header count as context if different from baseline
            context_parts = []
            if resp_size not in size_tolerance:
                size_diff = abs(resp_size - main_len)
                pct_diff = (size_diff / max(main_len, 1)) * 100
                body_info = f"BODY: {main_len}b → {resp_size}b ({pct_diff:.0f}%)"
                if body_info not in [f for f in findings if f.startswith("BODY:")]:
                    context_parts.append(body_info)

            if resp_hcount > max_hcount + 1 or resp_hcount < min_hcount - 1:
                hcount_info = f"HEADER COUNT: {min_hcount}-{max_hcount} → {resp_hcount}"
                if hcount_info not in [f for f in findings if f.startswith("HEADER COUNT:")]:
                    context_parts.append(hcount_info)

            all_findings = findings + context_parts

            if all_findings and confidence >= 2:
                behavior_msg = " | ".join(all_findings)
                # Group by first finding type for dedup
                first_finding_type = findings[0].split(":")[0].strip()
                behavior_key = f"{first_finding_type}_{resp_status}_{resp_size // 1000}"

                if behavior_key not in behavior_groups:
                    behavior_groups[behavior_key] = {
                        'msg': behavior_msg,
                        'url': uri,
                        'count': 0,
                        'payloads': [],
                        'confidence': confidence,
                        'dh': dh,
                    }
                behavior_groups[behavior_key]['count'] += 1
                behavior_groups[behavior_key]['payloads'].append(str(dh))
                behavior_groups[behavior_key]['confidence'] = max(
                    behavior_groups[behavior_key]['confidence'], confidence
                )

        except Exception as e:
            if "got more than 100 headers" in str(e):
                print(f"\033[33m   └── [WARNING]\033[0m | Server returned >100 headers | \033[34m{uri}\033[0m | PAYLOAD: {dh}")
            elif "Connection aborted" in str(e):
                print(f"\033[33m   └── [WARNING]\033[0m | Connection aborted | \033[34m{uri}\033[0m | PAYLOAD: {dh}")
            continue

        if len(list(dh.values())[0]) < 50 and len(list(dh.keys())[0]) < 50:
            sys.stdout.write(f"{Colors.BLUE}{dh} :: {req_dh.status_code}{Colors.RESET}\r")
            sys.stdout.write("\033[K")

    # Step 3: Confirm and display results
    FP_THRESHOLD = 10  # More than 10 payloads triggering same behavior = FP

    for key, data in behavior_groups.items():
        confirmed = False

        # Too many payloads = FP regardless of confidence
        if data['count'] > FP_THRESHOLD:
            confirmed = False
        # HIGH confidence (debug headers/values found) = always confirmed
        elif data['confidence'] == 3:
            confirmed = True
        # MEDIUM confidence with few payloads: confirm with retry
        elif data['count'] <= 5 and data['confidence'] >= 2:
            retry = _confirm_finding(url, s, data['dh'], human)
            if retry:
                retry_size = len(retry.content)
                retry_status = retry.status_code

                if retry_status not in baseline_statuses and retry_status not in ignore_statuses:
                    confirmed = True
                elif retry_size not in size_tolerance:
                    size_diff = abs(retry_size - main_len)
                    pct_diff = (size_diff / max(main_len, 1)) * 100
                    if pct_diff > 15 or size_diff > 500:
                        confirmed = True
        # MEDIUM confidence with many payloads: likely FP
        elif data['count'] > 5 and data['confidence'] < 3:
            confirmed = False

        if confirmed:
            conf_label = "HIGH" if data['confidence'] == 3 else "MEDIUM"
            print(
                f"\033[32m └──   [DEBUG CONFIRMED ({conf_label})]\033[0m | "
                f"{data['msg']} | \033[34m{data['url']}\033[0m | "
                f"PAYLOAD: {data['payloads'][0]}"
            )
            if data['count'] > 1:
                print(f"\033[90m        (+{data['count']-1} similar payloads)\033[0m")
        elif data['count'] > FP_THRESHOLD:
            print(
                f"\033[33m └──   [LIKELY FP - {data['count']} payloads trigger same behavior]\033[0m | "
                f"{data['msg']} | \033[34m{data['url']}\033[0m"
            )
        elif data['count'] > 5 and data['confidence'] < 3:
            print(
                f"\033[33m └──   [LIKELY FP - {data['count']} payloads trigger same behavior]\033[0m | "
                f"{data['msg']} | \033[34m{data['url']}\033[0m"
            )