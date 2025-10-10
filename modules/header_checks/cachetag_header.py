#!/usr/bin/env python3

from utils.style import Colors


def check_cachetag_header(base_header: list[str]) -> None:
    print(f"{Colors.CYAN} ├ Header cache tags{Colors.RESET}")

    results = []

    for header in base_header:
        # Skip headers without colons to avoid index errors
        if ":" not in header:
            continue

        # Split once and reuse
        header_parts = header.split(":", 1)  # Split only on first colon
        header_name = header_parts[0].strip().lower()
        header_name_lower = header_name.lower()
        header_value = header_parts[1].strip()
        header_lower = header.lower()

        # Check all conditions in one pass
        if (
            "cache" in header_lower
            or header_name_lower == "vary"
            or header_name_lower == "age"
            or "access" in header_name_lower
            or "host" in header_lower
        ):
            results.append(f"{header_name}:{header_value}")

    # Print results
    for result in results:
        print(f" ├─ {result:<30}")
