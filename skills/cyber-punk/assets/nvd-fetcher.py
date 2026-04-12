#!/usr/bin/env python3
"""
NVD Fetcher - Queries the NIST National Vulnerability Database (NVD) API v2.0
to fetch CVE and CWE data for a project's dependencies.
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NVD_CVE_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_WINDOW = 30  # seconds
RATE_LIMIT_NO_KEY = 5
RATE_LIMIT_WITH_KEY = 50
BACKOFF_INITIAL = 2
BACKOFF_MAX = 60
MAX_RETRIES = 3

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------
_request_timestamps: list[float] = []


def _rate_limit_wait(api_key: str | None) -> None:
    """Sleep if necessary to respect the NVD rolling-window rate limit."""
    limit = RATE_LIMIT_WITH_KEY if api_key else RATE_LIMIT_NO_KEY
    now = time.time()
    # Prune timestamps outside the window
    while _request_timestamps and _request_timestamps[0] < now - RATE_WINDOW:
        _request_timestamps.pop(0)
    if len(_request_timestamps) >= limit:
        sleep_for = _request_timestamps[0] + RATE_WINDOW - now + 0.1
        if sleep_for > 0:
            print(f"  Rate limit reached, sleeping {sleep_for:.1f}s ...", file=sys.stderr)
            time.sleep(sleep_for)
    _request_timestamps.append(time.time())


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _build_headers(api_key: str | None) -> dict:
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    return headers


def nvd_get(url: str, params: dict, api_key: str | None) -> dict | None:
    """GET with rate limiting and exponential back-off on 403/429."""
    _rate_limit_wait(api_key)
    headers = _build_headers(api_key)
    delay = BACKOFF_INITIAL

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=30)
            if resp.status_code in (403, 429):
                if attempt < MAX_RETRIES:
                    print(f"  HTTP {resp.status_code}, backing off {delay}s (attempt {attempt}/{MAX_RETRIES})", file=sys.stderr)
                    time.sleep(delay)
                    delay = min(delay * 2, BACKOFF_MAX)
                    continue
                else:
                    print(f"  HTTP {resp.status_code} after {MAX_RETRIES} retries, skipping.", file=sys.stderr)
                    return None
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.JSONDecodeError:
            print(f"  Warning: invalid JSON response, skipping.", file=sys.stderr)
            return None
        except requests.exceptions.RequestException as exc:
            print(f"  Network error: {exc}", file=sys.stderr)
            return None
    return None


# ---------------------------------------------------------------------------
# Version comparison (best-effort semver)
# ---------------------------------------------------------------------------

def parse_version(ver: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple of integers."""
    parts = re.split(r"[.\-+]", ver.strip())
    result: list[int] = []
    for p in parts:
        digits = re.match(r"(\d+)", p)
        if digits:
            result.append(int(digits.group(1)))
    return tuple(result) if result else (0,)


def version_less_than(installed: str, threshold: str) -> bool:
    return parse_version(installed) < parse_version(threshold)


def version_less_equal(installed: str, threshold: str) -> bool:
    return parse_version(installed) <= parse_version(threshold)


# ---------------------------------------------------------------------------
# CVE extraction helpers
# ---------------------------------------------------------------------------

def extract_cvss(metrics: dict) -> tuple[float | None, str]:
    """Return (score, severity) preferring CVSS v3.1 > v3.0 > v2.0."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity", "UNKNOWN")
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        data = entries[0].get("cvssData", {})
        score = data.get("baseScore")
        severity = entries[0].get("baseSeverity", "UNKNOWN")
        return score, severity
    return None, "UNKNOWN"


def extract_cwe_ids(weaknesses: list) -> list[str]:
    ids: list[str] = []
    for w in weaknesses:
        for desc in w.get("descriptions", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                ids.append(val)
    return ids


def extract_affected_versions(configurations: list) -> str:
    """Build a human-readable version constraint string from CPE match nodes."""
    constraints: list[str] = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                parts: list[str] = []
                vs = match.get("versionStartIncluding")
                vse = match.get("versionStartExcluding")
                ve = match.get("versionEndIncluding")
                vee = match.get("versionEndExcluding")
                if vs:
                    parts.append(f">= {vs}")
                if vse:
                    parts.append(f"> {vse}")
                if ve:
                    parts.append(f"<= {ve}")
                if vee:
                    parts.append(f"< {vee}")
                if parts:
                    constraints.append(", ".join(parts))
    return " | ".join(constraints) if constraints else "unspecified"


def is_version_affected(installed: str, configurations: list) -> bool:
    """Best-effort check whether installed version falls inside any affected range."""
    if not configurations:
        return True  # No CPE data; include conservatively
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                vs = match.get("versionStartIncluding")
                vse = match.get("versionStartExcluding")
                ve = match.get("versionEndIncluding")
                vee = match.get("versionEndExcluding")
                # If no version bounds at all, treat as potentially affected
                if not any([vs, vse, ve, vee]):
                    return True
                in_lower = True
                if vs and version_less_than(installed, vs):
                    in_lower = False
                if vse and version_less_equal(installed, vse):
                    in_lower = False
                in_upper = True
                if ve and not version_less_equal(installed, ve):
                    in_upper = False
                if vee and not version_less_than(installed, vee):
                    in_upper = False
                if in_lower and in_upper:
                    return True
    return False


def cve_mentions_package(cve_item: dict, package: str) -> bool:
    """Check if the CVE description or CPE entries reference the package name."""
    pkg_lower = package.lower()
    # Check description
    for desc in cve_item.get("descriptions", []):
        if pkg_lower in desc.get("value", "").lower():
            return True
    # Check CPE match strings
    for config in cve_item.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if pkg_lower in match.get("criteria", "").lower():
                    return True
    return False


# ---------------------------------------------------------------------------
# Main query functions
# ---------------------------------------------------------------------------

def query_cves_for_package(package: str, version: str, api_key: str | None) -> list[dict]:
    """Query NVD for CVEs related to a package and filter by installed version."""
    data = nvd_get(NVD_CVE_BASE, {"keywordSearch": package}, api_key)
    if not data:
        return []

    results: list[dict] = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        if not cve_mentions_package(cve, package):
            continue
        configurations = cve.get("configurations", [])
        if not is_version_affected(version, configurations):
            continue
        score, severity = extract_cvss(cve.get("metrics", {}))
        desc_text = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break
        refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
        results.append({
            "cve_id": cve.get("id", ""),
            "package": package,
            "affected_versions": extract_affected_versions(configurations),
            "installed_version": version,
            "cvss_score": score,
            "severity": severity,
            "cwe_ids": extract_cwe_ids(cve.get("weaknesses", [])),
            "description": desc_text,
            "references": refs,
        })
    return results


def query_cwe(cwe_id: str, language: str, api_key: str | None) -> dict | None:
    """Fetch CVE examples for a specific CWE ID and return a summary record."""
    data = nvd_get(NVD_CVE_BASE, {"cweId": cwe_id}, api_key)
    if not data:
        return None
    vulns = data.get("vulnerabilities", [])
    # Derive a human-readable name from the first CVE's weakness descriptions
    name = cwe_id
    description = ""
    if vulns:
        cve = vulns[0].get("cve", {})
        for w in cve.get("weaknesses", []):
            for d in w.get("descriptions", []):
                if d.get("value", "").startswith("CWE-"):
                    continue
                if d.get("lang") == "en":
                    name = d.get("value", cwe_id)
                    break
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
    return {
        "cwe_id": cwe_id,
        "name": name,
        "description": description[:300] if description else "",
        "applicable_to": language,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch CVE/CWE data from the NIST NVD API v2.0 for project dependencies."
    )
    parser.add_argument(
        "--dependencies", required=True,
        help='JSON string of package:version pairs, e.g. \'{"express": "4.17.1"}\'',
    )
    parser.add_argument(
        "--language", required=True,
        choices=["javascript", "python", "go", "java", "rust", "php", "ruby", "c_cpp"],
        help="Target programming language.",
    )
    parser.add_argument(
        "--api-key", default=None,
        help="NVD API key. Falls back to NVD_API_KEY env var.",
    )
    parser.add_argument(
        "--output", required=True,
        help="Path to write the output JSON file.",
    )
    parser.add_argument(
        "--cwe-ids", default=None,
        help='Comma-separated CWE IDs to also fetch (e.g. "CWE-89,CWE-79").',
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Parse dependencies
    try:
        dependencies: dict[str, str] = json.loads(args.dependencies)
    except json.JSONDecodeError as exc:
        print(f"Error: invalid --dependencies JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    # Resolve API key (CLI flag > env var)
    api_key = args.api_key or os.environ.get("NVD_API_KEY")

    # Parse CWE IDs
    cwe_ids: list[str] = []
    if args.cwe_ids:
        cwe_ids = [c.strip() for c in args.cwe_ids.split(",") if c.strip()]

    language: str = args.language
    total = len(dependencies)

    # ----- Query CVEs for each dependency -----
    all_cves: list[dict] = []
    for idx, (package, version) in enumerate(dependencies.items(), start=1):
        print(f"Querying NVD for {package}... ({idx}/{total})", file=sys.stderr)
        cves = query_cves_for_package(package, version, api_key)
        all_cves.extend(cves)

    # ----- Query CWEs -----
    language_cwes: list[dict] = []
    if cwe_ids:
        for cwe_id in cwe_ids:
            print(f"Querying NVD for {cwe_id}...", file=sys.stderr)
            record = query_cwe(cwe_id, language, api_key)
            if record:
                language_cwes.append(record)

    # ----- Severity counts -----
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for cve in all_cves:
        sev = cve.get("severity", "UNKNOWN").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # ----- Build output -----
    output = {
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "language": language,
            "total_dependencies": total,
            "api_key_used": api_key is not None,
            "total_cves_found": len(all_cves),
        },
        "dependency_cves": all_cves,
        "language_cwes": language_cwes,
    }

    # Write JSON
    output_path = args.output
    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(output, fh, indent=2, ensure_ascii=False)
    except OSError as exc:
        print(f"Error writing output file: {exc}", file=sys.stderr)
        sys.exit(1)

    # ----- Print summary -----
    print("\nNVD Scan Complete:", file=sys.stderr)
    print(f"  - Scanned: {total} dependencies", file=sys.stderr)
    print(f"  - CVEs found: {len(all_cves)}", file=sys.stderr)
    print(
        f"  - Critical: {severity_counts['CRITICAL']} | "
        f"High: {severity_counts['HIGH']} | "
        f"Medium: {severity_counts['MEDIUM']} | "
        f"Low: {severity_counts['LOW']}",
        file=sys.stderr,
    )
    print(f"  - Results written to: {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
