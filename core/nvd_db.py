"""NVD 2.0 client used by TRACE's passive technology -> CVE correlation.

The client resolves a detected product/version to CPE 2.3 names and then asks
NVD for CVEs affecting each exact CPE. Results are cached on disk so repeated
scans do not hammer the public API.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import requests
from packaging.version import InvalidVersion, Version
from dotenv import load_dotenv

load_dotenv()

NVD_BASE = "https://services.nvd.nist.gov/rest/json"
CACHE_DIR = Path(os.getenv("TRACE_NVD_CACHE_DIR", ".cache/nvd"))
CACHE_TTL = int(os.getenv("TRACE_NVD_CACHE_TTL_HOURS", "168")) * 3600
# Empty/negative lookups are deliberately short-lived so a transient outage
# or a temporary NVD miss cannot poison the cache for a week.
NEGATIVE_CACHE_TTL = int(os.getenv("TRACE_NVD_NEGATIVE_CACHE_TTL_HOURS", "1")) * 3600
MIN_INTERVAL = float(os.getenv("TRACE_NVD_MIN_REQUEST_INTERVAL", "6.2"))

_last_request = 0.0


def _cache_path(prefix: str, key: str) -> Path:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{prefix}_{digest}.json"


def _read_cache(path: Path) -> Any | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        age = time.time() - path.stat().st_mtime

        # New cache format: {"items": ..., "negative": bool}
        if isinstance(payload, dict) and "items" in payload:
            ttl = NEGATIVE_CACHE_TTL if payload.get("negative") else CACHE_TTL
            if age <= ttl:
                return payload["items"]
            return None

        # Legacy cache files from the first implementation: keep non-empty
        # entries, but never reuse an empty list indefinitely.
        if isinstance(payload, list) and payload and age <= CACHE_TTL:
            return payload
    except (OSError, json.JSONDecodeError, TypeError):
        return None
    return None


def _write_cache(path: Path, items: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "cached_at": time.time(),
        "negative": not bool(items),
        "items": items,
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _get(path: str, params: dict[str, Any]) -> dict[str, Any]:
    global _last_request
    wait = MIN_INTERVAL - (time.monotonic() - _last_request)
    if wait > 0:
        time.sleep(wait)

    headers = {"User-Agent": "TRACE-security-scanner/1.1"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    response = requests.get(
        f"{NVD_BASE}/{path}",
        params=params,
        headers=headers,
        timeout=20,
    )
    _last_request = time.monotonic()
    response.raise_for_status()
    return response.json()


def _cpe_version(cpe_name: str) -> str | None:
    """Read the version field from a CPE 2.3 name."""
    parts = cpe_name.split(":")
    if len(parts) != 13 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return parts[5]


def _normalize_cpe_token(value: str) -> str:
    """Normalize a detector value into a CPE 2.3 token candidate."""
    value = value.strip().lower().replace(" ", "_")
    return value.replace("/", "_")


def _cpe_vendor_aliases(vendor: str, product: str) -> list[str]:
    """Return common NVD vendor aliases for products whose CPE ownership changed."""
    vendor_n = _normalize_cpe_token(vendor)
    product_n = _normalize_cpe_token(product)
    aliases = [vendor_n]
    if product_n == "nginx":
        for alias in ("nginx", "f5"):
            if alias not in aliases:
                aliases.append(alias)
    return aliases


def _exact_cpe_names(vendor: str, product: str, version: str) -> list[str]:
    """Build exact CPE names directly, including the common historical 2.2 form."""
    names: list[str] = []
    for v in _cpe_vendor_aliases(vendor, product):
        names.append(f"cpe:2.3:a:{v}:{_normalize_cpe_token(product)}:{version}:*:*:*:*:*:*:*")
        names.append(f"cpe:/a:{v}:{_normalize_cpe_token(product)}:{version}")
    return names


def _cpe23_components(cpe_name: str) -> tuple[str, str, str, str] | None:
    parts = cpe_name.split(":")
    if len(parts) != 13 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return parts[2], parts[3], parts[4], parts[5]


def _cpe22_components(cpe_name: str) -> tuple[str, str, str, str] | None:
    # CPE 2.2: cpe:/a:vendor:product:version:...
    if not cpe_name.startswith("cpe:/"):
        return None
    raw = cpe_name[5:]
    parts = raw.split(":")
    if len(parts) < 4:
        return None
    return parts[0], parts[1], parts[2], parts[3]


def _cpe_matches_product(cpe_name: str, vendor: str, product: str) -> bool:
    parsed = _cpe23_components(cpe_name) or _cpe22_components(cpe_name)
    if not parsed:
        return False
    _, cpe_vendor, cpe_product, _ = parsed
    expected_vendors = {
        _normalize_cpe_token(alias)
        for alias in _cpe_vendor_aliases(vendor, product)
    }
    return (
        _normalize_cpe_token(cpe_vendor) in expected_vendors
        and _normalize_cpe_token(cpe_product) == _normalize_cpe_token(product)
    )


def _version_in_range(
    version: str,
    start_inc: str | None,
    start_exc: str | None,
    end_inc: str | None,
    end_exc: str | None,
) -> bool:
    """Compare versions conservatively, falling back to lexical ordering."""
    try:
        current = Version(version)
        if start_inc and current < Version(start_inc):
            return False
        if start_exc and current <= Version(start_exc):
            return False
        if end_inc and current > Version(end_inc):
            return False
        if end_exc and current >= Version(end_exc):
            return False
        return True
    except InvalidVersion:
        # NVD has ecosystem-specific versions such as r32, 1.29.0, etc.
        # A lexical fallback is better than silently discarding a candidate.
        current = version.lower()
        if start_inc and current < start_inc.lower():
            return False
        if start_exc and current <= start_exc.lower():
            return False
        if end_inc and current > end_inc.lower():
            return False
        if end_exc and current >= end_exc.lower():
            return False
        return True


def _extract_cpe_names(item: dict[str, Any]) -> list[str]:
    cpe = (item or {}).get("cpe") or {}
    names: list[str] = []
    for name_item in cpe.get("cpeName") or []:
        if isinstance(name_item, dict):
            name = name_item.get("cpeName") or name_item.get("cpe23Uri") or name_item.get("cpe22Uri")
        else:
            name = name_item
        if isinstance(name, str):
            names.append(name)
    return names


def cpe_candidates(vendor: str, product: str, version: str) -> list[str]:
    """Resolve exact CPEs, including deprecated/historical CPEs.

    NVD contains many older products as deprecated CPE 2.2 names. A strict
    modern CPE 2.3 lookup can therefore return no result even though the
    product/version has published CVEs. We ask for deprecated records too and
    keep both current and historical names.
    """
    vendor = _normalize_cpe_token(vendor)
    product = _normalize_cpe_token(product)
    version = version.strip()
    key = f"{vendor}|{product}|{version}|deprecated-v2"
    cache = _cache_path("cpe", key)
    cached = _read_cache(cache)
    if cached is not None:
        return cached

    candidates: set[str] = set()

    exact_match = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    try:
        data = _get(
            "cpes/2.0",
            {
                "cpeMatchString": exact_match,
                "includeDeprecated": "true",
                "resultsPerPage": 200,
            },
        )
        for item in data.get("products", []) or []:
            for name in _extract_cpe_names(item):
                if _cpe_matches_product(name, vendor, product):
                    parsed = _cpe23_components(name) or _cpe22_components(name)
                    if parsed and parsed[3] == version:
                        candidates.add(name)
    except requests.RequestException:
        pass

    # Explicitly ask NVD for the deprecated/current CPE family as a fallback.
    if not candidates:
        virtual = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"
        try:
            data = _get(
                "cpes/2.0",
                {
                    "virtualMatchString": virtual,
                    "includeDeprecated": "true",
                    "resultsPerPage": 2000,
                },
            )
            for item in data.get("products", []) or []:
                for name in _extract_cpe_names(item):
                    if not _cpe_matches_product(name, vendor, product):
                        continue
                    parsed = _cpe23_components(name) or _cpe22_components(name)
                    if parsed and parsed[3] == version:
                        candidates.add(name)
        except requests.RequestException:
            pass

    result = sorted(candidates)
    _write_cache(cache, result)
    return result


def _cve_applicability_matches(
    cve: dict[str, Any], vendor: str, product: str, version: str
) -> list[str]:
    """Evaluate NVD applicability recursively, including nested AND/OR nodes."""
    matched: list[str] = []
    configurations = cve.get("configurations") or []

    def walk(node: dict[str, Any]) -> None:
        if not isinstance(node, dict):
            return
        for cpe_match in node.get("cpeMatch") or []:
            criteria = cpe_match.get("criteria") or cpe_match.get("cpe23Uri") or cpe_match.get("cpe22Uri") or ""
            if not isinstance(criteria, str):
                continue
            if not _cpe_matches_product(criteria, vendor, product):
                continue

            parsed = _cpe23_components(criteria) or _cpe22_components(criteria)
            criteria_version = parsed[3] if parsed else None

            if criteria_version not in (None, "", "*", "-") and criteria_version != version:
                continue

            if not _version_in_range(
                version,
                cpe_match.get("versionStartIncluding"),
                cpe_match.get("versionStartExcluding"),
                cpe_match.get("versionEndIncluding"),
                cpe_match.get("versionEndExcluding"),
            ):
                continue

            if cpe_match.get("vulnerable", True):
                matched.append(criteria)

        for child in node.get("children") or []:
            walk(child)

    for config in configurations:
        for node in config.get("nodes") or []:
            walk(node)

    return sorted(set(matched))


def vulnerabilities_for_product(vendor: str, product: str, version: str) -> list[tuple[dict[str, Any], list[str]]]:
    """Find CVEs by exact CPE names plus family applicability.

    Exact CPE queries are attempted first because keywordSearch is not a reliable
    substitute for CPE matching: it can rank/restrict the result set by text and
    miss CVEs whose product identity is represented by historical vendor names.
    """
    vendor_n = _normalize_cpe_token(vendor)
    product_n = _normalize_cpe_token(product)
    version_n = version.strip()
    key = f"{vendor_n}|{product_n}|{version_n}|exact-and-family-v3"
    cache = _cache_path("product_cve", key)
    cached = _read_cache(cache)
    if cached is not None:
        return [(entry["vulnerability"], entry.get("cpe_matches", [])) for entry in cached]

    matched: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    def collect(raw: dict[str, Any], cpes: list[str]) -> None:
        cve = raw.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id or cve_id in seen_ids:
            return
        applicability = _cve_applicability_matches(cve, vendor_n, product_n, version_n)
        if applicability:
            seen_ids.add(cve_id)
            matched.append({"vulnerability": raw, "cpe_matches": sorted(set(cpes + applicability))})

    # 1) Ask the CVE API directly for the exact detected CPE names. This catches
    # products whose CPE dictionary entries are deprecated or remapped.
    for exact_cpe in _exact_cpe_names(vendor_n, product_n, version_n):
        for raw in vulnerabilities_for_cpe(exact_cpe):
            collect(raw, [exact_cpe])

    # 2) Search the product family under all known vendor aliases, then evaluate
    # applicability locally. This catches wildcard/range CPE match criteria.
    for vendor_alias in _cpe_vendor_aliases(vendor_n, product_n):
        keyword = f"{vendor_alias.replace('_', ' ')} {product_n.replace('_', ' ')}"
        start_index = 0
        max_pages = 10
        try:
            for _ in range(max_pages):
                data = _get(
                    "cves/2.0",
                    {
                        "keywordSearch": keyword,
                        "startIndex": start_index,
                        "resultsPerPage": 2000,
                    },
                )
                vulns = data.get("vulnerabilities", []) or []
                if not vulns:
                    break

                for vuln in vulns:
                    collect(vuln, [])

                total = int(data.get("totalResults") or 0)
                start_index += len(vulns)
                if start_index >= total:
                    break
        except requests.RequestException:
            continue

    _write_cache(cache, matched)
    return [(entry["vulnerability"], entry.get("cpe_matches", [])) for entry in matched]


def vulnerabilities_for_cpe(cpe_name: str) -> list[dict[str, Any]]:
    cache = _cache_path("cve", cpe_name)
    cached = _read_cache(cache)
    if cached is not None:
        return cached

    try:
        data = _get(
            "cves/2.0",
            {
                "cpeName": cpe_name,
                "resultsPerPage": 2000,
            },
        )
    except requests.RequestException:
        data = {"vulnerabilities": []}
    vulns = data.get("vulnerabilities", []) or []
    _write_cache(cache, vulns)
    return vulns

def _cvss(cve: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        metric = entries[0].get("cvssData") or {}
        return metric.get("baseScore"), metric.get("baseSeverity"), metric.get("vectorString")
    return None, None, None


def normalize_cve(vuln: dict[str, Any]) -> dict[str, Any]:
    cve = vuln.get("cve") or {}
    score, severity, vector = _cvss(cve)
    descriptions = cve.get("descriptions") or []
    description = next((x.get("value") for x in descriptions if x.get("lang") == "en"), "")
    weaknesses = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            if d.get("value"):
                weaknesses.append(d["value"])
    refs = [r.get("url") for r in cve.get("references") or [] if r.get("url")]
    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "description": description,
        "cvss": score,
        "severity": severity.lower() if isinstance(severity, str) else None,
        "vector": vector,
        "cwe": sorted(set(weaknesses)),
        "references": refs,
    }
