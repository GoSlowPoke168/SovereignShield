"""
preprocessor.py
───────────────
Pure-Python data preparation layer.

All heavy lifting (parsing, diffing, CVE cross-referencing) happens here
BEFORE any LLM call.  This keeps the prompts short, factual, and token-efficient:
the agent's prompt contains only the computed findings, never raw JSON blobs.
"""

import json
from pathlib import Path

from .vulnerability_fetcher import search_vulnerabilities


# ── I/O helpers ────────────────────────────────────────────────────────────────

def load_json(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_text(path: str | Path) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ── SBOM diff ──────────────────────────────────────────────────────────────────

def compute_sbom_diff(vendor: dict, deep_scan: dict) -> dict:
    """
    Compute the structural difference between the vendor-declared SBOM
    and the independently deep-scanned SBOM.

    Returns a structured summary rather than raw sets so that the LLM
    prompt stays small and the logic stays in Python (not in the model).
    """
    vendor_deps: dict[str, str] = {
        d["name"]: d["version"]
        for d in vendor["declared_dependencies"]
    }
    scan_deps: dict[str, str] = {
        d["name"]: d["version"]
        for d in deep_scan["detected_dependencies"]
    }

    hidden = {
        name: ver
        for name, ver in scan_deps.items()
        if name not in vendor_deps
    }

    # Version drift: declared but with a different version than scanned
    version_drift = {
        name: {"declared": vendor_deps[name], "scanned": scan_deps[name]}
        for name in vendor_deps
        if name in scan_deps and vendor_deps[name] != scan_deps[name]
    }

    return {
        "total_vendor_declared": len(vendor_deps),
        "total_scan_detected": len(scan_deps),
        "hidden_dependencies": [
            {"name": name, "version": ver}
            for name, ver in hidden.items()
        ],
        "hidden_count": len(hidden),
        "version_drift": [
            {"name": name, **versions}
            for name, versions in version_drift.items()
        ],
        "version_drift_count": len(version_drift),
    }


# ── CVE cross-reference ────────────────────────────────────────────────────────

def cross_reference_cves(diff: dict) -> list[dict]:
    """
    Match every hidden dependency against the live ExploitDB database.
    """
    matches: list[dict] = []
    
    # Limit to first 50 dependencies to avoid hanging on massive files (e.g. 500MB Jars)
    hidden_deps = diff.get("hidden_dependencies", [])[:50]
    
    for dep in hidden_deps:
        # Prevent token limit exceptions for the LLM
        if len(matches) >= 10:
            break
            
        package_name = dep["name"]
        version = dep["version"]
        
        # Use our live fetcher to check ExploitDB
        found_exploits = search_vulnerabilities(package_name, version)
        matches.extend(found_exploits)
        
    return matches
