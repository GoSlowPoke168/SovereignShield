import json
from pathlib import Path

from . import config
from .vulnerability_fetcher import search_vulnerabilities

def load_json(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_text(path: str | Path) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def compute_sbom_diff(vendor: dict, deep_scan: dict) -> dict:
    """
    Compute the structural difference between the vendor-declared SBOM
    and the independently deep-scanned SBOM.
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

def cross_reference_cves(diff: dict) -> list[dict]:
    """
    Match every hidden dependency against the live ExploitDB database.
    """
    matches: list[dict] = []
    
    # Limit hidden deps to avoid hanging on massive files
    hidden_deps = diff.get("hidden_dependencies", [])[:config.MAX_HIDDEN_DEPS_FOR_QUERY]
    
    for dep in hidden_deps:
        # Prevent token limit exceptions for the LLM
        if len(matches) >= config.MAX_CVE_MATCHES:
            break
            
        package_name = dep["name"]
        version = dep["version"]
        
        # Use our live fetcher to check ExploitDB
        found_exploits = search_vulnerabilities(package_name, version)
        matches.extend(found_exploits)
        
    return matches
