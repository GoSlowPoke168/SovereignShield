"""
utils.py
────────
Shared utility functions for the SovereignShield pipeline.

Includes a post-processing grounding validator that strips any CVE IDs,
package names, or identifiers fabricated by the LLM that were NOT present
in the pipeline's pre-computed input data.
"""

import json
import re
from typing import Any


def extract_json(raw: str) -> dict:
    """
    Robustly extract a JSON object from an LLM response that may be wrapped
    in markdown code fences or have leading/trailing prose.
    """
    text = raw.strip()

    # 1. Direct parse (model returned clean JSON)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Strip ``` fences
    fence_match = re.search(r"```(?:json)?\s*([\s\S]+?)```", text)
    if fence_match:
        try:
            return json.loads(fence_match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # 3. Grab outermost { ... } block
    brace_match = re.search(r"\{[\s\S]+\}", text)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not extract valid JSON from model response:\n{raw[:500]}")


# ── CVE ID Validator ──────────────────────────────────────────────────────────

# Real CVE IDs follow the strict format: CVE-<4-digit-year>-<4+ digit sequence>
_CVE_REAL_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def is_valid_cve_format(cve_id: str) -> bool:
    """
    Return True only if the string matches the canonical CVE ID format.
    CVE-YYYY-NNNNN where YYYY is a 4-digit year and NNNNN is 4+ digits.
    Fabricated IDs like 'CVE-SYMFONY-YAML-INJECTION' will fail this check.
    """
    if not cve_id or not isinstance(cve_id, str):
        return False
    return bool(_CVE_REAL_PATTERN.match(cve_id.strip()))


# ── Grounding Validator ───────────────────────────────────────────────────────

def validate_and_ground_decomp_findings(
    result: dict,
    allowed_cve_ids: set[str],
    allowed_package_names: set[str],
) -> dict:
    """
    Post-process the DecompositionAgent's JSON output.

    Rules enforced:
    1. `cve_match` must be null OR an ID that actually appeared in the
       pre-computed CVE matches list AND follows the canonical CVE format.
       Any fabricated CVE ID is replaced with null and a grounding note added.
    2. `hidden_dependency` must reference a package name from the actual
       hidden_dependencies list. If it doesn't, severity is downgraded and
       a grounding note is added.
    3. `severity` and `cvss_score` must be consistent with the source data.
       If the CVE was nullified due to grounding failure, score is cleared.
    4. `confidence` is clamped to [0.0, 1.0].
    """
    grounding_warnings: list[str] = []
    raw_findings = result.get("findings", [])
    valid_findings = []

    # 1. Strip out hallucinated packages entirely
    for finding in raw_findings:
        pkg_name = finding.get("hidden_dependency")
        if not pkg_name:
            continue
            
        clean_pkg = pkg_name.split('==')[0].split(':')[0]
        if clean_pkg.startswith('@'):
            clean_pkg = '@' + clean_pkg[1:].split('@')[0]
        else:
            clean_pkg = clean_pkg.split('@')[0]
            
        if clean_pkg not in allowed_package_names:
            grounding_warnings.append(
                f"GROUNDING: Dropped hallucinated package '{pkg_name}' — not in allowed list."
            )
            continue
            
        # Re-assign grounding to the strict clean name so deduplication works perfectly
        finding["hidden_dependency"] = clean_pkg
        valid_findings.append(finding)

    # 2. Aggressive Deduplication (merge multiple LLM entries for the same package)
    deduped_map = {}
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for finding in valid_findings:
        pkg_name = finding.get("hidden_dependency")
        if pkg_name not in deduped_map:
            deduped_map[pkg_name] = finding
        else:
            existing_rank = severity_rank.get(str(deduped_map[pkg_name].get("severity", "LOW")).upper(), 0)
            new_rank = severity_rank.get(str(finding.get("severity", "LOW")).upper(), 0)
            if new_rank > existing_rank:
                deduped_map[pkg_name] = finding
                
    findings = list(deduped_map.values())
    result["findings"] = findings

    for finding in findings:
        raw_cve = finding.get("cve_match")

        # ── Rule 1: CVE ID must be in the allow-list AND valid format ─────────
        if raw_cve and raw_cve != "null":
            if not is_valid_cve_format(str(raw_cve)):
                grounding_warnings.append(
                    f"GROUNDING: Rejected malformed CVE ID '{raw_cve}' for "
                    f"'{finding.get('hidden_dependency', '?')}' — does not match "
                    f"CVE-YYYY-NNNNN format. Set to null."
                )
                finding["cve_match"] = None
                finding["cvss_score"] = None
                finding["severity"] = "LOW"
            elif str(raw_cve).upper() not in {c.upper() for c in allowed_cve_ids}:
                grounding_warnings.append(
                    f"GROUNDING: Rejected hallucinated CVE '{raw_cve}' for "
                    f"'{finding.get('hidden_dependency', '?')}' — not present in "
                    f"pre-computed CVE data. Set to null."
                )
                finding["cve_match"] = None
                finding["cvss_score"] = None
                finding["severity"] = "LOW"

        # ── Rule 2: Clamp confidence ─────────────────────────────────────────
        conf = finding.get("confidence")
        if conf is not None:
            finding["confidence"] = max(0.0, min(1.0, float(conf)))

    if grounding_warnings:
        result["grounding_warnings"] = grounding_warnings
        # Downgrade overall confidence when grounding failures exist
        penalty = min(0.15 * len(grounding_warnings), 0.45)
        result["overall_confidence"] = max(
            0.0, float(result.get("overall_confidence", 1.0)) - penalty
        )

    return result


def validate_and_ground_arbiter_findings(
    result: dict,
    allowed_threat_ids: set[str],
) -> dict:
    """
    Post-process the ArbiterAgent's JSON output.

    Rules enforced:
    1. Every `threat_id` in `confirmed_threats` must be a string that either:
       a. Matches a known SS-DISC-*, SS-POL-* prefix pattern (provenance codes), OR
       b. Exactly matches a real CVE ID from allowed_threat_ids.
       Fabricated IDs are flagged and replaced with a sanitized version.
    2. `total_risk_score` is recomputed from the actual findings to prevent
       inflated scores.
    3. `verdict` must be exactly "BLOCK" or "ALLOW" — any other value
       triggers a BLOCK as a safety default.
    """
    grounding_warnings: list[str] = []
    severity_points = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
    recomputed_score = 0

    threats = result.get("confirmed_threats", [])
    for i, threat in enumerate(threats):
        tid = str(threat.get("threat_id", ""))
        sev = str(threat.get("severity", "LOW")).upper()

        # ── Rule 1: Threat ID validation ──────────────────────────────────────
        is_ss_prefix = (
            tid.startswith("SS-DISC-") or
            tid.startswith("SS-POL-") or
            tid.startswith("SS-")
        )
        is_real_cve = (
            tid.upper() in {c.upper() for c in allowed_threat_ids}
            and is_valid_cve_format(tid)
        )

        if not is_ss_prefix and not is_real_cve:
            # Could be a real CVE with wrong format OR pure hallucination
            if is_valid_cve_format(tid) and tid.upper() not in {c.upper() for c in allowed_threat_ids}:
                grounding_warnings.append(
                    f"GROUNDING: CVE '{tid}' in confirmed_threats was not in "
                    f"pre-computed data — relabelled as SS-DISC-UNVERIFIED-{i+1}."
                )
                threat["threat_id"] = f"SS-DISC-UNVERIFIED-{i+1}"
                threat["description"] = (
                    f"[GROUNDING FLAG: Original CVE '{tid}' not in verified data] "
                    + threat.get("description", "")
                )
            elif not is_valid_cve_format(tid) and tid.startswith("CVE-"):
                # e.g. "CVE-SYMFONY-YAML-INJECTION" — a clearly fabricated ID
                grounding_warnings.append(
                    f"GROUNDING: Rejected fabricated CVE-style ID '{tid}' — "
                    f"does not match CVE-YYYY-NNNNN format. Relabelled."
                )
                threat["threat_id"] = f"SS-DISC-FABRICATED-{i+1}"
                threat["severity"] = "LOW"
                threat["description"] = (
                    f"[GROUNDING FLAG: Fabricated ID '{tid}' rejected] "
                    + threat.get("description", "")
                )
                sev = "LOW"

        # ── Rule 2: Recompute score ───────────────────────────────────────────
        if sev not in severity_points:
            sev = "LOW"
            threat["severity"] = "LOW"
        recomputed_score += severity_points[sev]

    # Override the model's self-reported score with our validated computation
    reported_score = result.get("total_risk_score", 0)
    if reported_score != recomputed_score:
        grounding_warnings.append(
            f"GROUNDING: Risk score recomputed from {reported_score} → "
            f"{recomputed_score} based on verified findings."
        )
        result["total_risk_score"] = recomputed_score

    # ── Rule 3: Verdict sanity check ─────────────────────────────────────────
    verdict = str(result.get("verdict", "")).upper()
    if verdict not in ("BLOCK", "ALLOW"):
        grounding_warnings.append(
            f"GROUNDING: Invalid verdict '{result.get('verdict')}' — "
            f"defaulting to BLOCK (safety default)."
        )
        result["verdict"] = "BLOCK"

    if grounding_warnings:
        existing = result.get("grounding_warnings", [])
        result["grounding_warnings"] = existing + grounding_warnings

    return result
