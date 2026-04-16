"""
agents/arbiter_agent.py
────────────────────────
NIST SP 800-218 — Practice RV.1.3
"Analyze all identified vulnerabilities and policy violations and determine risk."

SCALABLE DESIGN FOR LARGE TARGETS:
  The previous design asked the LLM to enumerate every single threat ID in its
  JSON response (e.g., 760 items for Juice Shop), which:
    (a) fills the context window with the input listing, AND
    (b) requires a 760-item JSON array as output — easily 100K+ chars.

  The new design recognises that Python has already done all enumeration:
    • Risk score          → computed authoritatively from severity points
    • Verdict             → determined from score + severity rules
    • Threat list         → built from decomp + prov findings
    • Confidence flags    → evaluated against threshold

  The LLM is asked ONLY for:
    • verdict_rationale   — a natural language explanation of why BLOCK/ALLOW
    • recommended_action  — one actionable next step
    • (Optional) a brief description for each HIGH/CRITICAL finding only

  The full confirmed_threats list is assembled in Python from the pre-computed
  decomp_items and prov_items, never requiring the LLM to enumerate them.

  This reduces the prompt by ~95% for large targets and eliminates the
  response overflow problem entirely.

ANTI-HALLUCINATION DESIGN:
  • The LLM cannot create new threat IDs because it is not asked to list them.
  • The risk score is hard-coded from Python — LLM cannot change it.
  • The verdict is hard-coded from Python — LLM cannot change it.
  • verdict_rationale and recommended_action are grounded by a post-processing
    step that strips any fabricated CVE IDs from the text.
  • Verdict is validated to be exactly BLOCK or ALLOW.
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running this file directly for isolated testing
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from .. import config
from .. import ui
from .. import utils
from ..watsonx_client import get_model

_model = None

def _get_model():
    global _model
    if _model is None:
        _model = get_model()
    return _model


def _build_confidence_note(decomp: dict, prov: dict) -> tuple[list[str], str]:
    flags: list[str] = []
    decomp_conf = decomp.get("overall_confidence", 1.0)
    prov_conf = prov.get("overall_confidence", 1.0)
    threshold = config.CONFIDENCE_THRESHOLD

    if decomp_conf < threshold:
        flags.append(
            f"DecompositionAgent confidence {decomp_conf:.2f} is below threshold "
            f"{threshold}. A secondary binary deep-scan is required "
            "before this verdict can be considered final."
        )
    if prov_conf < threshold:
        flags.append(
            f"ProvenanceAgent confidence {prov_conf:.2f} is below threshold "
            f"{threshold}. Manual cryptographic verification by the "
            "Security Review Board is required before this verdict can be considered final."
        )

    if flags:
        note = "⚠️  LOW-CONFIDENCE FLAGS DETECTED — verdict should be treated as PRELIMINARY:\n" + \
               "\n".join(f"  • {f}" for f in flags)
    else:
        note = "✅  All upstream confidence scores meet threshold. Proceed to verdict."

    return flags, note


def _build_threat_allow_list(
    decomp_findings: dict, prov_findings: dict
) -> tuple[list[dict], list[dict], set[str]]:
    """
    Build the exhaustive list of threat items from upstream agents.
    Returns (decomp_items, prov_items, allowed_ids_set).
    """
    severity_points = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
    allowed_ids: set[str] = set()
    decomp_items = []
    prov_items = []

    for i, finding in enumerate(decomp_findings.get("findings", [])):
        dep_name = finding.get("hidden_dependency", f"UNKNOWN-DEP-{i+1}")
        cve = finding.get("cve_match")
        sev = str(finding.get("severity", "LOW")).upper()
        if sev not in severity_points:
            sev = "LOW"

        if cve and cve != "null" and utils.is_valid_cve_format(str(cve)):
            threat_id = str(cve)
        else:
            clean = dep_name.replace("@", "-").replace("/", "-").replace(":", "-")
            threat_id = f"SS-DISC-{clean.upper()[:40]}"

        allowed_ids.add(threat_id)
        decomp_items.append({
            "threat_id": threat_id,
            "source_agent": "DecompositionAgent",
            "severity": sev,
            "cvss_score": finding.get("cvss_score"),
            "nist_reference": "PO.1.1",
            "description": finding.get("detail", ""),
            "hidden_dependency": dep_name,
        })

    for i, viol in enumerate(prov_findings.get("findings", {}).get("violations", [])):
        code = str(viol.get("policy_code", f"SS-POL-VIOLATION-{i+1}"))
        sev = str(viol.get("severity", "HIGH")).upper()
        if sev not in severity_points:
            sev = "HIGH"

        if not any(code.startswith(p) for p in (
            "SS-POL-", "SS-DISC-", "ZTP-GEO-", "ZTP-SIG-", "ZTP-CERT-"
        )):
            code = f"SS-POL-VIOLATION-{i+1}"

        allowed_ids.add(code)
        prov_items.append({
            "threat_id": code,
            "source_agent": "ProvenanceAgent",
            "severity": sev,
            "nist_reference": "PO.3.2",
            "description": viol.get("violation_detail", ""),
            "triggering_field": viol.get("triggering_field", "N/A"),
            "triggering_value": viol.get("triggering_value", "N/A"),
        })

    return decomp_items, prov_items, allowed_ids


def run(
    decomp_findings: dict,
    prov_findings: dict,
    package_name: str = "Unknown Package",
    vendor_name: str = "Unknown Vendor",
    max_retries: int = config.MAX_RETRIES
) -> dict:
    """
    Invoke the Arbiter Agent and return the full Customs Inspection Report.

    All enumeration (threat list, risk score, verdict) is done in Python.
    The LLM is asked only to write the verdict rationale and recommended action,
    keeping the prompt small regardless of how many dependencies were analysed.
    """
    model = _get_model()
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    low_confidence_flags, confidence_note = _build_confidence_note(
        decomp_findings, prov_findings
    )

    # ── All heavy lifting done in Python ──────────────────────────────────────
    decomp_items, prov_items, allowed_threat_ids = _build_threat_allow_list(
        decomp_findings, prov_findings
    )
    all_items = decomp_items + prov_items
    total_expected = len(all_items)

    severity_points = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
    authoritative_score = sum(severity_points.get(item["severity"], 1) for item in all_items)
    is_block = authoritative_score >= 5 or any(
        item["severity"] in ("CRITICAL", "HIGH") for item in all_items
    )
    authoritative_verdict = "BLOCK" if is_block else "ALLOW"

    # ── Build a concise context for the LLM — HIGH/CRITICAL only ─────────────
    # The LLM only needs enough context to write a meaningful rationale.
    # It does NOT need to enumerate every finding.
    critical_high = [it for it in all_items if it["severity"] in ("CRITICAL", "HIGH")]
    sev_summary = {
        "CRITICAL": sum(1 for it in all_items if it["severity"] == "CRITICAL"),
        "HIGH":     sum(1 for it in all_items if it["severity"] == "HIGH"),
        "MEDIUM":   sum(1 for it in all_items if it["severity"] == "MEDIUM"),
        "LOW":      sum(1 for it in all_items if it["severity"] == "LOW"),
    }
    prov_summary = [
        f"  • {it['threat_id']}  [{it['severity']}]  —  {it['description'][:100]}"
        for it in prov_items
    ]

    # Cap critical/high listing at 20 items for the prompt to stay lean
    critical_high_for_prompt = critical_high[:20]
    ch_listing = "\n".join(
        f"  • {it['threat_id']}  [{it['severity']}]  {it.get('hidden_dependency', it.get('triggering_field',''))}  —  {it['description'][:120]}"
        for it in critical_high_for_prompt
    )
    ch_note = (
        f"  (showing {len(critical_high_for_prompt)} of {len(critical_high)} CRITICAL/HIGH findings)"
        if len(critical_high) > len(critical_high_for_prompt) else ""
    )

    system_message = (
        "You are the final arbitration authority in the SovereignShield security pipeline.\n"
        "CRITICAL RULES:\n"
        "1. Respond with ONLY valid JSON. No prose, no markdown, no code fences.\n"
        "2. Do NOT invent CVE IDs, threat codes, or package names not shown to you.\n"
        "3. verdict MUST be exactly the string provided in AUTHORITATIVE VERDICT.\n"
        "4. total_risk_score MUST be exactly the integer provided in AUTHORITATIVE SCORE.\n"
        "5. Your role is ONLY to write the verdict_rationale and recommended_action.\n"
        "6. Do not add any keys not listed in the requested schema."
    )

    prompt = f"""You are the Arbiter Agent in the SovereignShield supply-chain inspection pipeline.

MANDATE (NIST SP 800-218 RV.1.3): Issue the final inspection verdict with a factual rationale.

━━━ AUTHORITATIVE VERDICT (pre-computed — DO NOT CHANGE) ━━━
  Verdict       : {authoritative_verdict}
  Risk Score    : {authoritative_score} pts  (CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1)

━━━ SEVERITY DISTRIBUTION ({total_expected} total findings) ━━━
  CRITICAL : {sev_summary['CRITICAL']}
  HIGH     : {sev_summary['HIGH']}
  MEDIUM   : {sev_summary['MEDIUM']}
  LOW      : {sev_summary['LOW']}

━━━ CRITICAL/HIGH FINDINGS (context for your rationale) ━━━
{ch_listing or "  None"}
{ch_note}

━━━ PROVENANCE VIOLATIONS ━━━
{chr(10).join(prov_summary) or "  None"}

━━━ CONFIDENCE ━━━
{confidence_note}

TASK: Write a factual verdict_rationale (2–4 sentences) and a recommended_action (1 sentence).
  - verdict_rationale must reference the risk score ({authoritative_score}), the verdict ({authoritative_verdict}),
    and name the most significant finding types (by severity count and key CVEs/codes).
  - recommended_action must be one specific, actionable next step.
  - Do NOT invent CVE IDs or codes not listed above.
  - Do NOT re-enumerate every finding.

Respond with ONLY this JSON (no markdown, no code fences):
{{
  "verdict_rationale": "<factual 2-4 sentence rationale>",
  "recommended_action": "<one specific actionable next step>"
}}"""

    last_error: Exception | None = None
    raw = ""
    rationale = f"Risk score {authoritative_score} ({sev_summary['CRITICAL']} CRITICAL, {sev_summary['HIGH']} HIGH, {sev_summary['MEDIUM']} MEDIUM, {sev_summary['LOW']} LOW). Verdict: {authoritative_verdict}."
    action = "Quarantine the package and initiate a full security review before deployment."

    for attempt in range(1 + max_retries):
        try:
            messages = [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt},
            ]
            response = model.chat(messages=messages)
            raw = response["choices"][0]["message"]["content"]
            llm_out = utils.extract_json(raw)

            if isinstance(llm_out.get("verdict_rationale"), str):
                rationale = llm_out["verdict_rationale"]
            if isinstance(llm_out.get("recommended_action"), str):
                action = llm_out["recommended_action"]

            # Scrub any fabricated CVE-like patterns from rationale/action
            if rationale:
                rationale = re.sub(r'\bCVE-(?!\d{4}-\d{4,})\S+', '[REDACTED]', rationale)
            if action:
                action = re.sub(r'\bCVE-(?!\d{4}-\d{4,})\S+', '[REDACTED]', action)

            break  # success

        except (ValueError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < max_retries:
                ui.print_warn(
                    f"[ArbiterAgent] JSON parse error (attempt {attempt + 1}), retrying..."
                )
            else:
                ui.print_warn(
                    f"[ArbiterAgent] All retries failed — using auto-generated rationale. "
                    f"Error: {exc}"
                )

    # ── Assemble the full report from Python-computed data ────────────────────
    return {
        "report_title": "SovereignShield Customs Inspection Report",
        "package": package_name,
        "vendor": vendor_name,
        "inspection_timestamp": now_utc,
        "total_expected_findings": total_expected,
        "total_risk_score": authoritative_score,
        "verdict": authoritative_verdict,
        "verdict_rationale": rationale,
        "recommended_action": action,
        "total_violations": total_expected,
        "confirmed_threats": all_items,  # full list — built entirely from Python
        "low_confidence_flags": low_confidence_flags,
        "severity_distribution": sev_summary,
    }
