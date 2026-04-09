"""
agents/arbiter_agent.py
────────────────────────
NIST SP 800-218 — Practice RV.1.3
"Analyze identified vulnerabilities to determine risk and appropriate response."

The Arbiter is the final authority in the SovereignShield pipeline.
It synthesises the exact output of the Decomposition and Provenance agents,
applies the confidence-threshold feedback loop (a genuine agentic decision
rather than a fixed sequential pipeline), and issues the definitive
BLOCK or ALLOW command.
    real conditional reasoning and is highlighted in the terminal output.
  • The LLM prompt explicitly passes these flags so it can justify them
    in the verdict rationale.
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from watsonx_client import get_model

_model = None
CONFIDENCE_THRESHOLD = 0.75


def _get_model():
    global _model
    if _model is None:
        _model = get_model()  # uses DEFAULT_MODEL from watsonx_client
    return _model


def _extract_json(raw: str) -> dict:
    text = raw.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    fence_match = re.search(r"```(?:json)?\s*([\s\S]+?)```", text)
    if fence_match:
        try:
            return json.loads(fence_match.group(1).strip())
        except json.JSONDecodeError:
            pass
    brace_match = re.search(r"\{[\s\S]+\}", text)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass
    raise ValueError(f"Could not extract valid JSON from model response:\n{raw[:500]}")


def _build_confidence_note(decomp: dict, prov: dict) -> tuple[list[str], str]:
    """
    Evaluate upstream confidence scores and build the feedback-loop note
    that is injected into the Arbiter's prompt.

    Returns (flags_list, formatted_note_string).
    """
    flags: list[str] = []
    decomp_conf = decomp.get("overall_confidence", 1.0)
    prov_conf = prov.get("overall_confidence", 1.0)

    if decomp_conf < CONFIDENCE_THRESHOLD:
        flags.append(
            f"DecompositionAgent confidence {decomp_conf:.2f} is below threshold "
            f"{CONFIDENCE_THRESHOLD}. A secondary binary deep-scan is required "
            "before this verdict can be considered final."
        )
    if prov_conf < CONFIDENCE_THRESHOLD:
        flags.append(
            f"ProvenanceAgent confidence {prov_conf:.2f} is below threshold "
            f"{CONFIDENCE_THRESHOLD}. Manual cryptographic verification by the "
            "Security Review Board is required before this verdict can be considered final."
        )

    if flags:
        note = "⚠️  LOW-CONFIDENCE FLAGS DETECTED — verdict should be treated as PRELIMINARY:\n" + \
               "\n".join(f"  • {f}" for f in flags)
    else:
        note = "✅  All upstream confidence scores meet threshold. Proceed to verdict."

    return flags, note


def run(decomp_findings: dict, prov_findings: dict, package_name: str = "Unknown Package", vendor_name: str = "Unknown Vendor", max_retries: int = 2) -> dict:
    """
    Invoke the Arbiter Agent and return the full Customs Inspection Report.

    Parameters
    ----------
    decomp_findings : Output of decomposition_agent.run()
    prov_findings   : Output of provenance_agent.run()
    max_retries     : Additional attempts on JSON parse failure.

    Returns
    -------
    Parsed arbiter report dict.
    """
    model = _get_model()
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    low_confidence_flags, confidence_note = _build_confidence_note(
        decomp_findings, prov_findings
    )

    prompt = f"""You are the Arbiter Agent — the final authority — in the SovereignShield automated supply-chain inspection pipeline.

MANDATE (NIST SP 800-218 Practice RV.1.3): Analyze all identified vulnerabilities and policy violations to determine risk and issue the definitive response.

━━━ DECOMPOSITION AGENT FINDINGS ━━━
{json.dumps(decomp_findings, indent=2)}

━━━ PROVENANCE AGENT FINDINGS ━━━
{json.dumps(prov_findings, indent=2)}

━━━ CONFIDENCE ASSESSMENT (AGENTIC FEEDBACK LOOP) ━━━
{confidence_note}

VERDICT RULES (apply strictly in this priority order):
1. BLOCK if any confirmed threat has CRITICAL severity.
2. BLOCK if total confirmed threats + policy violations >= 2.
3. BLOCK if any low-confidence flag is present (preliminary verdict required).
4. BLOCK if signature_status is MISMATCH or cert_status is EXPIRED.
5. ALLOW only if: zero CRITICAL findings, zero policy violations, all confidence above threshold, valid signature, valid cert.

CRITICAL INSTRUCTION: You MUST compile EVERY SINGLE vulnerability, discrepancy, and policy violation found by the Decomposition Agent and Provenance Agent into your `confirmed_threats` array. Do NOT skip or filter out "LOW" or "MEDIUM" severity vulnerabilities; log all of them!

Current UTC timestamp: {now_utc}

Respond with ONLY valid JSON — no prose, no markdown fences — in this exact schema:
{{
  "report_title": "SovereignShield Customs Inspection Report",
  "package": "{package_name}",
  "vendor": "{vendor_name}",
  "inspection_timestamp": "{now_utc}",
  "confirmed_threats": [
    {{
      "threat_id": "<USE EXACT CVE ID (e.g., CVE-2021-3807) OR EXACT POLICY CODE (e.g. SIG-MISMATCH). DO NOT USE T-XXX>",
      "source_agent": "<DecompositionAgent|ProvenanceAgent>",
      "description": "<clear, concise threat description>",
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "nist_reference": "<NIST SP 800-218 practice code, e.g. PO.1.1>"
    }}
  ],
  "low_confidence_flags": {json.dumps(low_confidence_flags)},
  "total_violations": <integer — count of confirmed_threats>,
  "verdict": "<BLOCK|ALLOW>",
  "verdict_rationale": "<two to three sentences explaining exactly why this verdict was reached, citing specific threat IDs and policy codes>",
  "recommended_action": "<one specific, actionable next step for the security team>"
}}"""

    last_error: Exception | None = None
    for attempt in range(1 + max_retries):
        try:
            messages = [
                {
                    "role": "system",
                    "content": "You are a security analysis agent. You MUST respond with ONLY valid JSON. No prose, no markdown, no explanations — raw JSON only."
                },
                {"role": "user", "content": prompt}
            ]
            response = model.chat(messages=messages)
            raw = response["choices"][0]["message"]["content"]
            result = _extract_json(raw)
            # Ensure the pre-computed flags are preserved even if the model omits them
            if not result.get("low_confidence_flags"):
                result["low_confidence_flags"] = low_confidence_flags
            return result
        except (ValueError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < max_retries:
                print(f"  [ArbiterAgent] JSON parse error (attempt {attempt + 1}), retrying...")

    raise RuntimeError(
        f"ArbiterAgent failed to return valid JSON after {1 + max_retries} attempts. "
        f"Last error: {last_error}"
    )
