import json
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
        _model = get_model()  # uses DEFAULT_MODEL from watsonx_client
    return _model


def _build_confidence_note(decomp: dict, prov: dict) -> tuple[list[str], str]:
    """
    Evaluate upstream confidence scores and build the feedback-loop note
    that is injected into the Arbiter's prompt.
    """
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


def run(decomp_findings: dict, prov_findings: dict, package_name: str = "Unknown Package", vendor_name: str = "Unknown Vendor", max_retries: int = config.MAX_RETRIES) -> dict:
    """
    Invoke the Arbiter Agent and return the full Customs Inspection Report.
    """
    model = _get_model()
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    low_confidence_flags, confidence_note = _build_confidence_note(
        decomp_findings, prov_findings
    )

    d_count = len(decomp_findings.get("findings", []))
    p_violations = prov_findings.get("findings", {}).get("violations", [])
    p_count = len(p_violations)
    
    total_expected = d_count + p_count

    prompt = f"""You are the Arbiter Agent — the final authority — in the SovereignShield automated supply-chain inspection pipeline.

MANDATE (NIST SP 800-218 Practice RV.1.3): Analyze all identified vulnerabilities and policy violations to determine risk and issue the definitive response.

━━━ INPUT DATA ━━━
DECOMPOSITION FINDINGS ({d_count} items):
{json.dumps(decomp_findings, indent=2)}

PROVENANCE VIOLATIONS ({p_count} items):
{json.dumps(prov_findings, indent=2)}

━━━ CONFIDENCE ASSESSMENT ━━━
{confidence_note}

STRICT OPERATIONAL RULES:
1. **ABSOLUTE ITEMIZATION**: There are EXACTLY {total_expected} unique finding objects in the data above. You MUST produce EXACTLY {total_expected} entries in your `confirmed_threats` list.
2. **NO SUMMARIZATION**: Every discrepancy from Decomposition and every violation from Provenance must be its own standalone record. Grouping is FORBIDDEN.
3. **ZERO HALLUCINATION**: Use only IDs from the input or the standardized prefixes (`CVE-`, `SS-DISC-`, `SS-POL-`).
4. **THOROUGHNESS**: Provide a specific justification for every single item.

WEIGHTED RISK SCORING:
- CRITICAL severity finding         : 10 points
- HIGH severity / Policy violation  : 5 points
- MEDIUM severity finding           : 2 points
- LOW severity / DISC finding       : 1 point

Respond with ONLY valid JSON — no prose, no markdown — in this exact schema:
{{
  "report_title": "SovereignShield Customs Inspection Report",
  "package": "{package_name}",
  "vendor": "{vendor_name}",
  "inspection_timestamp": "{now_utc}",
  "total_expected_findings": {total_expected},
  "total_risk_score": <calculated integer sum>,
  "confirmed_threats": [
    {{
      "threat_id": "<SS-DISC-..., SS-POL-..., or CVE-...>",
      "source_agent": "<DecompositionAgent|ProvenanceAgent>",
      "description": "<specific justification for this item>",
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "nist_reference": "<PO.1.1|PO.3.2|RV.1.3>"
    }}
  ],
  "total_violations": <integer count equal to total_expected_findings>,
  "verdict": "<BLOCK|ALLOW>",
  "verdict_rationale": "<thorough risk breakdown citing the itemized score summation>",
  "recommended_action": "<one specific actionable next step>"
}}"""

    last_error: Exception | None = None
    raw = ""
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
            result = utils.extract_json(raw)
            # Ensure the pre-computed flags are preserved even if the model omits them
            if not result.get("low_confidence_flags"):
                result["low_confidence_flags"] = low_confidence_flags
            return result
        except (ValueError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < max_retries:
                ui.print_warn(f"[ArbiterAgent] JSON parse error (attempt {attempt + 1}), retrying...")

    ui.print_error(f"[ArbiterAgent] RAW MODEL RESPONSE:\n{raw[:2000]}")
    raise RuntimeError(
        f"ArbiterAgent failed to return valid JSON after {1 + max_retries} attempts. "
        f"Last error: {last_error}"
    )
