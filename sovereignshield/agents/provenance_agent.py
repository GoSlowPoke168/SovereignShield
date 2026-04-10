import json
import sys
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


def run(metadata: dict, policy: str, max_retries: int = config.MAX_RETRIES) -> dict:
    """
    Invoke the Provenance Agent and return its compliance verdict.
    """
    model = _get_model()

    prompt = f"""You are the Provenance Agent in the SovereignShield automated supply-chain inspection pipeline.

MANDATE (NIST SP 800-218 Practice PO.3.2): Verify the provenance and integrity of all third-party software components.

━━━ SOFTWARE UPDATE METADATA ━━━
{json.dumps(metadata, indent=2)}

━━━ ZERO-TRUST GEOGRAPHIC ROUTING POLICY ━━━
{policy}

TASK:
1. Compare every metadata field against EVERY ZTP-GEO policy clause.
2. **MISSING DATA IS A VIOLATION**: If metadata is empty or missing, you MUST record violations for `SS-POL-SIG-UNVERIFIED` and `SS-POL-CERT-MISSING`.
3. **MANDATORY ITEMIZATION**: Report Signature status, Certificate status, and Origin violations as SEPARATE objects in the `violations` array.
4. **DO NOT SUMMARIZE**: Each issue must be its own record. 
5. If metadata is provided but the signature field is missing/invalid, log a violation.

Respond with ONLY valid JSON — no prose, no markdown — in this exact schema:
{{
  "agent": "ProvenanceAgent",
  "findings": {{
    "compile_origin": "<value or 'UNKNOWN'>",
    "violations": [
      {{
        "policy_code": "<SS-POL-SIG-UNVERIFIED|SS-POL-CERT-MISSING|ZTP-GEO-XXX>",
        "triggering_field": "<field name>",
        "triggering_value": "<field value>",
        "violation_detail": "<specific explanation>",
        "severity": "<CRITICAL|HIGH|MEDIUM>"
      }}
    ],
    "signature_status": "<VERIFIED|UNVERIFIED|MISMATCH>",
    "cert_status": "<VALID|EXPIRED|MISSING>",
    "confidence": <float 0.0–1.0>,
    "summary": "<two sentences assessment>"
  }},
  "overall_confidence": <float 0.0–1.0>
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
            return utils.extract_json(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < max_retries:
                ui.print_warn(f"[ProvenanceAgent] JSON parse error (attempt {attempt + 1}), retrying...")

    ui.print_error(f"[ProvenanceAgent] RAW MODEL RESPONSE:\n{raw[:2000]}")
    raise RuntimeError(
        f"ProvenanceAgent failed to return valid JSON after {1 + max_retries} attempts. "
        f"Last error: {last_error}"
    )
