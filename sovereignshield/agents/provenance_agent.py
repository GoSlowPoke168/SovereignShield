"""
agents/provenance_agent.py
───────────────────────────
NIST SP 800-218 — Practice PO.3.2
"Verify the provenance and integrity of third-party components."

This agent reads the software update metadata (compile origin, timestamps,
digital signature hashes, code signing certificate status) and cross-
references it against the plain-text Zero-Trust geographic routing policy.

It identifies every violated policy clause by code (ZTP-GEO-XXX), assigns
severity to each violation, and returns a confidence-scored compliance verdict.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from watsonx_client import get_model

_model = None


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


def run(metadata: dict, policy: str, max_retries: int = 2) -> dict:
    """
    Invoke the Provenance Agent and return its compliance verdict.

    Parameters
    ----------
    metadata    : Contents of update_metadata.json
    policy      : Full text of zero_trust_policy.txt
    max_retries : Additional attempts on JSON parse failure.

    Returns
    -------
    Parsed agent findings dict.
    """
    model = _get_model()

    prompt = f"""You are the Provenance Agent in the SovereignShield automated supply-chain inspection pipeline.

MANDATE (NIST SP 800-218 Practice PO.3.2): Verify the provenance and integrity of all third-party software components.

━━━ SOFTWARE UPDATE METADATA ━━━
{json.dumps(metadata, indent=2)}

━━━ ZERO-TRUST GEOGRAPHIC ROUTING POLICY ━━━
{policy}

TASK:
1. Read every field in the metadata carefully.
2. Compare each field against EVERY policy clause (ZTP-GEO-001 through ZTP-GEO-006).
3. For each violated clause, record the exact policy code and the specific metadata field that triggered it.
4. Determine signature status: VERIFIED / UNVERIFIED / MISMATCH.
5. Determine certificate status: VALID / EXPIRED / MISSING.

SCORING RULES:
- Confidence 0.90–1.0 : Explicit hash mismatches, expired certs, or known-restricted compile origin confirmed.
- Confidence 0.75–0.89: Geographic violations only (no hash or cert issues found).
- Confidence below 0.75: Ambiguous or contradictory metadata.

Respond with ONLY valid JSON — no prose, no markdown fences — in this exact schema:
{{
  "agent": "ProvenanceAgent",
  "findings": {{
    "compile_origin": "<value from metadata>",
    "violations": [
      {{
        "policy_code": "<ZTP-GEO-XXX>",
        "triggering_field": "<metadata field name>",
        "triggering_value": "<metadata field value>",
        "violation_detail": "<specific explanation of what was violated>",
        "severity": "<CRITICAL|HIGH|MEDIUM>"
      }}
    ],
    "signature_status": "<VERIFIED|UNVERIFIED|MISMATCH>",
    "cert_status": "<VALID|EXPIRED|MISSING>",
    "confidence": <float 0.0–1.0>,
    "summary": "<two sentences: overall provenance assessment>"
  }},
  "overall_confidence": <float 0.0–1.0>
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
            return _extract_json(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < max_retries:
                print(f"  [ProvenanceAgent] JSON parse error (attempt {attempt + 1}), retrying...")

    raise RuntimeError(
        f"ProvenanceAgent failed to return valid JSON after {1 + max_retries} attempts. "
        f"Last error: {last_error}"
    )
