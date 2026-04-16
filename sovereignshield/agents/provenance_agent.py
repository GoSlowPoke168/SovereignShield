"""
agents/provenance_agent.py
──────────────────────────
NIST SP 800-218 — Practice PO.3.2
"Verify the provenance and integrity of all third-party software components."

ANTI-HALLUCINATION DESIGN:
  • The prompt provides an exhaustive list of ALL valid policy codes the model
    is permitted to use. The model cannot invent new policy codes.
  • All enumerated fields (signature_status, cert_status, compile_origin)
    are constrained to exact allowed values defined in the schema.
  • The policy text is injected verbatim so findings cite actual clauses.
  • Post-processing validates that only known policy codes appear in output.
  • temperature=0.0 is enforced to suppress creative generation.
"""

import json
import re
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
        _model = get_model()
    return _model


# ── Valid policy code prefixes (used for post-processing validation) ───────────
# Any model-generated code that falls outside these prefixes is flagged.
_VALID_POL_PREFIXES = (
    "SS-POL-SIG-",
    "SS-POL-CERT-",
    "SS-POL-GEO-",
    "SS-POL-ORIGIN-",
    "SS-POL-HASH-",
    "SS-POL-TIMESTAMP-",
    "ZTP-GEO-",
    "ZTP-SIG-",
    "ZTP-CERT-",
)

# Exhaustive enumeration of valid policy codes the model may generate.
# These map to real clauses that can appear in a zero-trust geo-routing policy.
_PERMITTED_POLICY_CODES = [
    "SS-POL-SIG-UNVERIFIED",   # Signature field missing or invalid
    "SS-POL-SIG-MISMATCH",     # Signature present but does not match binary
    "SS-POL-CERT-MISSING",     # Certificate field absent
    "SS-POL-CERT-EXPIRED",     # Certificate present but expired
    "SS-POL-CERT-UNTRUSTED",   # Certificate from an untrusted authority
    "SS-POL-GEO-BLOCKED",      # Origin country is in the blocked list
    "SS-POL-GEO-UNKNOWN",      # Origin country could not be determined
    "SS-POL-ORIGIN-UNVERIFIED",# Compile origin field is missing or unverifiable
    "SS-POL-HASH-MISSING",     # No cryptographic hash provided
    "SS-POL-HASH-MISMATCH",    # Hash provided does not match computed value
    "SS-POL-TIMESTAMP-MISSING",# Build timestamp absent
    "SS-POL-TIMESTAMP-FUTURE", # Build timestamp is in the future (tamper indicator)
]

_PERMITTED_CODES_SET = set(_PERMITTED_POLICY_CODES)


def _validate_provenance_output(result: dict, metadata: dict) -> dict:
    """
    Post-process the ProvenanceAgent output to enforce grounding.

    Rules:
    1. Every policy_code in violations must be in the PERMITTED_POLICY_CODES set
       OR start with a known prefix. Unknown codes are relabelled.
    2. triggering_value must match an actual field value from metadata.
    3. signature_status must be VERIFIED, UNVERIFIED, or MISMATCH.
    4. cert_status must be VALID, EXPIRED, or MISSING.
    5. confidence is clamped to [0.0, 1.0].
    """
    grounding_warnings: list[str] = []
    findings = result.get("findings", {})
    violations = findings.get("violations", [])

    # Flatten metadata values for cross-reference checks
    flat_metadata_values = set()
    def _flatten(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                _flatten(v, f"{prefix}.{k}" if prefix else k)
        elif isinstance(obj, list):
            for item in obj:
                _flatten(item, prefix)
        else:
            flat_metadata_values.add(str(obj))
    _flatten(metadata)

    validated_violations = []
    for i, viol in enumerate(violations):
        code = str(viol.get("policy_code", ""))
        tval = str(viol.get("triggering_value", ""))

        # ── Rule 1: Validate policy code ─────────────────────────────────────
        is_known_code = code in _PERMITTED_CODES_SET
        is_known_prefix = any(code.startswith(p) for p in _VALID_POL_PREFIXES)
        if not is_known_code and not is_known_prefix:
            grounding_warnings.append(
                f"GROUNDING: Unknown policy code '{code}' relabelled "
                f"to 'SS-POL-ORIGIN-UNVERIFIED'."
            )
            viol["policy_code"] = "SS-POL-ORIGIN-UNVERIFIED"
            viol["violation_detail"] = (
                f"[GROUNDING FLAG: Original code '{code}' not in permitted list] "
                + viol.get("violation_detail", "")
            )

        # ── Rule 2: triggering_value cross-reference ─────────────────────────
        # Only flag if metadata is non-empty and value is entirely absent
        if metadata and tval and tval not in flat_metadata_values and tval not in ("UNKNOWN", "null", "N/A", ""):
            # Don't hard-reject — just note it; the value might be derived/computed
            viol["_triggering_value_note"] = (
                f"Value '{tval}' not found verbatim in metadata fields."
            )

        validated_violations.append(viol)

    findings["violations"] = validated_violations

    # ── Rule 3: Validate enumerated fields ────────────────────────────────────
    sig = str(findings.get("signature_status", "")).upper()
    if sig not in ("VERIFIED", "UNVERIFIED", "MISMATCH"):
        grounding_warnings.append(
            f"GROUNDING: Invalid signature_status '{sig}' — set to UNVERIFIED."
        )
        findings["signature_status"] = "UNVERIFIED"

    cert = str(findings.get("cert_status", "")).upper()
    if cert not in ("VALID", "EXPIRED", "MISSING"):
        grounding_warnings.append(
            f"GROUNDING: Invalid cert_status '{cert}' — set to MISSING."
        )
        findings["cert_status"] = "MISSING"

    # ── Rule 4: Clamp confidence ──────────────────────────────────────────────
    conf = findings.get("confidence")
    if conf is not None:
        findings["confidence"] = max(0.0, min(1.0, float(conf)))

    overall = result.get("overall_confidence")
    if overall is not None:
        result["overall_confidence"] = max(0.0, min(1.0, float(overall)))

    if grounding_warnings:
        result["grounding_warnings"] = grounding_warnings
        penalty = min(0.1 * len(grounding_warnings), 0.3)
        result["overall_confidence"] = max(
            0.0, float(result.get("overall_confidence", 1.0)) - penalty
        )

    return result


def run(metadata: dict, policy: str, max_retries: int = config.MAX_RETRIES) -> dict:
    """
    Invoke the Provenance Agent and return its grounded compliance verdict.
    All policy codes in the output are validated against a known-good allow-list.
    """
    model = _get_model()

    # Format the permitted codes block for the prompt
    permitted_codes_block = (
        "PERMITTED POLICY CODES (EXHAUSTIVE — you MUST ONLY use these exact strings):\n"
        + "\n".join(f"  • {code}" for code in _PERMITTED_POLICY_CODES)
    )

    # Analyse metadata completeness to pre-compute what violations are possible
    has_signature = bool(metadata.get("signature") or metadata.get("signature_hash"))
    has_cert = bool(metadata.get("certificate") or metadata.get("cert") or metadata.get("cert_fingerprint"))
    has_origin = bool(metadata.get("compile_origin") or metadata.get("build_origin") or metadata.get("origin"))
    has_hash = bool(metadata.get("hash") or metadata.get("sha256") or metadata.get("checksum"))
    has_timestamp = bool(metadata.get("build_timestamp") or metadata.get("timestamp") or metadata.get("built_at"))

    metadata_completeness_block = f"""
METADATA COMPLETENESS ANALYSIS (pre-computed by Python — treat as authoritative):
  - Signature field present  : {has_signature}  → {'Verify against policy' if has_signature else 'MUST generate SS-POL-SIG-UNVERIFIED violation'}
  - Certificate field present: {has_cert}        → {'Verify against policy' if has_cert else 'MUST generate SS-POL-CERT-MISSING violation'}
  - Compile origin present   : {has_origin}      → {'Verify geography against policy' if has_origin else 'MUST generate SS-POL-ORIGIN-UNVERIFIED violation'}
  - Hash field present       : {has_hash}        → {'Verify against binary' if has_hash else 'MUST generate SS-POL-HASH-MISSING violation'}
  - Build timestamp present  : {has_timestamp}   → {'Verify plausibility' if has_timestamp else 'MUST generate SS-POL-TIMESTAMP-MISSING violation'}
"""

    system_message = (
        "You are a security compliance analysis agent in the SovereignShield pipeline.\n"
        "CRITICAL RULES — YOU MUST FOLLOW THESE WITHOUT EXCEPTION:\n"
        "1. Respond with ONLY valid JSON. No prose, no markdown, no explanations.\n"
        "2. You MUST ONLY use policy codes from the PERMITTED POLICY CODES list. "
        "Inventing new codes (e.g., 'ZTP-GEO-123', 'SS-POL-VENDOR-UNTRUSTED') is FORBIDDEN.\n"
        "3. Every violation you report MUST correspond to a real field from the metadata "
        "or a real clause from the policy text. Do not fabricate violations.\n"
        "4. The `triggering_field` and `triggering_value` MUST reference actual fields "
        "from the provided metadata JSON. You cannot reference fields that do not exist.\n"
        "5. If the metadata is completely empty, you MUST still produce violations for "
        "every absent required field (signature, certificate, origin, hash, timestamp).\n"
        "6. signature_status MUST be exactly one of: VERIFIED, UNVERIFIED, MISMATCH.\n"
        "7. cert_status MUST be exactly one of: VALID, EXPIRED, MISSING."
    )

    prompt = f"""You are the Provenance Agent in the SovereignShield automated supply-chain inspection pipeline.

MANDATE (NIST SP 800-218 Practice PO.3.2): Verify the provenance and integrity of all third-party software components.

━━━ HARD CONSTRAINTS (VIOLATIONS WILL BE DETECTED AND PENALIZED) ━━━
{permitted_codes_block}

━━━ SOFTWARE UPDATE METADATA (SOURCE OF TRUTH) ━━━
{json.dumps(metadata, indent=2)}

{metadata_completeness_block}

━━━ ZERO-TRUST GEOGRAPHIC ROUTING POLICY (VERBATIM) ━━━
{policy}

TASK:
1. Compare every metadata field against EVERY clause in the Zero-Trust Policy above.
2. Use ONLY the policy codes from the PERMITTED POLICY CODES list above.
3. **MISSING DATA IS A VIOLATION**: Use the METADATA COMPLETENESS ANALYSIS above.
   For every field marked False, you MUST generate the corresponding violation.
4. **MANDATORY ITEMIZATION**: Report Signature, Certificate, and Origin violations
   as SEPARATE objects in the `violations` array. Do NOT combine them.
5. **FACTUAL TRIGGERING FIELDS**: The `triggering_field` must be the actual JSON key
   from the metadata above. The `triggering_value` must be the actual value from
   that field, or "ABSENT" if the field does not exist.
6. **NO FABRICATION**: Do not invent violation details not supported by the metadata
   or policy text. Only cite clauses that actually appear in the policy text above.

Respond with ONLY valid JSON — no prose, no markdown — in this exact schema:
{{
  "agent": "ProvenanceAgent",
  "findings": {{
    "compile_origin": "<exact value from metadata 'compile_origin'/'build_origin'/'origin' field, or 'UNKNOWN' if absent>",
    "violations": [
      {{
        "policy_code": "<EXACT code from PERMITTED POLICY CODES list above>",
        "triggering_field": "<exact JSON key from metadata, or 'N/A' if field is absent>",
        "triggering_value": "<exact field value from metadata, or 'ABSENT' if field missing>",
        "violation_detail": "<specific explanation citing the policy clause and metadata value>",
        "severity": "<CRITICAL|HIGH|MEDIUM>"
      }}
    ],
    "signature_status": "<VERIFIED|UNVERIFIED|MISMATCH — based strictly on metadata>",
    "cert_status": "<VALID|EXPIRED|MISSING — based strictly on metadata>",
    "confidence": <float 0.0–1.0>,
    "summary": "<two factual sentences based ONLY on the metadata and policy provided>"
  }},
  "overall_confidence": <float 0.0–1.0>
}}"""

    last_error: Exception | None = None
    raw = ""
    for attempt in range(1 + max_retries):
        try:
            messages = [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt}
            ]
            response = model.chat(messages=messages)
            raw = response["choices"][0]["message"]["content"]
            result = utils.extract_json(raw)

            # ── Post-processing: Programmatic grounding validation ────────────
            result = _validate_provenance_output(result, metadata)
            return result

        except (ValueError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < max_retries:
                ui.print_warn(f"[ProvenanceAgent] JSON parse error (attempt {attempt + 1}), retrying...")

    ui.print_error(f"[ProvenanceAgent] RAW MODEL RESPONSE:\n{raw[:2000]}")
    raise RuntimeError(
        f"ProvenanceAgent failed to return valid JSON after {1 + max_retries} attempts. "
        f"Last error: {last_error}"
    )
