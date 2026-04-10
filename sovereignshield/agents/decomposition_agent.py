"""
agents/decomposition_agent.py
──────────────────────────────
NIST SP 800-218 — Practice PO.1.1
"Identify and document all software components and dependencies."

This agent receives the pre-computed SBOM diff and CVE matches from the
Python preprocessor.  Its job is to *interpret* the discrepancies (not
re-parse raw JSON), produce a confidence-scored finding for each hidden
dependency, and return structured JSON that the Arbiter can act on.

Improvements over the original plan:
  • Robust JSON extraction: tries json.loads first, then strips markdown
    fences, then falls back to regex to find the outermost {} block.
  • Explicit retry (up to 2 attempts) if JSON parsing fails.
  • Model initialised once at module scope — not on every call — so that
    repeated demo runs don't pay extra auth overhead.
"""

import json
import sys
from pathlib import Path

# Allow running this file directly for isolated testing
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from .. import config
from .. import ui
from .. import utils
from ..watsonx_client import get_model

# ── Module-level model instance (initialised lazily) ──────────────────────────
_model = None


def _get_model():
    global _model
    if _model is None:
        _model = get_model()  # uses DEFAULT_MODEL from watsonx_client
    return _model


# ── Main agent entry point ─────────────────────────────────────────────────────

def run(diff: dict, cve_matches: list[dict], max_retries: int = config.MAX_RETRIES) -> dict:
    """
    Invoke the Decomposition Agent and return its structured findings.
    """
    model = _get_model()

    # Limit hidden deps to avoid context overflow, but use the expanded config limit
    raw_hidden = diff.get("hidden_dependencies", [])
    hidden_deps = raw_hidden[:config.MAX_HIDDEN_DEPS_FOR_QUERY]
    expected_count = len(hidden_deps)
    
    prompt_diff = dict(diff)
    prompt_diff["hidden_dependencies"] = hidden_deps

    prompt = f"""You are the Decomposition Agent in the SovereignShield automated supply-chain inspection pipeline.

MANDATE (NIST SP 800-218 Practice PO.1.1): Identify and document all undisclosed software components and dependencies.

━━━ SBOM DISCREPANCY SUMMARY ━━━
{json.dumps(prompt_diff, indent=2)}

━━━ CVE DATABASE MATCHES FOR HIDDEN DEPENDENCIES ━━━
{json.dumps(cve_matches, indent=2)}

STRICT OPERATIONAL RULES:
1. **ABSOLUTE ITEMIZATION**: There are EXACTLY {expected_count} hidden dependencies listed above. You MUST produce EXACTLY {expected_count} unique findings in your output array.
2. **NO SUMMARIZATION**: Every single package must have its own individual finding. Grouping similar packages is an UNACCEPTABLE failure of thoroughness.
3. **ZERO HALLUCINATION**: If a dependency has NO matching CVE in the input data, you MUST set `cve_match` to `null`.
4. **THOROUGHNESS**: Provide a specific, one-sentence risk assessment for each component individually.

Respond with ONLY valid JSON — no prose, no markdown — in this exact schema:
{{
  "agent": "DecompositionAgent",
  "expected_finding_count": {expected_count},
  "findings": [
    {{
      "hidden_dependency": "<name:version>",
      "cve_match": "<CVE-ID or null>",
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "cvss_score": <float or null>,
      "confidence": <float 0.0–1.0>,
      "detail": "<one-sentence risk assessment for this specific package>"
    }}
  ],
  "overall_confidence": <float 0.0–1.0>,
  "summary": "<two sentences: overall assessment of the SBOM discrepancy>"
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
                ui.print_warn(f"[DecompositionAgent] JSON parse error (attempt {attempt + 1}), retrying...")

    ui.print_error(f"[DecompositionAgent] RAW MODEL RESPONSE:\n{raw[:2000]}")
    raise RuntimeError(
        f"DecompositionAgent failed to return valid JSON after {1 + max_retries} attempts. "
        f"Last error: {last_error}"
    )
