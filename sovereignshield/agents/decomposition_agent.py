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
import re
import sys
from pathlib import Path

# Allow running this file directly for isolated testing
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from watsonx_client import get_model

# ── Module-level model instance (initialised lazily) ──────────────────────────
_model = None


def _get_model():
    global _model
    if _model is None:
        _model = get_model()  # uses DEFAULT_MODEL from watsonx_client
    return _model


# ── JSON extraction helper ─────────────────────────────────────────────────────

def _extract_json(raw: str) -> dict:
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


# ── Main agent entry point ─────────────────────────────────────────────────────

def run(diff: dict, cve_matches: list[dict], max_retries: int = 2) -> dict:
    """
    Invoke the Decomposition Agent and return its structured findings.

    Parameters
    ----------
    diff        : Output of preprocessor.compute_sbom_diff()
    cve_matches : Output of preprocessor.cross_reference_cves()
    max_retries : Number of additional attempts if JSON parsing fails.

    Returns
    -------
    Parsed agent findings dict.
    """
    model = _get_model()

    # To prevent LLM context exhaustion on massive SBOM discrepancies like Juice Shop,
    # we smartly truncate the explicit list to only pass the critically vulnerable ones + a small sample.
    prompt_diff = dict(diff)
    vulnerable_names = {match["package"] for match in cve_matches}
    
    important_deps = []
    for dep in diff.get("hidden_dependencies", []):
        if dep["name"] in vulnerable_names:
            important_deps.append(dep)
        elif len(important_deps) < len(vulnerable_names) + 15:
            important_deps.append(dep)
            
    prompt_diff["hidden_dependencies"] = important_deps

    prompt = f"""You are the Decomposition Agent in the SovereignShield automated supply-chain inspection pipeline.

MANDATE (NIST SP 800-218 Practice PO.1.1): Identify and document all undisclosed software components and dependencies.

You have been given a PRE-COMPUTED analysis produced by the Python preprocessor.
Do NOT re-parse raw input. Interpret the findings below and assess threat significance.

━━━ SBOM DISCREPANCY SUMMARY (Truncated for brevity) ━━━
{json.dumps(prompt_diff, indent=2)}

━━━ CVE DATABASE MATCHES FOR HIDDEN DEPENDENCIES ━━━
{json.dumps(cve_matches, indent=2)}

SCORING RULES:
- Confidence 0.95–1.0 : CVE matches with CRITICAL/HIGH severity confirmed for hidden deps.
- Confidence 0.75–0.94: Hidden deps found but no CVE matches in database.
- Confidence below 0.75: Data is ambiguous, incomplete, or contradictory.

Produce a concise finding for EACH hidden dependency.

Respond with ONLY valid JSON — no prose, no markdown fences — in this exact schema:
{{
  "agent": "DecompositionAgent",
  "findings": [
    {{
      "hidden_dependency": "<name:version>",
      "cve_match": "<CVE-ID or NONE>",
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN>",
      "cvss_score": <float or null>,
      "confidence": <float 0.0–1.0>,
      "detail": "<one sentence: threat significance and exploit vector>"
    }}
  ],
  "version_drift_noted": <true|false>,
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
            return _extract_json(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < max_retries:
                print(f"  [DecompositionAgent] JSON parse error (attempt {attempt + 1}), retrying...")

    print(f"  [DecompositionAgent] RAW MODEL RESPONSE:\n{raw[:2000]}")
    raise RuntimeError(
        f"DecompositionAgent failed to return valid JSON after {1 + max_retries} attempts. "
        f"Last error: {last_error}"
    )
