"""
utils.py
────────
Shared utility functions for the SovereignShield pipeline.
"""

import json
import re

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
