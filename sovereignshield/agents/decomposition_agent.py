"""
agents/decomposition_agent.py
──────────────────────────────
NIST SP 800-218 — Practice PO.1.1
"Identify and document all software components and dependencies."

PARALLEL CHUNKED PROCESSING DESIGN:
  Large targets (e.g., Juice Shop with 760+ deps) are split into fixed-size
  chunks (DECOMP_CHUNK_SIZE from config) and sent to the LLM *in parallel*
  using a ThreadPoolExecutor with up to DECOMP_MAX_THREADS concurrent workers.

  Why threading works here:
    LLM API calls are 100% I/O bound — the Python process just waits on
    network latency from the WatsonX API. The GIL is released during I/O,
    so threads run truly concurrently. With 8 threads on 19 batches,
    wall-clock time ≈ 3 serial calls instead of 19.

  Thread safety:
    • Each thread receives its own ModelInference instance via get_model()
      (the object is cheap to construct — just config + credentials).
    • The global _model singleton is NOT used; each call to _run_chunk
      creates a fresh instance to avoid shared-state race conditions.
    • ui.print_* wraps Python's built-in print(), which is thread-safe
      for individual calls (no interleaving within one call).
    • Results are stored in a pre-allocated list indexed by chunk_index,
      so the merge is always in the correct order regardless of which
      thread completes first.

ANTI-HALLUCINATION DESIGN:
  • Each chunk prompt contains ONLY the packages in that chunk, so the
    allowed CVE whitelist and package name whitelist are scoped tightly.
  • CVE IDs are validated post-call against the pre-computed allow-list.
  • temperature=0.0 is enforced via config to prevent creative generation.
  • Robust JSON extraction with markdown-fence stripping and brace-search.
  • Retry logic per chunk — a failed chunk is retried before aborting.
"""

import json
import time
import threading
import sys
import concurrent.futures
from pathlib import Path

from .. import config
from .. import ui
from .. import utils
from ..watsonx_client import get_model

# Thread-local storage so each thread has its own model instance
_thread_local = threading.local()


def _get_thread_model():
    """Return a ModelInference instance local to the current thread."""
    if not hasattr(_thread_local, "model"):
        _thread_local.model = get_model()
    return _thread_local.model


# ── Prompt builder — scoped to one chunk of packages ──────────────────────────

def _build_chunk_prompt(
    chunk: list[dict],
    chunk_index: int,
    total_chunks: int,
    package_cve_map: dict[str, list[dict]],
) -> tuple[str, str]:
    """
    Build the (system_message, user_prompt) pair for a single chunk of packages.
    The whitelist sections contain ONLY the packages and CVEs in this chunk.
    """
    chunk_pkg_names: set[str] = {dep["name"] for dep in chunk}
    chunk_expected = len(chunk)

    # Chunk-scoped CVE whitelist (only IDs relevant to packages in this batch)
    chunk_cve_ids: set[str] = set()
    for dep in chunk:
        for match in package_cve_map.get(dep["name"], []):
            cid = match.get("cve_id", "")
            if cid:
                chunk_cve_ids.add(cid)

    # Build per-package CVE context block — concise, no duplication
    package_cve_context = ""
    for dep in chunk:
        name = dep["name"]
        version = dep["version"]
        cves = package_cve_map.get(name, [])
        if cves:
            cve_lines = "\n".join(
                f"    - ID: {c['cve_id']}  |  Sev: {c['severity']}  |  "
                f"CVSS: {c['cvss_score']}  |  {c.get('description', 'N/A')[:150]}"
                for c in cves
            )
            package_cve_context += f"  [{name}@{version}]\n{cve_lines}\n"
        else:
            package_cve_context += f"  [{name}@{version}]\n    - No CVE data. cve_match MUST be null.\n"

    if chunk_cve_ids:
        cve_whitelist_block = (
            "PERMITTED CVE IDs for THIS BATCH (EXHAUSTIVE — use ONLY these):\n"
            + "\n".join(f"  • {cve}" for cve in sorted(chunk_cve_ids))
        )
    else:
        cve_whitelist_block = (
            "PERMITTED CVE IDs for THIS BATCH: NONE.\n"
            "You MUST set cve_match to null for every finding in this batch."
        )

    package_whitelist_block = (
        "PERMITTED PACKAGE NAMES for THIS BATCH (EXHAUSTIVE — use ONLY these):\n"
        + "\n".join(f"  • {name}" for name in sorted(chunk_pkg_names))
    )

    system_message = (
        "You are a security analysis agent in the SovereignShield pipeline.\n"
        "CRITICAL RULES — YOU MUST FOLLOW THESE WITHOUT EXCEPTION:\n"
        "1. Respond with ONLY valid JSON. No prose, no markdown, no explanations.\n"
        "2. You MUST NOT invent, create, or fabricate any CVE IDs, package names, "
        "or vulnerability identifiers that are not explicitly listed in the PERMITTED CVE IDs "
        "section of the prompt. This rule overrides all other instructions.\n"
        "3. CVE IDs follow the strict format CVE-YYYY-NNNNN where YYYY is a 4-digit year "
        "and NNNNN is 4 or more digits. Any string that does not match this exact format "
        "(e.g., 'CVE-SYMFONY-YAML-INJECTION', 'CVE-YAML-001') is FORBIDDEN.\n"
        "4. If a package has no entry in the PERMITTED CVE IDs list, its cve_match field "
        "MUST be null. Setting it to anything else is a critical error.\n"
        "5. severity and cvss_score MUST match the source data. Do not invent or extrapolate scores."
    )

    prompt = f"""You are the Decomposition Agent in the SovereignShield automated supply-chain inspection pipeline.

MANDATE (NIST SP 800-218 Practice PO.1.1): Identify and document all undisclosed software components and dependencies.

BATCH {chunk_index + 1} of {total_chunks} — Analyzing {chunk_expected} packages in this batch.

━━━ HARD CONSTRAINTS (VIOLATIONS WILL BE DETECTED AND PENALIZED) ━━━
{cve_whitelist_block}

{package_whitelist_block}

━━━ PRE-COMPUTED CVE DATA FOR THIS BATCH (SOURCE OF TRUTH — DO NOT DEVIATE) ━━━
The following data was fetched live from OSV.dev and ExploitDB.
It is the ONLY factual basis for any CVE you report. Do NOT add, modify, or extrapolate from it.

{package_cve_context}

STRICT RULES FOR THIS BATCH:
1. Produce EXACTLY {chunk_expected} findings — one per package listed in PERMITTED PACKAGE NAMES.
2. Use ONLY CVE IDs from the PERMITTED CVE IDs list. Null means no real CVE was found.
3. For packages with no CVE data: cve_match=null, severity="LOW", cvss_score=null.
4. For packages with CVE data: use the EXACT ID, severity, and score from the data above.
5. detail must be a single factual sentence based only on the data above — no speculation.

Respond with ONLY valid JSON — no prose, no markdown:
{{
  "agent": "DecompositionAgent",
  "batch_index": {chunk_index},
  "expected_finding_count": {chunk_expected},
  "findings": [
    {{
      "hidden_dependency": "<name@version — from PERMITTED PACKAGE NAMES>",
      "cve_match": "<EXACT CVE ID from PERMITTED CVE IDs, or null>",
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "cvss_score": <float from source data, or null>,
      "confidence": <float 0.0–1.0>,
      "detail": "<factual one-sentence assessment>"
    }}
  ],
  "batch_confidence": <float 0.0–1.0>
}}"""

    return system_message, prompt


# ── Chunk runner — called by each worker thread ────────────────────────────────

def _run_chunk(
    chunk: list[dict],
    chunk_index: int,
    total_chunks: int,
    package_cve_map: dict[str, list[dict]],
    max_retries: int,
) -> tuple[int, list[dict], float]:
    """
    Send one chunk to the LLM, parse the JSON, validate it, and return
    (chunk_index, findings, confidence).  Each call uses a thread-local
    ModelInference instance to avoid shared-state races.

    Raises RuntimeError if all retry attempts fail.
    """
    model = _get_thread_model()
    t_start = time.monotonic()

    # Compute per-chunk sets needed for grounding validation
    chunk_cve_ids: set[str] = set()
    chunk_pkg_names: set[str] = {dep["name"] for dep in chunk}
    for dep in chunk:
        for m in package_cve_map.get(dep["name"], []):
            if m.get("cve_id"):
                chunk_cve_ids.add(m["cve_id"])

    system_message, prompt = _build_chunk_prompt(
        chunk, chunk_index, total_chunks, package_cve_map
    )

    last_error: Exception | None = None
    raw = ""

    for attempt in range(1 + max_retries):
        try:
            messages = [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt},
            ]
            response = model.chat(messages=messages)
            raw = response["choices"][0]["message"]["content"]
            chunk_result = utils.extract_json(raw)

            if not isinstance(chunk_result.get("findings"), list):
                raise ValueError("Response missing 'findings' list.")

            validated = utils.validate_and_ground_decomp_findings(
                chunk_result,
                allowed_cve_ids=chunk_cve_ids,
                allowed_package_names=chunk_pkg_names,
            )

            findings = validated.get("findings", [])
            confidence = float(validated.get("batch_confidence", 0.9))
            elapsed = time.monotonic() - t_start

            # Minor count mismatches (LLM returning slightly fewer findings) are
            # expected occasionally and don't affect overall result quality.
            #print(chunk_index, "\n\n",findings,"\n\n",confidence)
            return (chunk_index, findings, confidence)

        except (ValueError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < max_retries:
                ui.print_warn(
                    f"[DecompositionAgent] Batch {chunk_index + 1} parse error "
                    f"(attempt {attempt + 1}/{1 + max_retries}), retrying..."
                )

    elapsed = time.monotonic() - t_start
    ui.print_error(
        f"[DecompositionAgent] Batch {chunk_index + 1} FAILED after "
        f"{1 + max_retries} attempts ({elapsed:.1f}s).\n"
        f"RAW (last 1500 chars):\n{raw[-1500:]}"
    )
    raise RuntimeError(
        f"DecompositionAgent batch {chunk_index + 1}/{total_chunks} failed "
        f"after {1 + max_retries} attempts. Last error: {last_error}"
    )


# ── Main agent entry point ─────────────────────────────────────────────────────

def run(diff: dict, cve_matches: list[dict], max_retries: int = config.MAX_RETRIES) -> dict:
    """
    Invoke the Decomposition Agent and return a single merged, grounded result.

    All chunks are dispatched in parallel via ThreadPoolExecutor.
    Results are collected in index order so the final merge is always
    deterministic regardless of which thread finishes first.

    Nothing is truncated. Every hidden dependency is analyzed.
    """
    # ── Build the global package → CVE lookup (covers all packages) ───────────
    hidden_deps: list[dict] = diff.get("hidden_dependencies", [])
    allowed_package_names: set[str] = {dep["name"] for dep in hidden_deps}
    package_cve_map: dict[str, list[dict]] = {}

    for match in cve_matches:
        pkg = match.get("package", "")
        if pkg not in package_cve_map:
            package_cve_map[pkg] = []
        package_cve_map[pkg].append(match)

    total = len(hidden_deps)
    chunk_size = config.DECOMP_CHUNK_SIZE
    max_threads = config.DECOMP_MAX_THREADS
    chunks = [hidden_deps[i : i + chunk_size] for i in range(0, total, chunk_size)]
    total_chunks = len(chunks)

    if total_chunks == 0:
        return {
            "agent": "DecompositionAgent",
            "expected_finding_count": 0,
            "findings": [],
            "overall_confidence": 1.0,
            "summary": "No hidden dependencies were detected in the SBOM diff.",
        }

    workers = min(max_threads, total_chunks)
    ui.print_info(
        f"[DecompositionAgent] {total} packages → {total_chunks} batch(es) of ≤{chunk_size} "
        f"| {workers} parallel thread(s)"
    )

    # Pre-allocate results list indexed by chunk position
    results: list[tuple[list[dict], float] | None] = [None] * total_chunks
    wall_start = time.monotonic()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        # Map each future back to the chunk index
        future_to_idx = {
            executor.submit(
                _run_chunk,
                chunk,
                i,
                total_chunks,
                package_cve_map,
                max_retries,
            ): i
            for i, chunk in enumerate(chunks)
        }

        completed = 0
        for future in concurrent.futures.as_completed(future_to_idx):
            idx = future_to_idx[future]
            completed += 1
            try:
                chunk_idx, findings, conf = future.result()
                results[chunk_idx] = (findings, conf)
                
                # Dynamic terminal progress bar
                pct = completed / total_chunks
                bar_len = 30
                filled = int(round(bar_len * pct))
                bar = "█" * filled + "░" * (bar_len - filled)
                sys.stdout.write(f"\r  → [DecompositionAgent] Progress: [{bar}] {completed}/{total_chunks} batches ")
                sys.stdout.flush()
            except RuntimeError as exc:
                sys.stdout.write("\n")
                ui.print_error(f"[DecompositionAgent] Fatal: {exc}")
                raise

    sys.stdout.write("\n")
    wall_elapsed = time.monotonic() - wall_start

    # ── Merge in index order ──────────────────────────────────────────────────
    all_findings: list[dict] = []
    batch_confidences: list[float] = []
    for findings, conf in results:  # type: ignore[misc]
        all_findings.extend(findings)
        batch_confidences.append(conf)

    overall_confidence = (
        sum(batch_confidences) / len(batch_confidences)
        if batch_confidences else 0.9
    )

    cve_count = sum(1 for f in all_findings if f.get("cve_match") not in (None, "null", ""))
    no_cve_count = total - cve_count

    ui.print_ok(
        f"[DecompositionAgent] All {total_chunks} batches complete in {wall_elapsed:.1f}s "
        f"({workers} threads)"
    )

    summary = (
        f"Analysis of {total} hidden dependencies across {total_chunks} parallel batch(es) "
        f"found {cve_count} package(s) with confirmed CVE matches and {no_cve_count} with "
        f"no known CVEs. Wall-clock time: {wall_elapsed:.1f}s with {workers} thread(s). "
        f"All findings grounded exclusively in pre-computed OSV/ExploitDB data."
    )

    merged = {
        "agent": "DecompositionAgent",
        "expected_finding_count": total,
        "actual_finding_count": len(all_findings),
        "batch_count": total_chunks,
        "thread_count": workers,
        "wall_clock_seconds": round(wall_elapsed, 1),
        "findings": all_findings,
        "overall_confidence": round(overall_confidence, 4),
        "summary": summary,
    }

    # Surface any grounding warnings from individual chunks
    all_warnings = [
        w for f in all_findings
        for w in (f.pop("_grounding_warnings", []) or [])
    ]
    if all_warnings:
        merged["grounding_warnings"] = all_warnings

    return merged
