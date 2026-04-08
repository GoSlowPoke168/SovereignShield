"""
main.py
────────
Entry point for the SovereignShield supply-chain inspection pipeline.

Run:
    python main.py

Or via the convenience launcher:
    python run.py
"""

import json
import os
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from .preprocessor import load_json, load_text, compute_sbom_diff, cross_reference_cves
from .agents import decomposition_agent, provenance_agent, arbiter_agent

# Use absolute paths relative to the project root
PROJECT_ROOT = Path(__file__).parent.parent
MOCK_DIR = PROJECT_ROOT / "data" / "mock_payloads"
OUTPUT_DIR = PROJECT_ROOT / "data" / "reports"


# ── Terminal formatting helpers ────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
DIM    = "\033[2m"
BG_RED   = "\033[41m"
BG_GREEN = "\033[42m"


def _supports_color() -> bool:
    """Return True if the terminal likely supports ANSI color codes."""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"{code}{text}{RESET}" if _supports_color() else text


def print_banner():
    banner = r"""
  ███████╗ ██████╗ ██╗   ██╗███████╗██████╗ ███████╗██╗ ██████╗ ███╗   ██╗    ███████╗ ███████╗
  ██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗██╔════╝██║██╔════╝ ████╗  ██║    ███████║ ███████║
  ███████╗██║   ██║██║   ██║█████╗  ██████╔╝█████╗  ██║██║  ███╗██╔██╗ ██║    ╚══════╝ ╚══════╝
  ╚════██║██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══╝  ██║██║   ██║██║╚██╗██║    ███████╗ ███████╗
  ███████║╚██████╔╝ ╚████╔╝ ███████╗██║  ██║███████╗██║╚██████╔╝██║ ╚████║     ╚█████║ █████╔╝ 
  ╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝      ╚████╝ ╚████╝  
                                                                                                 SHIELD
  Automated Supply-Chain Customs Inspection Pipeline
  NIST SP 800-218 Aligned  |  IBM Granite Guardian  |  Zero-Trust Architecture
"""
    print(_c(CYAN, banner))


def print_section(title: str, phase: int | None = None):
    label = f"  PHASE {phase}: {title}" if phase else f"  {title}"
    print()
    print(_c(CYAN, "═" * 68))
    print(_c(BOLD + WHITE, label))
    print(_c(CYAN, "═" * 68))


def print_ok(msg: str):
    print(f"  {_c(GREEN, '✓')} {msg}")


def print_info(msg: str):
    print(f"  {_c(CYAN, '→')} {msg}")


def print_warn(msg: str):
    print(f"  {_c(YELLOW, '⚠')} {msg}")


# ── Report writers ─────────────────────────────────────────────────────────────

def write_text_report(arbiter: dict, decomp: dict, prov: dict):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    verdict = arbiter.get("verdict", "UNKNOWN")

    lines = [
        "=" * 68,
        "  SOVEREIGNSHIELD — CUSTOMS INSPECTION REPORT",
        "=" * 68,
        f"  Generated        : {timestamp}",
        f"  Package          : {arbiter.get('package')}",
        f"  Vendor           : {arbiter.get('vendor', 'N/A')}",
        f"  Inspection ID    : SS-{timestamp.replace(':', '').replace('-', '')[:14]}",
        f"  VERDICT          : *** {verdict} ***",
        "",
        "  CONFIRMED THREATS",
        "-" * 68,
    ]
    for threat in arbiter.get("confirmed_threats", []):
        lines.append(
            f"  [{threat['threat_id']}] {threat['severity']:<8} | "
            f"{threat['source_agent']:<22} | {threat['nist_reference']}"
        )
        lines.append(f"           {threat['description']}")
        lines.append("")

    flags = arbiter.get("low_confidence_flags", [])
    if flags:
        lines += ["  LOW-CONFIDENCE FLAGS (AGENTIC FEEDBACK LOOP)", "-" * 68]
        for flag in flags:
            wrapped = textwrap.fill(flag, width=64, initial_indent="  • ", subsequent_indent="    ")
            lines.append(wrapped)
        lines.append("")

    lines += [
        "  DECOMPOSITION AGENT  (NIST SP 800-218 PO.1.1)",
        "-" * 68,
        f"  {decomp.get('summary', 'No summary available.')}",
        f"  Confidence Score : {decomp.get('overall_confidence', 'N/A')}",
        "",
        "  PROVENANCE AGENT  (NIST SP 800-218 PO.3.2)",
        "-" * 68,
        f"  {prov['findings'].get('summary', 'No summary available.')}",
        f"  Confidence Score : {prov.get('overall_confidence', 'N/A')}",
        "",
        "  VERDICT RATIONALE  (NIST SP 800-218 RV.1.3)",
        "-" * 68,
    ]
    rationale = textwrap.fill(
        arbiter.get("verdict_rationale", ""), width=64,
        initial_indent="  ", subsequent_indent="  "
    )
    lines.append(rationale)
    lines += [
        "",
        "  RECOMMENDED ACTION",
        "-" * 68,
        f"  {arbiter.get('recommended_action', 'N/A')}",
        "=" * 68,
        f"  Total violations : {arbiter.get('total_violations', 0)}",
        "=" * 68,
    ]

    out_path = OUTPUT_DIR / "inspection_report.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print_ok(f"Text report written  → {out_path}")


def write_html_report(arbiter: dict, decomp: dict, prov: dict):
    verdict = arbiter.get("verdict", "UNKNOWN")
    is_block = (verdict == "BLOCK")
    v_color = "#ef4444" if is_block else "#22c55e"
    v_bg = "rgba(239,68,68,0.15)" if is_block else "rgba(34,197,94,0.15)"
    v_icon = "🚫" if is_block else "✅"

    def severity_badge(sev: str) -> str:
        colors = {
            "CRITICAL": ("#ef4444", "#1a0000"),
            "HIGH":     ("#f97316", "#1a0800"),
            "MEDIUM":   ("#eab308", "#181200"),
            "LOW":      ("#22c55e", "#001a06"),
        }
        fg, bg = colors.get(sev, ("#94a3b8", "#111"))
        return (
            f'<span style="background:{bg};color:{fg};border:1px solid {fg};'
            f'padding:2px 8px;border-radius:4px;font-size:0.75em;'
            f'font-weight:700;letter-spacing:0.05em">{sev}</span>'
        )

    def conf_bar(score: float | None) -> str:
        if score is None:
            return "N/A"
        pct = int((score or 0) * 100)
        fg = "#22c55e" if pct >= 90 else "#eab308" if pct >= 75 else "#ef4444"
        return (
            f'<div style="display:flex;align-items:center;gap:8px">'
            f'<div style="flex:1;height:6px;background:#1e293b;border-radius:3px">'
            f'<div style="width:{pct}%;height:100%;background:{fg};border-radius:3px"></div>'
            f'</div><span style="font-size:0.8em;color:{fg}">{score:.2f}</span></div>'
        )

    threats_rows = ""
    for t in arbiter.get("confirmed_threats", []):
        threats_rows += (
            f"<tr>"
            f"<td><code>{t['threat_id']}</code></td>"
            f"<td><span style='color:#94a3b8;font-size:0.82em'>{t['source_agent']}</span></td>"
            f"<td>{severity_badge(t['severity'])}</td>"
            f"<td>{t['description']}</td>"
            f"<td><code style='color:#7dd3fc'>{t['nist_reference']}</code></td>"
            f"</tr>"
        )

    decomp_rows = ""
    for f in decomp.get("findings", []):
        decomp_rows += (
            f"<tr>"
            f"<td><code>{f.get('hidden_dependency','N/A')}</code></td>"
            f"<td><code style='color:#fca5a5'>{f.get('cve_match','NONE')}</code></td>"
            f"<td>{severity_badge(f.get('severity','UNKNOWN'))}</td>"
            f"<td style='font-size:0.85em'>{f.get('detail','')}</td>"
            f"</tr>"
        )

    prov_findings = prov.get("findings", {})
    violations_rows = ""
    for v in prov_findings.get("violations", []):
        violations_rows += (
            f"<tr>"
            f"<td><code style='color:#7dd3fc'>{v.get('policy_code','')}</code></td>"
            f"<td>{severity_badge(v.get('severity','MEDIUM'))}</td>"
            f"<td style='font-size:0.85em'>{v.get('violation_detail','')}</td>"
            f"</tr>"
        )

    flags_html = ""
    for flag in arbiter.get("low_confidence_flags", []):
        flags_html += f'<li style="margin:6px 0;color:#fbbf24">{flag}</li>'
    flags_section = ""
    if flags_html:
        flags_section = f"""
        <div class="card" style="border-color:#fbbf24">
          <div class="card-header" style="color:#fbbf24">⚠ Agentic Feedback Loop — Low-Confidence Flags</div>
          <ul style="margin:0;padding-left:20px">{flags_html}</ul>
        </div>"""

    timestamp = arbiter.get("inspection_timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SovereignShield — Customs Inspection Report</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg:     #050a14;
      --bg2:    #0a1628;
      --bg3:    #0f1f3d;
      --border: #1e3a5f;
      --text:   #cbd5e1;
      --muted:  #64748b;
      --accent: #3b82f6;
      --accent2:#0ea5e9;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 48px 24px;
      min-height: 100vh;
    }}
    .container {{ max-width: 1100px; margin: 0 auto; }}

    /* ── Header ── */
    .header {{
      display: flex; align-items: center; gap: 16px;
      margin-bottom: 8px;
    }}
    .shield {{ font-size: 2.5em; }}
    h1 {{ font-size: 1.75em; font-weight: 700; color: #f1f5f9;
          letter-spacing: -0.02em; line-height: 1.2; }}
    .subtitle {{ color: var(--muted); font-size: 0.85em; margin-top: 2px; }}
    .meta-bar {{
      display: flex; gap: 24px; margin: 20px 0 32px;
      padding: 14px 20px; background: var(--bg2);
      border: 1px solid var(--border); border-radius: 8px;
      font-size: 0.82em; color: var(--muted);
    }}
    .meta-bar span {{ color: var(--text); font-weight: 500; }}

    /* ── Verdict banner ── */
    .verdict-banner {{
      display: flex; align-items: center; gap: 20px;
      padding: 24px 32px; border-radius: 12px;
      border: 2px solid {v_color};
      background: {v_bg};
      margin-bottom: 32px;
    }}
    .verdict-icon {{ font-size: 2.5em; }}
    .verdict-label {{ font-size: 0.75em; text-transform: uppercase;
                       letter-spacing: 0.12em; color: {v_color}; font-weight: 600; }}
    .verdict-text  {{ font-family: 'JetBrains Mono', monospace;
                       font-size: 2.2em; font-weight: 700; color: {v_color}; }}
    .verdict-count {{ margin-left: auto; text-align: right; }}
    .verdict-count-num {{ font-size: 2em; font-weight: 700; color: {v_color}; }}
    .verdict-count-label {{ font-size: 0.75em; color: var(--muted); }}

    /* ── Cards ── */
    .card {{
      background: var(--bg2); border: 1px solid var(--border);
      border-radius: 10px; padding: 24px; margin-bottom: 24px;
    }}
    .card-header {{
      font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.1em;
      color: var(--accent2); font-weight: 600; margin-bottom: 16px;
      padding-bottom: 10px; border-bottom: 1px solid var(--border);
    }}
    .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}

    /* ── Tables ── */
    table {{ width: 100%; border-collapse: collapse; }}
    th {{
      background: var(--bg3); color: #94a3b8; font-size: 0.75em;
      text-transform: uppercase; letter-spacing: 0.08em;
      padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border);
    }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #0f1b2d; font-size: 0.88em; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover {{ background: rgba(59,130,246,0.05); }}
    code {{ font-family: 'JetBrains Mono', monospace; font-size: 0.88em; }}

    /* ── Agent summary cards ── */
    .summary-text {{ line-height: 1.7; font-size: 0.9em; color: var(--text);
                      margin-bottom: 14px; }}
    .conf-label {{ font-size: 0.75em; color: var(--muted); margin-bottom: 6px; }}

    /* ── Rationale ── */
    .rationale {{ line-height: 1.8; font-size: 0.92em; color: #e2e8f0; }}
    .action-box {{
      margin-top: 16px; padding: 14px 18px;
      background: rgba(59,130,246,0.08); border: 1px solid rgba(59,130,246,0.25);
      border-radius: 6px; font-size: 0.88em;
    }}
    .action-label {{ font-size: 0.72em; text-transform: uppercase; letter-spacing: 0.1em;
                      color: var(--accent); font-weight: 600; margin-bottom: 6px; }}

    /* ── Footer ── */
    footer {{
      margin-top: 48px; text-align: center; font-size: 0.78em; color: var(--muted);
      padding-top: 20px; border-top: 1px solid var(--border);
    }}
  </style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="shield">🛡️</div>
    <div>
      <h1>SovereignShield</h1>
      <div class="subtitle">Customs Inspection Report — Automated Supply-Chain Security Pipeline</div>
    </div>
  </div>

  <!-- Meta bar -->
  <div class="meta-bar">
    <div>Package &nbsp;<span>{arbiter.get('package', 'N/A')}</span></div>
    <div>Vendor &nbsp;<span>{arbiter.get('vendor', 'N/A')}</span></div>
    <div>Timestamp &nbsp;<span>{timestamp}</span></div>
    <div>Framework &nbsp;<span>NIST SP 800-218</span></div>
    <div>Model &nbsp;<span>IBM Granite 3.3</span></div>
  </div>

  <!-- Verdict banner -->
  <div class="verdict-banner">
    <div class="verdict-icon">{v_icon}</div>
    <div>
      <div class="verdict-label">Final Verdict</div>
      <div class="verdict-text">{verdict}</div>
    </div>
    <div class="verdict-count">
      <div class="verdict-count-num">{arbiter.get('total_violations', 0)}</div>
      <div class="verdict-count-label">Confirmed Violations</div>
    </div>
  </div>

  {flags_section}

  <!-- Confirmed Threats -->
  <div class="card">
    <div class="card-header">Confirmed Threats</div>
    <table>
      <tr>
        <th>ID</th><th>Source Agent</th><th>Severity</th>
        <th>Description</th><th>NIST Reference</th>
      </tr>
      {threats_rows if threats_rows else "<tr><td colspan='5' style='text-align:center;color:#64748b'>No threats confirmed</td></tr>"}
    </table>
  </div>

  <!-- Agent summaries side by side -->
  <div class="grid-2">

    <!-- Decomposition Agent -->
    <div class="card">
      <div class="card-header">🔍 Decomposition Agent — NIST PO.1.1</div>
      <p class="summary-text">{decomp.get('summary', 'No summary available.')}</p>
      <div class="conf-label">Confidence Score</div>
      {conf_bar(decomp.get('overall_confidence'))}
      <br>
      <table style="margin-top:12px">
        <tr><th>Dependency</th><th>CVE</th><th>Severity</th><th>Detail</th></tr>
        {decomp_rows if decomp_rows else "<tr><td colspan='4'>No findings</td></tr>"}
      </table>
    </div>

    <!-- Provenance Agent -->
    <div class="card">
      <div class="card-header">🔎 Provenance Agent — NIST PO.3.2</div>
      <p class="summary-text">{prov_findings.get('summary', 'No summary available.')}</p>
      <div class="conf-label">Confidence Score</div>
      {conf_bar(prov.get('overall_confidence'))}
      <br>
      <div style="display:flex;gap:16px;margin:12px 0;font-size:0.82em">
        <span>Signature: <strong style="color:{'#ef4444' if prov_findings.get('signature_status')=='MISMATCH' else '#94a3b8'}">{prov_findings.get('signature_status','N/A')}</strong></span>
        <span>Cert: <strong style="color:{'#ef4444' if prov_findings.get('cert_status')=='EXPIRED' else '#94a3b8'}">{prov_findings.get('cert_status','N/A')}</strong></span>
        <span>Origin: <strong>{prov_findings.get('compile_origin','N/A')}</strong></span>
      </div>
      <table>
        <tr><th>Policy Code</th><th>Severity</th><th>Violation</th></tr>
        {violations_rows if violations_rows else "<tr><td colspan='3'>No violations</td></tr>"}
      </table>
    </div>

  </div>

  <!-- Arbiter Rationale -->
  <div class="card">
    <div class="card-header">⚖️ Arbiter Rationale — NIST RV.1.3</div>
    <p class="rationale">{arbiter.get('verdict_rationale', 'No rationale provided.')}</p>
    <div class="action-box">
      <div class="action-label">Recommended Action</div>
      {arbiter.get('recommended_action', 'N/A')}
    </div>
  </div>

  <footer>
    Generated by SovereignShield v1.0 &nbsp;|&nbsp; IBM Granite 3.3 (ibm/granite-3-3-8b-instruct) &nbsp;|&nbsp;
    NIST SP 800-218 Aligned &nbsp;|&nbsp; {timestamp}
  </footer>

</div>
</body>
</html>"""

    out_path = OUTPUT_DIR / "inspection_report.html"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print_ok(f"HTML report written  → {out_path}")


# ── Pipeline orchestrator ──────────────────────────────────────────────────────

def run_pipeline(target_binary: str | None = None, policy_path_override: str | None = None, vendor_sbom_override: str | None = None):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print_banner()

    # ── Phase 1 & 2 ────────────────────────────────────────────────────────────
    if target_binary:
        from .scanner import run_deep_scan
        print_section("LIVE BINARY INGESTION & DEEP SCAN", phase=1)
        target_path = Path(target_binary).resolve()
        
        if vendor_sbom_override and Path(vendor_sbom_override).exists():
            vendor_sbom_path = Path(vendor_sbom_override).resolve()
            vendor_sbom = load_json(vendor_sbom_path)
            print_ok(f"vendor SBOM loaded from CLI override: {vendor_sbom_path.name}")
        else:
            # Fallback to smart glob search in target directory
            search_dir = target_path if target_path.is_dir() else target_path.parent
            potential_sboms = list(search_dir.glob("*sbom*.json"))
            if potential_sboms:
                vendor_sbom_path = potential_sboms[0]
                vendor_sbom = load_json(vendor_sbom_path)
                print_ok(f"vendor SBOM auto-detected in directory: {vendor_sbom_path.name}")
            else:
                print_warn("No vendor SBOM found. Assuming 0 declared dependencies (Zero-Trust Fallback).")
                vendor_sbom = {"declared_dependencies": []}
            
        metadata_path = (target_path if target_path.is_dir() else target_path.parent) / "update_metadata.json"
        if metadata_path.exists():
            metadata = load_json(metadata_path)
            print_ok(f"update_metadata.json loaded from {metadata_path.name}")
        else:
            print_warn("No update metadata found. Policy evaluations will run strictly on binary contents.")
            metadata = {}
            
        if policy_path_override and Path(policy_path_override).exists():
            policy = load_text(Path(policy_path_override))
            print_ok(f"zero trust policy loaded from CLI override: {Path(policy_path_override).name}")
        else:
            search_dir = target_path if target_path.is_dir() else target_path.parent
            potential_policies = list(search_dir.glob("*policy*.txt"))
            if potential_policies:
                policy_path = potential_policies[0]
                policy = load_text(policy_path)
                print_ok(f"Zero-Trust Policy auto-detected in directory: {policy_path.name}")
            else:
                # Fallback to the internal example policy if no local one is found
                policy = load_text(MOCK_DIR / "zero_trust_policy.txt")
                print_ok("zero_trust_policy.txt loaded (Internal Default Rules)")
        
        # Execute Pipeline Deep Scan logic natively
        deep_scan = run_deep_scan(target_path)
        print_ok(f"Deep scan phase successfully generated internal SBOM map for {target_path.name}")
        
    else:
        print_section("LOADING MOCK DEMO PAYLOAD", phase=1)
        vendor_sbom = load_json(MOCK_DIR / "vendor_sbom.json")
        deep_scan   = load_json(MOCK_DIR / "deep_scan_sbom.json")
        metadata    = load_json(MOCK_DIR / "update_metadata.json")
        policy      = load_text(MOCK_DIR / "zero_trust_policy.txt")
        print_ok("vendor_sbom.json      loaded")
        print_ok("deep_scan_sbom.json   loaded")
        print_ok("update_metadata.json  loaded")
        print_ok("zero_trust_policy.txt loaded")

    print_section("PYTHON PRE-PROCESSING  (no LLM tokens consumed)", phase=2)
    diff = compute_sbom_diff(vendor_sbom, deep_scan)
    cve_matches = cross_reference_cves(diff)
    print_info(f"Vendor-declared deps  : {diff['total_vendor_declared']}")
    print_info(f"Deep-scan detected    : {diff['total_scan_detected']}")
    print_warn(f"Hidden dependencies   : {diff['hidden_count']}  ← undisclosed by vendor")
    if diff.get("version_drift_count", 0):
        print_warn(f"Version drift found   : {diff['version_drift_count']} packages")
    print_warn(f"CVE matches found     : {len(cve_matches)}  ← confirmed vulnerabilities")

    # ── Phase 3: Decomposition Agent ─────────────────────────────────────────
    print_section("DECOMPOSITION AGENT  [NIST SP 800-218 — PO.1.1]", phase=3)
    print_info("Querying ibm/granite-3-3-8b-instruct ...")
    decomp_result = decomposition_agent.run(diff, cve_matches)
    print_ok(f"Confidence score      : {decomp_result.get('overall_confidence')}")
    print_ok(f"Findings returned     : {len(decomp_result.get('findings', []))} hidden dependency assessments")

    # ── Phase 4: Provenance Agent ─────────────────────────────────────────────
    print_section("PROVENANCE AGENT  [NIST SP 800-218 — PO.3.2]", phase=4)
    print_info("Querying ibm/granite-3-3-8b-instruct ...")
    prov_result = provenance_agent.run(metadata, policy)
    print_ok(f"Confidence score      : {prov_result.get('overall_confidence')}")
    viol_count = len(prov_result.get("findings", {}).get("violations", []))
    print_ok(f"Policy violations     : {viol_count} clause(s) triggered")
    print_ok(f"Signature status      : {prov_result.get('findings', {}).get('signature_status', 'N/A')}")
    print_ok(f"Certificate status    : {prov_result.get('findings', {}).get('cert_status', 'N/A')}")

    # ── Phase 5: Arbiter Agent ────────────────────────────────────────────────
    print_section("ARBITER AGENT  [NIST SP 800-218 — RV.1.3]", phase=5)
    print_info("Evaluating confidence thresholds (agentic feedback loop) ...")
    d_conf = decomp_result.get("overall_confidence", 1.0)
    p_conf = prov_result.get("overall_confidence", 1.0)
    low_conf_detected = d_conf < 0.75 or p_conf < 0.75
    if low_conf_detected:
        print_warn(f"Low-confidence flag triggered — secondary review embedded in report")
    else:
        print_ok("All confidence scores above threshold — proceeding to verdict")
    print_info("Querying ibm/granite-3-3-8b-instruct ...")
    if target_binary:
        target_path = Path(target_binary)
        pkg_name = target_path.name
        vnd_name = "Unknown Vendor"
    else:
        pkg_name = "DataBridge-Enterprise v4.2.1"
        vnd_name = "NexaTech Solutions"

    arbiter_result = arbiter_agent.run(
        decomp_findings=decomp_result, 
        prov_findings=prov_result,
        package_name=pkg_name,
        vendor_name=vnd_name
    )

    # ── Phase 6: Generate output reports ─────────────────────────────────────
    print_section("GENERATING INSPECTION REPORTS", phase=6)
    write_text_report(arbiter_result, decomp_result, prov_result)
    write_html_report(arbiter_result, decomp_result, prov_result)

    # ── Final verdict ─────────────────────────────────────────────────────────
    verdict = arbiter_result.get("verdict", "UNKNOWN")
    is_block = (verdict == "BLOCK")
    v_tag = _c(RED + BOLD, f"  ┃  VERDICT: {verdict}  ┃") if is_block \
            else _c(GREEN + BOLD, f"  ┃  VERDICT: {verdict}  ┃")

    print()
    print(_c(CYAN, "═" * 68))
    print(_c(BOLD + WHITE, "  SOVEREIGNSHIELD — FINAL VERDICT"))
    print(_c(CYAN, "═" * 68))
    print()
    print(v_tag)
    print()
    print_info(f"Package    : {arbiter_result.get('package')}")
    print_info(f"Threats    : {arbiter_result.get('total_violations', 0)} confirmed")
    rationale = arbiter_result.get("verdict_rationale", "")
    for line in textwrap.wrap(f"Rationale  : {rationale}", width=64):
        print(f"  {line}")
    print_info(f"Action     : {arbiter_result.get('recommended_action', 'N/A')}")
    print()
    print_ok(f"Full reports saved to ./{OUTPUT_DIR}/")
    print(_c(CYAN, "═" * 68))


if __name__ == "__main__":
    run_pipeline()
