"""
main.py
────────
Entry point for the SovereignShield supply-chain inspection pipeline.

Run:
    python main.py

Or via the convenience launcher:
    python run.py
"""

import base64
import json
import os
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from .preprocessor import load_json, load_text, compute_sbom_diff, cross_reference_cves
from .agents import decomposition_agent, provenance_agent, arbiter_agent
from . import config

# Paths anchor to CWD at runtime so the tool works regardless of where it is installed.
# config.py uses __file__-relative paths for internal data; here we follow suit so that
# running `python run.py` from any directory still writes reports next to the project files.
PROJECT_ROOT = Path(__file__).parent.parent
OUTPUT_DIR   = PROJECT_ROOT / "data" / "reports"
ASSETS_DIR   = PROJECT_ROOT / "data" / "assets"

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


def _get_base64_logo() -> str:
    """Read the logo file and return a base64 data URI."""
    logo_path = ASSETS_DIR / "sovereignshield_logo.png"
    if not logo_path.exists():
        return ""
    with open(logo_path, "rb") as f:
        encoded = base64.b64encode(f.read()).decode("utf-8")
        return f"data:image/png;base64,{encoded}"


# ── Report writers ─────────────────────────────────────────────────────────────

def write_json_report(arbiter: dict, decomp: dict, prov: dict, ts_str: str, cve_matches: list[dict] = None):
    """
    Emit a machine-readable JSON report alongside the HTML.
    Suitable for ingestion by SIEM tools, CI/CD gates, and other automated consumers.
    Schema is stable across runs — use verdict, total_risk_score, and confirmed_threats.
    """
    pkg_name = arbiter.get('package', 'UnknownApp').replace(' ', '_')
    sev_dist = arbiter.get("severity_distribution", {})

    # Build the canonical, parsable payload
    payload = {
        "schema_version": "1.0",
        "tool": "SovereignShield",
        "nist_alignment": "SP 800-218",
        "generated_at": arbiter.get("inspection_timestamp", ts_str),
        "package": arbiter.get("package"),
        "vendor": arbiter.get("vendor"),
        "verdict": arbiter.get("verdict"),
        "total_risk_score": arbiter.get("total_risk_score"),
        "verdict_rationale": arbiter.get("verdict_rationale"),
        "recommended_action": arbiter.get("recommended_action"),
        "severity_distribution": sev_dist,
        "total_findings": arbiter.get("total_violations", 0),
        "agent_confidence": {
            "decomposition": decomp.get("overall_confidence"),
            "provenance": prov.get("overall_confidence"),
        },
        "low_confidence_flags": arbiter.get("low_confidence_flags", []),
        "confirmed_threats": [
            {
                "threat_id": t.get("threat_id"),
                "source_agent": t.get("source_agent"),
                "severity": t.get("severity"),
                "cvss_score": t.get("cvss_score"),
                "nist_reference": t.get("nist_reference"),
                "description": t.get("description"),
            }
            for t in arbiter.get("confirmed_threats", [])
        ],
    }

    pkg_dir = OUTPUT_DIR / pkg_name
    pkg_dir.mkdir(parents=True, exist_ok=True)
    out_path = pkg_dir / f"{pkg_name}_{ts_str}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print_ok(f"JSON report written  → {out_path.relative_to(PROJECT_ROOT)}")

def write_html_report(arbiter: dict, decomp: dict, prov: dict, ts_str: str, cve_matches: list[dict] = None):
    verdict = arbiter.get("verdict", "UNKNOWN")
    is_block = (verdict == "BLOCK")
    v_color = "#d93025" if is_block else "#1e8e3e"
    v_bg = "rgba(217, 48, 37, 0.08)" if is_block else "rgba(30, 142, 62, 0.08)"
    v_icon = "🚫" if is_block else "✅"
    pkg_name = arbiter.get('package', 'UnknownApp').replace(' ', '_')
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    logo_base64 = _get_base64_logo()

    # Calculate System Composite Confidence Score
    c1 = decomp.get('overall_confidence', 0)
    c2 = prov.get('overall_confidence', 0)
    sys_confidence = (c1 + c2) / 2 if (c1 and c2) else c1 or c2 or None

    # Calculate statistics for the chart
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for t in arbiter.get("confirmed_threats", []):
        s = t.get("severity", "MEDIUM").upper()
        if s in sev_counts:
            sev_counts[s] += 1

    # Calculate counts and labels for the chart
    sev_labels = [
        f"Critical ({sev_counts['CRITICAL']})",
        f"High ({sev_counts['HIGH']})",
        f"Medium ({sev_counts['MEDIUM']})",
        f"Low ({sev_counts['LOW']})"
    ]

    # Filter chips HTML
    filters_html = f"""
    <style>
      .hide-cb-label {{
        padding: 10px 22px; border-radius: 30px; border: 1px solid var(--border);
        background: var(--glass); color: var(--muted); cursor: pointer;
        display: flex; align-items: center; gap: 10px;
        font-size: 0.85em; font-weight: 800; text-transform: uppercase;
        transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        letter-spacing: 0.05em;
      }}
      .hide-cb-label:hover {{ transform: translateY(-3px); border-color: var(--accent); color: var(--accent); }}
      .hide-cb-label:has(input:checked) {{
        background: var(--accent); color: white; border-color: var(--accent);
        box-shadow: 0 4px 12px rgba(26, 115, 232, 0.4);
      }}
      .hide-cb-label:has(input:checked)[style*="--c"] {{
        background: var(--c); border-color: var(--c);
        box-shadow: 0 4px 12px var(--c);
      }}
      .hide-cb-label input {{ accent-color: white; width: 15px; height: 15px; cursor: pointer; }}

      .agent-tooltip {{
        cursor: help; 
        border-bottom: 1px dotted var(--muted);
        position: relative;
        display: inline-block;
      }}
      .agent-tooltip::after {{
        content: attr(data-tooltip);
        position: absolute;
        bottom: 130%; left: 0;
        width: 280px;
        padding: 14px 18px;
        background: rgba(26, 27, 30, 0.95);
        color: #fff;
        font-size: 0.85rem;
        font-weight: 600;
        line-height: 1.5;
        text-transform: none;
        letter-spacing: normal;
        border-radius: 10px;
        pointer-events: none;
        opacity: 0;
        transform: translateY(10px);
        transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        box-shadow: 0 10px 25px rgba(0,0,0,0.2);
        z-index: 100;
      }}
      .agent-tooltip:hover::after {{ opacity: 1; transform: translateY(0); }}
    </style>
    <div class="animate-in" style="animation-delay: 0.35s; display:flex; flex-direction:column; gap:16px; margin-bottom:24px;">
      <div style="display:flex; gap:12px;">
        <span style="font-size:0.85em;font-weight:900;text-transform:uppercase;color:var(--muted);align-self:center;margin-right:8px;">Show:</span>
        <button class="filter-chip active" onclick="setSeverityFilter('ALL', this)">All</button>
        <button class="filter-chip" onclick="setSeverityFilter('CRITICAL', this)" style="--c:#d93025">Critical</button>
        <button class="filter-chip" onclick="setSeverityFilter('HIGH', this)" style="--c:#e67c73">High</button>
        <button class="filter-chip" onclick="setSeverityFilter('MEDIUM', this)" style="--c:#f29900">Medium</button>
        <button class="filter-chip" onclick="setSeverityFilter('LOW', this)" style="--c:#1e8e3e">Low</button>
      </div>
      <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
        <span style="font-size:0.85em;font-weight:900;text-transform:uppercase;color:var(--muted);margin-right:2px;">Hide:</span>
        <label class="hide-cb-label" style="--c:#d93025">
          <input type="checkbox" onchange="toggleHide('CRITICAL', this.checked)"> Critical
        </label>
        <label class="hide-cb-label" style="--c:#e67c73">
          <input type="checkbox" onchange="toggleHide('HIGH', this.checked)"> High
        </label>
        <label class="hide-cb-label" style="--c:#f29900">
          <input type="checkbox" onchange="toggleHide('MEDIUM', this.checked)"> Medium
        </label>
        <label class="hide-cb-label" style="--c:#1e8e3e">
          <input type="checkbox" onchange="toggleHide('LOW', this.checked)"> Low
        </label>
        <label class="hide-cb-label" style="--c:#64748b">
          <input type="checkbox" onchange="toggleHide('FIXED', this.checked)"> Checked (Fixed)
        </label>
      </div>
    </div>
    """

    def severity_badge(sev: str) -> str:
        colors = {
            "CRITICAL": ("#b31412", "#fce8e6"),
            "HIGH":     ("#d93025", "#fce8e6"),
            "MEDIUM":   ("#f29900", "#fef7e0"),
            "LOW":      ("#1e8e3e", "#e6f4ea"),
        }
        fg, bg = colors.get(sev, ("#5f6368", "#f1f3f4"))
        return (
            f'<span style="background:{bg};color:{fg};border:1px solid {bg};'
            f'padding:6px 12px;border-radius:6px;font-size:0.85em;'
            f'font-weight:700;letter-spacing:0.04em">{sev}</span>'
        )

    def conf_bar(score: float | None, label: str = "") -> str:
        if score is None:
            return "N/A"
        pct = int((score or 0) * 100)
        fg = "#1e8e3e" if pct >= 90 else "#f29900" if pct >= 75 else "#d93025"
        label_html = f'<div style="font-size:0.7em; color:var(--muted); font-weight:800; text-transform:uppercase; margin-bottom:6px;">{label}</div>' if label else ""
        return (
            f'<div style="margin-bottom:12px;">{label_html}'
            f'<div style="display:flex;align-items:center;gap:12px">'
            f'<div style="flex:1;height:10px;background:rgba(0,0,0,0.06);border-radius:5px; overflow:hidden;">'
            f'<div style="width:{pct}%;height:100%;background:{fg};border-radius:5px; transition: width 1s ease-out;"></div>'
            f'</div><span style="font-size:1em;color:{fg};font-weight:800">{pct}%</span></div></div>'
        )

    prov_findings = prov.get("findings", {})
    threats_rows = ""
    
    cve_exploit_map = {}
    if cve_matches:
        for cve in cve_matches:
            cid = cve.get("cve_id")
            if cid:
                cve_exploit_map[cid] = cve.get("has_public_exploit", False)

    # Sort findings by severity: Critical > High > Medium > Low
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    sorted_threats = sorted(arbiter.get("confirmed_threats", []), key=lambda x: sev_order.get(x.get("severity", "UNKNOWN").upper(), 4))

    for idx, t in enumerate(sorted_threats):
        tid = t.get('threat_id', 'UNKNOWN')
        t_sev = t.get('severity', 'UNKNOWN').upper()
        
        # Metadata Styles
        meta_style = "font-size:0.85em; font-weight:800; text-transform:uppercase; color:var(--muted);"

        tid_upper = tid.upper()
        db_links_html = ""
        if "CVE-" in tid_upper and tid_upper.startswith("CVE-"):
            tid_html = f'<span class="code-cve">{tid}</span>'
            nvd_url  = f"https://nvd.nist.gov/vuln/detail/{tid}"
            osv_url  = f"https://osv.dev/vulnerability/{tid}"
            
            db_links_html += f'<div class="db-links">'
            db_links_html += f'<a class="db-link db-link-nvd" href="{nvd_url}" target="_blank" rel="noopener">NVD</a>'
            db_links_html += f'<a class="db-link db-link-osv" href="{osv_url}" target="_blank" rel="noopener">OSV</a>'
            
            # Conditionally render ExploitDB only if we fetched a positive signal for it
            if cve_exploit_map.get(tid, False):
                edb_url = f"https://www.exploit-db.com/search?cve={tid}"
                db_links_html += f'<a class="db-link db-link-edb" href="{edb_url}" target="_blank" rel="noopener">ExploitDB</a>'
            
            db_links_html += f'</div>'
        elif tid_upper.startswith("GHSA-"):
            tid_html = f'<span class="code-ghsa">{tid}</span>'
            osv_url = f"https://osv.dev/vulnerability/{tid}"
            gh_url  = f"https://github.com/advisories/{tid}"
            db_links_html = (
                f'<div class="db-links">'
                f'<a class="db-link db-link-osv" href="{osv_url}" target="_blank" rel="noopener">OSV</a>'
                f'<a class="db-link db-link-nvd" href="{gh_url}" target="_blank" rel="noopener">GitHub</a>'
                f'</div>'
            )
        else:
            # SS-POL-*, SS-DISC-*, or any internal code — keep blue code badge
            tid_html = f'<code>{tid}</code>'
            
        # Source Agent formatting for text wrap
        source_agent_display = t.get("source_agent", "Unknown").replace("Agent", " Agent")

        threats_rows += (
            f'<tr class="threat-row" data-severity="{t_sev}" id="row-{idx}" style="animation: fadeInUp 0.4s ease forwards; animation-delay: {0.5 + (idx * 0.08)}s; opacity:0;">'
            f'<td style="width:50px; text-align:center;"><input type="checkbox" class="fixed-check" onchange="toggleFixed({idx}, this)"></td>'
            f'<td><div style="font-weight:700; margin-bottom:6px;">{tid_html}</div>{db_links_html}</td>'
            f'<td><span style="{meta_style}">{source_agent_display}</span></td>'
            f"<td>{severity_badge(t['severity'])}</td>"
            f"<td style='line-height:1.6;color:var(--text); font-weight:500;' class='desc-col'>{t['description']}</td>"
            f'<td><code>{t["nist_reference"]}</code></td>'
            f"</tr>"
        )

    flags_html = ""
    for flag in arbiter.get("low_confidence_flags", []):
        flags_html += f'<li style="margin:10px 0;color:#d28e00; font-weight:500;">{flag}</li>'
    flags_section = ""
    if flags_html:
        flags_section = f"""
        <div class="card glass animate-in" style="border-left: 8px solid #f29900; animation-delay: 0.2s;">
          <div class="card-header" style="color:#d28e00">⚠ Agentic Feedback Loop — Low-Confidence Flags</div>
          <ul style="margin:0;padding-left:26px">{flags_html}</ul>
        </div>"""

    timestamp = arbiter.get("inspection_timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SovereignShield — Customs Inspection Report</title>
  <script>
    if (localStorage.getItem('ss-theme') === 'dark') {{
      document.documentElement.setAttribute('data-theme', 'dark');
    }}
  </script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {{
      --bg: #f5f7fa;
      --glass: rgba(255, 255, 255, 0.82);
      --border: rgba(218, 220, 224, 0.7);
      --text: #1a1b1e;
      --muted: #64748b;
      --accent: #1a73e8;
      --shadow: 0 8px 32px rgba(31, 38, 135, 0.07);
      --inner-bg: rgba(0, 0, 0, 0.04);
    }}
    :root[data-theme="dark"] {{
      --bg: #0f1115;
      --glass: rgba(20, 22, 28, 0.82);
      --border: rgba(255, 255, 255, 0.08);
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #60a5fa;
      --shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      --inner-bg: rgba(255, 255, 255, 0.03);
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Inter', -apple-system, sans-serif;
      background: radial-gradient(circle at top right, #eef2f7, #f5f7fa 40%),
                  radial-gradient(circle at bottom left, #e2e8f0, #f5f7fa 40%);
      background-attachment: fixed;
      color: var(--text);
      padding: 60px 20px;
      min-height: 100vh;
      line-height: 1.6;
    }}
    :root[data-theme="dark"] body {{
      background: radial-gradient(circle at top right, #1a1c23, #0f1115 40%),
                  radial-gradient(circle at bottom left, #14161b, #0f1115 40%);
    }}
    .container {{ max-width: 1140px; margin: 0 auto; }}

    /* Glass Effect & Hover Lift */
    .glass {{
      background: var(--glass);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--border);
      border-radius: 20px;
      box-shadow: var(--shadow);
      transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    }}
    .glass:hover {{
      transform: translateY(-10px) scale(1.01);
      box-shadow: 0 20px 40px rgba(0,0,0,0.12);
      border-color: var(--accent);
    }}

    /* Animations */
    @keyframes fadeInUp {{
      from {{ opacity: 0; transform: translateY(40px); }}
      to {{ opacity: 1; transform: translateY(0); }}
    }}
    .animate-in {{
      animation: fadeInUp 0.8s cubic-bezier(0.2, 0.8, 0.2, 1) forwards;
      opacity: 0;
    }}

    .header {{ display: flex; align-items: center; gap: 28px; margin-bottom: 40px; }}
    .shield-logo {{ width: 72px; height: 72px; filter: drop-shadow(0 8px 12px rgba(0,0,0,0.2)); transition: transform 0.6s ease; }}
    .shield-logo:hover {{ transform: rotate(15deg) scale(1.15); }}
    h1 {{ font-size: 2.5em; font-weight: 900; color: var(--text); letter-spacing: -0.04em; }}
    .subtitle {{ color: var(--muted); font-size: 1.05em; font-weight: 500; margin-top: 4px; }}

    .meta-bar {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 28px; margin-bottom: 40px; padding: 26px 36px;
    }}
    .meta-item {{ font-size: 0.9em; color: var(--muted); font-weight: 800; text-transform: uppercase; letter-spacing: 0.08em; }}
    .meta-item span {{ display: block; color: var(--text); font-weight: 700; margin-top: 6px; font-size: 1.25em; text-transform: none; letter-spacing: normal; }}

    .verdict-banner {{
      display: flex; align-items: center; gap: 40px;
      padding: 36px 48px; margin-bottom: 40px;
      border-left: 10px solid {v_color};
    }}
    .verdict-icon {{ font-size: 4em; filter: drop-shadow(0 6px 8px rgba(0,0,0,0.12)); }}
    .verdict-label {{ font-size: 0.9em; text-transform: uppercase; letter-spacing: 0.2em; color: {v_color}; font-weight: 900; margin-bottom: 6px; }}
    .verdict-text {{ font-family: 'JetBrains Mono', monospace; font-size: 3.2em; font-weight: 800; color: {v_color}; line-height: 1; }}
    .verdict-stats {{ margin-left: auto; display: flex; gap: 56px; text-align: right; }}
    .stat-val {{ font-size: 3em; font-weight: 900; color: {v_color}; line-height: 1; }}
    .stat-label {{ font-size: 0.85em; font-weight: 800; color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em; margin-top: 8px; }}

    .card {{ padding: 40px; margin-bottom: 40px; position: relative; overflow: visible; }}
    .card-header {{
      font-size: 1em; text-transform: uppercase; letter-spacing: 0.15em;
      color: var(--accent); font-weight: 900; margin-bottom: 30px;
      padding-bottom: 16px; border-bottom: 3px solid var(--border);
    }}

    .grid-summary {{ display: grid; grid-template-columns: 1.4fr 1.15fr; gap: 40px; margin-bottom: 40px; align-items: stretch; }}
    
    table {{ width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 16px; }}
    th {{
      text-align: left; padding: 20px; font-size: 0.85em;
      text-transform: uppercase; color: var(--muted); font-weight: 900;
      border-bottom: 3px solid var(--border);
    }}
    td {{ padding: 26px 20px; border-bottom: 1px solid var(--border); font-size: 1em; transition: all 0.3s cubic-bezier(0.19, 1, 0.22, 1); }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: rgba(26, 115, 232, 0.07); transform: translateX(8px); }}
    code {{ 
      font-family: 'JetBrains Mono', monospace; background: rgba(26, 115, 232, 0.07); 
      padding: 4px 10px; border-radius: 6px; font-size: 0.85em; font-weight: 600;
      display: inline-block; margin: 2px 0; color: var(--accent);
      border: 1px solid rgba(26, 115, 232, 0.1); text-transform: uppercase;
    }}
    /* CVE badge — red tint, same geometry as blue code but danger-coloured */
    .code-cve {{
      font-family: 'JetBrains Mono', monospace;
      background: rgba(217, 48, 37, 0.08);
      padding: 4px 10px; border-radius: 6px; font-size: 0.85em; font-weight: 700;
      display: inline-block; margin: 2px 0; color: #d93025;
      border: 1px solid rgba(217, 48, 37, 0.22); text-transform: uppercase;
      letter-spacing: 0.03em;
    }}
    /* GHSA badge — amber tint for open-source advisories */
    .code-ghsa {{
      font-family: 'JetBrains Mono', monospace;
      background: rgba(242, 153, 0, 0.09);
      padding: 4px 10px; border-radius: 6px; font-size: 0.85em; font-weight: 700;
      display: inline-block; margin: 2px 0; color: #c77b00;
      border: 1px solid rgba(242, 153, 0, 0.25); text-transform: uppercase;
      letter-spacing: 0.03em;
    }}
    /* small icon links next to CVE/GHSA badges */
    .db-links {{ display: flex; gap: 6px; margin-top: 6px; flex-wrap: wrap; }}
    .db-link {{
      display: inline-flex; align-items: center; gap: 4px;
      font-family: 'Inter', sans-serif; font-size: 0.72em; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.06em;
      padding: 3px 8px; border-radius: 4px; text-decoration: none;
      transition: all 0.2s ease; border: 1px solid;
    }}
    .db-link-nvd  {{ color: #1a73e8; border-color: rgba(26,115,232,0.3); background: rgba(26,115,232,0.06); }}
    .db-link-nvd:hover  {{ background: rgba(26,115,232,0.14); transform: translateY(-1px); }}
    .db-link-edb  {{ color: #d93025; border-color: rgba(217,48,37,0.3);  background: rgba(217,48,37,0.06); }}
    .db-link-edb:hover  {{ background: rgba(217,48,37,0.14); transform: translateY(-1px); }}
    .db-link-osv  {{ color: #1e8e3e; border-color: rgba(30,142,62,0.3);  background: rgba(30,142,62,0.06); }}
    .db-link-osv:hover  {{ background: rgba(30,142,62,0.14); transform: translateY(-1px); }}
    .tid-col {{ min-width: 260px; }}

    .action-box {{
      margin-top: 32px; padding: 28px; border-radius: 16px;
      background: rgba(26, 115, 232, 0.1); border-left: 8px solid var(--accent);
      transition: background 0.3s ease;
    }}
    .action-box:hover {{ background: rgba(26, 115, 232, 0.15); }}
    .action-label {{ font-size: 0.85em; text-transform: uppercase; font-weight: 900; color: var(--accent); margin-bottom: 12px; letter-spacing: 0.1em; }}
    
    .filter-chip {{
      padding: 10px 22px; border-radius: 30px; border: 1px solid var(--border);
      background: var(--glass); color: var(--muted); cursor: pointer;
      font-size: 0.85em; font-weight: 800; text-transform: uppercase;
      transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
      letter-spacing: 0.05em;
    }}
    .filter-chip:hover {{ transform: translateY(-3px); border-color: var(--accent); color: var(--accent); }}
    .filter-chip.active {{
      background: var(--accent); color: white; border-color: var(--accent);
      box-shadow: 0 4px 12px rgba(26, 115, 232, 0.4);
    }}
    .filter-chip.active[style*="--c"] {{
      background: var(--c); border-color: var(--c);
      box-shadow: 0 4px 12px var(--c);
    }}

    .threat-row.is-fixed {{ opacity: 0.4; filter: grayscale(0.8); }}
    .threat-row.is-fixed .desc-col {{ text-decoration: line-through; }}
    
    .fixed-check {{
      width: 20px; height: 20px; cursor: pointer; accent-color: var(--accent);
      transition: transform 0.2s ease;
    }}
    .fixed-check:hover {{ transform: scale(1.2); }}

    .chart-container {{ height: 320px; position: relative; padding: 15px; overflow: visible; }}

    footer {{
      margin-top: 100px; text-align: center; color: var(--muted); font-size: 0.9em;
      padding-top: 50px; border-top: 1px solid var(--border); font-weight: 600;
    }}
  </style>
</head>
<body>
<div class="container">

  <header class="header animate-in">
    <img src="{logo_base64}" alt="SovereignShield Logo" class="shield-logo">
    <div>
      <h1>SovereignShield</h1>
      <div class="subtitle">Customs Inspection Report &bull; Strategic Supply-Chain Defense Dashboard</div>
    </div>
    <button id="themeToggle" style="margin-left:auto; padding:10px 18px; border-radius:30px; border:1px solid var(--border); background:var(--glass); color:var(--text); cursor:pointer; font-weight:800; font-size:0.9em; box-shadow:var(--shadow); transition:all 0.3s; display:flex; align-items:center; gap:8px;">
      🌓 <span style="opacity: 0.8;">Toggle Dark</span>
    </button>
  </header>

  <div class="meta-bar glass animate-in" style="animation-delay: 0.1s;">
    <div class="meta-item">Package <span>{arbiter.get('package', 'N/A')}</span></div>
    <div class="meta-item">Vendor <span>{arbiter.get('vendor', 'Unknown')}</span></div>
    <div class="meta-item">Timestamp <span>{timestamp}</span></div>
    <div class="meta-item">Framework <span>NIST SP 800-218</span></div>
  </div>

  <div class="verdict-banner glass animate-in" style="animation-delay: 0.15s;">
    <div class="verdict-icon">{v_icon}</div>
    <div>
      <div class="verdict-label">Official Verdict</div>
      <div class="verdict-text">{verdict}</div>
    </div>
    <div class="verdict-stats">
      <div>
        <div class="stat-val">{arbiter.get('total_violations', 0)}</div>
        <div class="stat-label">Violations</div>
      </div>
      <div>
        <div class="stat-val">{int((sys_confidence or 0)*100)}%</div>
        <div class="stat-label">Composite Trust</div>
      </div>
    </div>
  </div>

  <div class="grid-summary">
    <div class="card glass animate-in" style="animation-delay: 0.2s;">
      <div class="card-header">⚖️ Executive Risk Rationale</div>
      <p style="font-size: 1.15em; line-height: 1.8; font-weight: 500;">{arbiter.get('verdict_rationale', 'N/A')}</p>
      <div class="action-box glass" style="box-shadow: none;">
        <div class="action-label">Recommended Action</div>
        <div style="font-weight: 700; font-size: 1.1em;">{arbiter.get('recommended_action', 'N/A')}</div>
      </div>
    </div>

    <div class="card glass animate-in" style="animation-delay: 0.3s;">
      <div class="card-header">📊 Risk Profile Index</div>
      <div class="chart-container">
        <canvas id="riskChart"></canvas>
      </div>
    </div>
  </div>

  {flags_section}

  <div class="card glass animate-in" style="animation-delay: 0.4s;">
    <div class="card-header">🔎 Detailed Forensics & Proof</div>
    
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 40px; margin-bottom: 40px;">
      <div class="glass" style="padding: 24px; background: var(--inner-bg); border-radius: 16px; box-shadow: none;">
        <div style="margin-bottom: 20px; font-size: 0.9em; font-weight: 900; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em;">Agent Confidence Levels</div>
        {conf_bar(decomp.get('overall_confidence'), '<span class="agent-tooltip" data-tooltip="Dissects binary artifacts, identifies deeply embedded or hidden open-source dependencies not declared in vendor SBOMs.">Decomposition Analysis Agent ⓘ</span>')}
        <div style="margin-top: 16px;"></div>
        {conf_bar(prov.get('overall_confidence'), '<span class="agent-tooltip" data-tooltip="Verifies digital signatures, certificates, origin country, and ensures alignment with Zero-Trust policies.">Provenance Verification Agent ⓘ</span>')}
      </div>
      
      <div class="glass" style="padding: 24px; background: var(--inner-bg); border-radius: 16px; display: grid; gap: 14px; font-size: 1em; box-shadow: none;">
         <div style="font-size: 0.9em; font-weight: 900; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em;">Compliance Metadata</div>
         <div>Origin Country: <strong style="float:right; color:var(--accent);">{prov_findings.get('compile_origin','N/A')}</strong></div>
         <div>Cert Validation: <strong style="float:right; color:{'#d93025' if prov_findings.get('cert_status')=='EXPIRED' else '#1e8e3e'}">{prov_findings.get('cert_status','N/A')}</strong></div>
         <div>Sec Signature: <strong style="float:right; color:{'#d93025' if prov_findings.get('signature_status')=='MISMATCH' else '#1e8e3e'}">{prov_findings.get('signature_status','N/A')}</strong></div>
      </div>
    </div>

    {filters_html}

    <div style="background: var(--glass); border-radius: 12px; padding-bottom: 10px;">
      <table style="width:100%; table-layout:auto;">
      <thead>
        <tr>
          <th style="width:50px; text-align:center;">Status</th>
          <th style="width:240px;">Target ID</th><th>Discovery Agent</th><th>Severity</th><th>Description</th><th>NIST Clause</th>
        </tr>
      </thead>
      <tbody>
        {threats_rows if threats_rows else "<tr><td colspan='6' style='text-align:center; padding: 70px; color: var(--muted); font-weight: 700; font-size: 1.1em;'>Clean Sweep: No vulnerabilities identified.</td></tr>"}
      </tbody>
    </table>
    </div>
  </div>

  <footer>
    &copy; 2026 SovereignShield Security Pipeline &bull; v1.4 High-Performance Edition &bull; NIST SP 800-218 RV.1.3 Compliance
  </footer>
</div>

<script>
  const ctx = document.getElementById('riskChart').getContext('2d');
  window.myRiskChart = new Chart(ctx, {{
    type: 'doughnut',
    data: {{
      labels: {json.dumps(sev_labels)},
      datasets: [{{
        data: [{sev_counts['CRITICAL']}, {sev_counts['HIGH']}, {sev_counts['MEDIUM']}, {sev_counts['LOW']}],
        backgroundColor: ['#b31412', '#d93025', '#f29900', '#1e8e3e'],
        borderWidth: 0,
        hoverOffset: 25
      }}]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      layout: {{ padding: {{ left: 10, right: 30, top: 30, bottom: 30 }} }},
      plugins: {{
        legend: {{ 
          position: 'right', 
          labels: {{ 
            usePointStyle: true, padding: 25,
            font: {{ size: 16, weight: '800', family: "'Inter', sans-serif" }},
            color: (localStorage.getItem('ss-theme') === 'dark' ? '#e2e8f0' : '#1a1b1e')
          }} 
        }},
        tooltip: {{
          enabled: true,
          backgroundColor: 'rgba(26, 27, 30, 0.95)',
          padding: 16,
          titleFont: {{ size: 16, weight: '900' }},
          bodyFont: {{ size: 14, weight: '700' }},
          cornerRadius: 12, displayColors: true, boxPadding: 8
        }}
      }}
    }}
  }});

  window.currentSeverity = 'ALL';
  window.hiddenToggles = {{
    'CRITICAL': false,
    'HIGH': false,
    'MEDIUM': false,
    'LOW': false,
    'FIXED': false
  }};

  function applyFilters() {{
    document.querySelectorAll('.threat-row').forEach(row => {{
      const rowSev = row.dataset.severity;
      const isFixed = row.classList.contains('is-fixed');
      
      // Compute visibility
      let visible = (window.currentSeverity === 'ALL' || rowSev === window.currentSeverity);
      if (visible && window.hiddenToggles['FIXED'] && isFixed) visible = false;
      if (visible && window.hiddenToggles[rowSev]) visible = false;

      row.style.display = visible ? 'table-row' : 'none';
    }});
  }}

  function setSeverityFilter(severity, btn) {{
    document.querySelectorAll('.filter-chip').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    window.currentSeverity = severity;
    applyFilters();
  }}

  function toggleHide(key, checked) {{
    window.hiddenToggles[key] = checked;
    applyFilters();
  }}

  function toggleFixed(idx, check) {{
    const row = document.getElementById('row-' + idx);
    if (check.checked) {{
      row.classList.add('is-fixed');
      localStorage.setItem('ss-fixed-' + idx, 'true');
    }} else {{
      row.classList.remove('is-fixed');
      localStorage.removeItem('ss-fixed-' + idx);
    }}
    applyFilters();
  }}

  // Persistence on load
  window.onload = () => {{
    const toggleBtn = document.getElementById('themeToggle');
    toggleBtn.addEventListener('click', () => {{
      const root = document.documentElement;
      const isDark = root.getAttribute('data-theme') === 'dark';
      const newTheme = isDark ? 'light' : 'dark';
      root.setAttribute('data-theme', newTheme);
      localStorage.setItem('ss-theme', newTheme);
      
      if (window.myRiskChart) {{
        window.myRiskChart.options.plugins.legend.labels.color = (newTheme === 'dark') ? '#e2e8f0' : '#1a1b1e';
        window.myRiskChart.update();
      }}
    }});

    document.querySelectorAll('.fixed-check').forEach((check, idx) => {{
      if (localStorage.getItem('ss-fixed-' + idx)) {{
        check.checked = true;
        document.getElementById('row-' + idx).classList.add('is-fixed');
      }}
    }});
  }};
</script>
</body>
</html>"""

    pkg_dir = OUTPUT_DIR / pkg_name
    pkg_dir.mkdir(parents=True, exist_ok=True)
    out_path = pkg_dir / f"{pkg_name}_{ts_str}.html"
    
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print_ok(f"HTML report written  → {out_path.relative_to(PROJECT_ROOT)}")



# ── Pipeline orchestrator ──────────────────────────────────────────────────────

def run_pipeline(target_binary: str | None = None, policy_path_override: str | None = None, vendor_sbom_override: str | None = None):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print_banner()

    # ── Phase 1 & 2 ────────────────────────────────────────────────────────────
    if not target_binary:
        print_error("FATAL: A target binary path must be provided. Interactive demo mode has been removed for production.")
        sys.exit(1)
        
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
            # For production missing a policy, fallback to the internal default policy
            if config.DEFAULT_POLICY.exists():
                policy = load_text(config.DEFAULT_POLICY)
                print_ok("zero_trust_policy.txt loaded from Internal Default Rules")
            else:
                print_warn("No local or internal policy found. Defaulting to strict inference.")
                policy = "Default strict zero-trust parameters inferred."
    
    # Execute Pipeline Deep Scan logic natively
    deep_scan = run_deep_scan(target_path)
    print_ok(f"Deep scan phase successfully generated internal SBOM map for {target_path.name}")

    print_section("PYTHON PRE-PROCESSING", phase=2)
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
    print_info(f"Processing {diff.get('hidden_count', 0)} hidden deps → "
               f"{-(-diff.get('hidden_count',0) // config.DECOMP_CHUNK_SIZE) or 1} batch(es) "
               f"× {config.DECOMP_CHUNK_SIZE} pkgs, up to {config.DECOMP_MAX_THREADS} parallel threads ...")
    decomp_result = decomposition_agent.run(diff, cve_matches)
    print_ok(f"Batches processed     : {decomp_result.get('batch_count', 1)} "
             f"({decomp_result.get('thread_count', 1)} thread(s), "
             f"{decomp_result.get('wall_clock_seconds', '?')}s wall-clock)")
    print_ok(f"Findings returned     : {decomp_result.get('actual_finding_count', len(decomp_result.get('findings', [])))} hidden dependency assessments")
    print_ok(f"Confidence score      : {decomp_result.get('overall_confidence')}")
    if decomp_result.get("grounding_warnings"):
        print_warn(f"Grounding warnings    : {len(decomp_result['grounding_warnings'])} hallucination(s) stripped")


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
    target_path = Path(target_binary)
    pkg_name = target_path.name
    vnd_name = "Unknown Vendor"

    arbiter_result = arbiter_agent.run(
        decomp_findings=decomp_result, 
        prov_findings=prov_result,
        package_name=pkg_name,
        vendor_name=vnd_name
    )

    # ── Phase 6: Generate output reports ─────────────────────────────────────
    print_section("GENERATING INSPECTION REPORTS", phase=6)
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    write_json_report(arbiter_result, decomp_result, prov_result, ts_str, cve_matches)
    write_html_report(arbiter_result, decomp_result, prov_result, ts_str, cve_matches)

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
    wrapped_rationale = textwrap.fill(rationale, width=80, initial_indent="  → Rationale  : ", subsequent_indent="                 ")
    wrapped_rationale = wrapped_rationale.replace("  → Rationale  : ", f"  {_c(CYAN, '→')} Rationale  : ", 1)
    print(wrapped_rationale)
    
    action = arbiter_result.get("recommended_action", "N/A")
    wrapped_action = textwrap.fill(action, width=80, initial_indent="  → Action     : ", subsequent_indent="                 ")
    wrapped_action = wrapped_action.replace("  → Action     : ", f"  {_c(CYAN, '→')} Action     : ", 1)
    print(wrapped_action)
    print()
    out_pkg_name = arbiter_result.get("package", "UnknownApp").replace(" ", "_")
    final_dir = OUTPUT_DIR.relative_to(PROJECT_ROOT) / out_pkg_name
    print_ok(f"Full reports saved to .\\{final_dir}\\")
    print(_c(CYAN, "═" * 68))


if __name__ == "__main__":
    run_pipeline()
