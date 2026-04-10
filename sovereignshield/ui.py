"""
ui.py
─────
Terminal UI and logging logic for SovereignShield.
Encapsulates all ANSI escape codes and terminal formatting.
"""

import sys

# ── ANSI Color Codes ──────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"

def supports_color() -> bool:
    """Return True if the terminal likely supports ANSI color codes."""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

def c(code: str, text: str) -> str:
    """Wrap text in a color code if supported."""
    return f"{code}{text}{RESET}" if supports_color() else text

# ── General UI Components ─────────────────────────────────────────────────────

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
    print(c(CYAN, banner))

def print_section(title: str, phase: int | None = None):
    label = f"  PHASE {phase}: {title}" if phase else f"  {title}"
    print()
    print(c(CYAN, "═" * 68))
    print(c(BOLD + WHITE, label))
    print(c(CYAN, "═" * 68))

def print_ok(msg: str):
    print(f"  {c(GREEN, '✓')} {msg}")

def print_info(msg: str):
    print(f"  {c(CYAN, '→')} {msg}")

def print_warn(msg: str):
    print(f"  {c(YELLOW, '⚠')} {msg}")

def print_error(msg: str):
    print(f"  {c(RED, '✘')} {msg}")

# ── Specialized Component UI ──────────────────────────────────────────────────

def scanner_status(char: str, name: str, elapsed: int, eta: str):
    """Update the live scanner status line."""
    # Truncate filename if it's too long
    display_name = name
    if len(display_name) > 24:
        display_name = display_name[:21] + "..."
    
    # \033[2K clears the line, \r returns to start
    msg = f"\r\033[2K  {c(CYAN, char)} [Scanner] Scanning {display_name} ({elapsed}s | {eta}) "
    sys.stdout.write(msg)
    sys.stdout.flush()

def scanner_bypass(format_name: str, file_name: str):
    """Print a scanner bypass message."""
    sys.stdout.write(f"\r  {c(CYAN, '✓')} [Scanner] Bypassing Syft — native {format_name} detected ({file_name})\n")
    sys.stdout.flush()

def scanner_auto_detect(folder_type: str, file_name: str):
    """Print an auto-detection message."""
    sys.stdout.write(f"\r  {c(CYAN, '✓')} [Scanner] Auto-detected {folder_type} ({file_name})\n")
    sys.stdout.flush()

def clear_line():
    """Clear the current line cleanly."""
    sys.stdout.write("\r" + " " * 120 + "\r")
    sys.stdout.flush()
