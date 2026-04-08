"""
run.py
──────
Convenience launcher for the SovereignShield pipeline.

Performs a pre-flight environment check before invoking main.py
so that missing credentials produce a clear, actionable error message.

Usage:
    python run.py
"""

import os
import sys
import argparse
from pathlib import Path

def preflight_check():
    """Verify that all required environment variables are set."""
    env_file = Path(".env")
    if env_file.exists():
        from dotenv import load_dotenv
        load_dotenv()

    missing = []
    for var in ("WATSONX_API_KEY", "WATSONX_PROJECT_ID", "WATSONX_URL"):
        val = os.getenv(var, "")
        if not val or val.startswith("your_"):
            missing.append(var)

    if missing:
        print()
        print("  ╔══════════════════════════════════════════════════════════╗")
        print("  ║         SovereignShield — Pre-flight Check FAILED        ║")
        print("  ╚══════════════════════════════════════════════════════════╝")
        print()
        print("  The following .env variables are missing or still set to placeholders:")
        for v in missing:
            print(f"    ✗  {v}")
        print()
        print("  Steps to fix:")
        print("  1. Open .env in the project root")
        print("  2. Set WATSONX_API_KEY  → your IBM Cloud API key")
        print("  3. Set WATSONX_PROJECT_ID → your watsonx.ai project ID")
        print("     (find it: watsonx.ai → project → Manage → General → Details)")
        print("  4. Set WATSONX_URL if you are outside us-south region")
        print()
        sys.exit(1)

    print("  ✓  Pre-flight check passed")


if __name__ == "__main__":
    preflight_check()
    from sovereignshield import main
    
    parser = argparse.ArgumentParser(description="SovereignShield Customs Pipeline")
    parser.add_argument("--target", type=str, help="Path to a live binary to scan.")
    parser.add_argument("--demo", action="store_true", help="Run the pipeline in demonstration mode using mock data.")
    parser.add_argument("--policy", type=str, help="Path to a custom zero trust policy file")
    parser.add_argument("--vendor-sbom", type=str, help="Path to a custom vendor sbom file")
    
    args = parser.parse_args()
    
    if args.target:
        main.run_pipeline(target_binary=args.target, policy_path_override=args.policy, vendor_sbom_override=args.vendor_sbom)
    else:
        print("\n\033[93m[INFO] Running in DEMO mode. (Pass --target <path> to scan a live binary)\033[0m")
        main.run_pipeline(target_binary=None)
