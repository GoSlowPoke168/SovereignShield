"""
config.py
─────────
Central configuration and constants for the SovereignShield pipeline.
All hardcoded filenames, paths, URLs, and thresholds are defined here.
"""

import os
from pathlib import Path

# ── System Paths ──────────────────────────────────────────────────────────────
SOVEREIGNSHIELD_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SOVEREIGNSHIELD_DIR.parent
MOCK_DIR = PROJECT_ROOT / "data" / "mock_payloads"
OUTPUT_DIR = PROJECT_ROOT / "data" / "reports"
TOOLS_DIR = PROJECT_ROOT / "tools"

SYFT_BIN_WIN = TOOLS_DIR / "syft.exe"
SYFT_BIN_NIX = TOOLS_DIR / "syft"

# ── Detection Rules ───────────────────────────────────────────────────────────
# Expanded SBOM candidate list provided by user
SBOM_CANDIDATES = [
    "sbom.json", "sbom.xml", "sbom.spdx.json", "sbom.spdx.yaml",
    "sbom.spdx.rdf", "sbom.spdx.tag", "spdx.json", "spdx.xml",
    "spdx.rdf", "spdx.tag", "cyclonedx.json", "cyclonedx.xml",
    "cyclonedx.yaml", "cdx.json", "cdx.xml", "cdx.yaml",
    "swid.xml", "software-id.swidtag", "bom.json", "bom.xml"
]

# Comprehensive manifest list provided by user (merged and unique)
COMMON_MANIFESTS = sorted(list({
    # Existing defaults
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "setup.py", "pyproject.toml",
    "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock", "composer.json", "composer.lock", "Gemfile", "Gemfile.lock",
    # User additions
    "AndroidManifest.xml", "app.manifest", "AssemblyInfo.cs", "bower.json", "Chart.yaml",
    "config.xml", "csproj", "deps.edn", "environment.yml", "gradle.properties",
    "Info.plist", "manifest.json", "manifest.webmanifest", "mix.exs", "module-info.java",
    "packages.config", "pipfile", "pipfile.lock", "project.clj", "project.json",
    "pubspec.yaml", "requirements.in", "setup.cfg", "stack.yaml", "tsconfig.json",
    "Vagrantfile", "version.json", "webpack.config.js", "Makefile", "Rakefile",
    "build.sbt", "flake.nix", "Cargo.metadata.json"
}))

IGNORE_DIRS = {"node_modules", "venv", ".venv", ".git", "target", "build", "__pycache__"}

# ── Logic Thresholds & Limits ────────────────────────────────────────────────
VERSION = "1.1.0"
CONFIDENCE_THRESHOLD = 0.75
MAX_HIDDEN_DEPS_FOR_QUERY = 100
MAX_CVE_MATCHES = 50
MAX_VULNS_PER_PACKAGE = 10
MAX_RETRIES = 2
SYFT_TIMEOUT = 600  # 10 minute strict timeout

# ── Networking & Cache ───────────────────────────────────────────────────────
EXPLOIT_DB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
CACHE_FILE = PROJECT_ROOT / "data" / "exploitdb_cache.csv"
OSV_URL = "https://api.osv.dev/v1/query"

# ── WatsonX Model Settings ────────────────────────────────────────────────────
DEFAULT_MODEL = "ibm/granite-4-h-small"
MODEL_PARAMS = {
    "max_tokens": 8192,
    "temperature": 0.05,
    "repetition_penalty": 1.1,
}
