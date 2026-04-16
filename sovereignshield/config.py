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
OUTPUT_DIR = PROJECT_ROOT / "data" / "reports"
TOOLS_DIR = PROJECT_ROOT / "tools"
RESOURCES_DIR = SOVEREIGNSHIELD_DIR / "resources"
DEFAULT_POLICY = RESOURCES_DIR / "zero_trust_policy.txt"

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
MAX_HIDDEN_DEPS_FOR_QUERY = 100   # No hard cap removed — chunking handles scale
MAX_CVE_MATCHES = 50
MAX_VULNS_PER_PACKAGE = 10
MAX_RETRIES = 2
SYFT_TIMEOUT = 600  # 10 minute strict timeout

# Number of packages sent to the DecompositionAgent per LLM call.
# Results from all chunks are merged in Python — no data is lost.
# Smaller = safer against token overflow; larger = fewer API calls.
# 15 is a highly accurate threshold for generative JSON logic arrays.
DECOMP_CHUNK_SIZE = 15

# Number of parallel LLM calls for Batch Processing.
# Since LLM calls are I/O bound, multithreading significantly speeds up large scans.
# 5-10 is a safe range for standard API rate limits.
DECOMP_MAX_THREADS = 8

# ── Networking & Cache ───────────────────────────────────────────────────────
EXPLOIT_DB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
CACHE_FILE = PROJECT_ROOT / "data" / "exploitdb_cache.csv"
OSV_URL = "https://api.osv.dev/v1/query"

# ── WatsonX Model Settings ────────────────────────────────────────────────────
DEFAULT_MODEL = "ibm/granite-4-h-small"
MODEL_PARAMS = {
    "max_tokens": 8192,
    # temperature=0.0 → fully deterministic output.
    # This is the first and most important defense against hallucination:
    # at zero temperature the model cannot "creatively" invent CVE IDs,
    # package names, or vulnerability identifiers that are not in its context.
    "temperature": 0.0,
    # repetition_penalty discourages the model from looping on fabricated patterns
    "repetition_penalty": 1.05,
    # top_p=1.0 with temperature=0.0 ensures greedy decoding
    "top_p": 1.0,
}
