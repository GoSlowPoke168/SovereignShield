"""
scanner.py
──────────
Handles local execution of Syft on live binaries.
Normalizes Syft's verbose JSON out into the SovereignShield expected format.
"""

import json
import os
import subprocess
import threading
import time
import sys
from pathlib import Path

# Look for syft in the project's tools folder. 
# Allow .exe for Windows or no extension for Linux/Mac.
PROJECT_ROOT = Path(__file__).parent.parent
SYFT_BIN_WIN = PROJECT_ROOT / "tools" / "syft.exe"
SYFT_BIN_NIX = PROJECT_ROOT / "tools" / "syft"

def get_syft_path() -> Path:
    if SYFT_BIN_WIN.exists():
        return SYFT_BIN_WIN
    if SYFT_BIN_NIX.exists():
        return SYFT_BIN_NIX
    
    # If not found locally, see if syft is magically in the system PATH
    import shutil
    global_syft = shutil.which("syft")
    if global_syft:
        return Path(global_syft)
        
    raise FileNotFoundError(
        "Syft executable not found! Please manually download syft and place it in "
        f"the tools directory at {SYFT_BIN_WIN} or {SYFT_BIN_NIX}."
    )


def get_total_size(path: Path) -> int:
    """Return total size in bytes for a file or an entire directory, escaping heavy ignores."""
    if path.is_file():
        return path.stat().st_size
    elif path.is_dir():
        total = 0
        ignore_dirs = {"node_modules", "venv", ".venv", ".git", "target", "build", "__pycache__"}
        
        # Manually walk to avoid rglob descending into 200,000 file node_modules
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for f in files:
                filepath = Path(root) / f
                if not filepath.is_symlink():
                    try:
                        total += filepath.stat().st_size
                    except Exception:
                        pass
        return total
    return 0


def run_deep_scan(target_binary: str | Path) -> dict:
    """
    Executes Syft on a target binary to generate a deep-scan SBOM dynamically,
    OR directly parses a CycloneDX JSON file if the target is already an SBOM.
    OR smartly delegates to specific valid package manifests in a directory.
    """
    target = Path(target_binary).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target binary not found: {target}")

    target_to_parse = [target]
    is_native_sbom_candidate = False

    # --- AUTO-DETECT SBOM OR ROUTE DIRECTORY MANIFESTS ---
    if target.is_dir():
        # Look for explicit SBOM files inside the root directory to instantly bypass
        for candidate in ["bom.json", "sbom.json", "cyclonedx.json", "spdx.json"]:
            potential_sbom = target / candidate
            if potential_sbom.exists():
                sys.stdout.write(f"\r  \033[96m✓\033[0m [Scanner] Auto-detected embedded SBOM inside folder ({candidate})\n")
                sys.stdout.flush()
                target_to_parse = [potential_sbom]
                is_native_sbom_candidate = True
                break
                
        # If no SBOM found, run the Intelligent Python Router to grab manifests
        if not is_native_sbom_candidate:
            common_manifests = {
                "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "setup.py", "pyproject.toml",
                "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "go.sum",
                "Cargo.toml", "Cargo.lock", "composer.json", "composer.lock", "Gemfile", "Gemfile.lock"
            }
            ignore_dirs = {"node_modules", "venv", ".venv", ".git", "target", "build", "__pycache__"}
            
            collected_manifests = []
            nested_sbom_candidate = None
            for root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if d not in ignore_dirs]
                for f in files:
                    lower_f = f.lower()
                    if "bom" in lower_f or "sbom" in lower_f or "cyclonedx" in lower_f or "spdx" in lower_f:
                        if lower_f.endswith(".json"):
                            nested_sbom_candidate = Path(root) / f
                            break # Found a deep native SBOM, stop searching
                    elif f in common_manifests:
                        collected_manifests.append(Path(root) / f)
                if nested_sbom_candidate:
                    break
            
            if nested_sbom_candidate:
                sys.stdout.write(f"\r  \033[96m✓\033[0m [Scanner] Auto-detected deeply nested SBOM ({nested_sbom_candidate.name})\n")
                sys.stdout.flush()
                target_to_parse = [nested_sbom_candidate]
                is_native_sbom_candidate = True
            elif collected_manifests:
                sys.stdout.write(f"\r  \033[96m✓\033[0m [Scanner] Smart Router identified {len(collected_manifests)} specific package manifests to parse.\n")
                sys.stdout.flush()
                target_to_parse = collected_manifests
            else:
                sys.stdout.write(f"\r  \033[93m⚠\033[0m [Scanner] No recognizable manifests found. Falling back to heavy full-directory Syft scan.\n")
                sys.stdout.flush()
    else:
        # It's a single file, explicitly check if it's a JSON
        if target.suffix.lower() == ".json":
            is_native_sbom_candidate = True

    # --- NATIVE SBOM INGESTION BYPASS ---
    # Only try to bypass if exactly one JSON file is determined to be the target
    if is_native_sbom_candidate and len(target_to_parse) == 1 and target_to_parse[0].suffix.lower() == ".json":
        native_target = target_to_parse[0]
        try:
            with open(native_target, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # 1. CycloneDX detection
            if "components" in data:
                sys.stdout.write(f"\r  \033[96m✓\033[0m [Scanner] Bypassing Syft — native CycloneDX SBOM detected ({native_target.name})\n")
                sys.stdout.flush()
                
                detected = []
                for comp in data.get("components", []):
                    if "name" in comp and "version" in comp:
                        detected.append({
                            "name": comp["name"],
                            "version": comp["version"]
                        })
                return {"detected_dependencies": detected}
                
            # 2. SPDX Format detection
            elif "packages" in data and any("SPDX" in str(v) for v in data.values()):
                sys.stdout.write(f"\r  \033[96m✓\033[0m [Scanner] Bypassing Syft — native SPDX SBOM detected ({native_target.name})\n")
                sys.stdout.flush()
                
                detected = []
                for pkg in data.get("packages", []):
                    if "name" in pkg and "versionInfo" in pkg:
                        detected.append({
                            "name": pkg["name"],
                            "version": pkg["versionInfo"]
                        })
                return {"detected_dependencies": detected}
                
            # 3. Native SovereignShield Format fallback
            elif "detected_dependencies" in data:
                sys.stdout.write(f"\r  \033[96m✓\033[0m [Scanner] Bypassing Syft — native SovereignShield SBOM detected ({native_target.name})\n")
                sys.stdout.flush()
                return data
                
        except Exception as e:
            sys.stdout.write(f"\r  \033[93m⚠\033[0m [Scanner] Failed to parse {native_target.name} natively. Falling back to Syft... \n")
            sys.stdout.flush()

    syft_cmd = get_syft_path()
    
    # Estimate time based on total payload size (Roughly 5MB per second parsing on normal machines)
    total_bytes = get_total_size(target)
    file_size_mb = total_bytes / (1024 * 1024)
    estimated_seconds = max(2, int(file_size_mb / 2.0)) # Adjusted to ~2MB/s given Syft's dense folder overhead
    
    stop_event = threading.Event()
    
    def spinner_task():
        spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        start_time = time.time()
        i = 0
        while not stop_event.is_set():
            elapsed = time.time() - start_time
            remaining = max(0, estimated_seconds - int(elapsed))
            eta_str = f"~{remaining}s remaining" if remaining > 0 else "Finishing up..."
            
            # Print spinner with cyan color styling matching SovereignShield UI
            target_display_name = target.name if len(target_to_parse) > 1 else target_to_parse[0].name
            sys.stdout.write(f"\r  \033[96m{spinner[i % len(spinner)]}\033[0m [Scanner] Executing Syft deep scan on {target_display_name} (Elapsed: {int(elapsed)}s | {eta_str})   ")
            sys.stdout.flush()
            i += 1
            time.sleep(0.1)
            
    spinner_thread = threading.Thread(target=spinner_task)
    spinner_thread.start()

    try:
        all_artifacts = []
        for t in target_to_parse:
            cmd_args = [str(syft_cmd), str(t), "-o", "json", "-q", "--exclude", "**/node_modules/**", "--exclude", "**/venv/**"]
            result = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                check=True,
                timeout=300 # 5 minute strict timeout to prevent permanent hangs
            )
            try:
                syft_data = json.loads(result.stdout)
                all_artifacts.extend(syft_data.get("artifacts", []))
            except json.JSONDecodeError:
                raise ValueError(f"Syft returned invalid JSON output for {t}.")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"\nSyft execution timed out after 300 seconds processing {target.name}.")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"\nSyft execution failed with exit code {e.returncode}.\nStderr: {e.stderr}")
    finally:
        stop_event.set()
        spinner_thread.join()
        sys.stdout.write("\r" + " " * 120 + "\r") # clear the line cleanly
        sys.stdout.flush()
        
    # Normalize to SovereignShield format
    # Syft stores finding packages in 'artifacts'
    detected = []
    seen = set()
    for artifact in all_artifacts:
        name = artifact.get("name", "Unknown")
        version = artifact.get("version", "Unknown")
        key = (name, version)
        if key not in seen:
            seen.add(key)
            detected.append({
                "name": name,
                "version": version
            })

    return {
        "detected_dependencies": detected
    }
