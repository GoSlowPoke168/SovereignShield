# SovereignShield 🛡️

**Automated Supply-Chain Customs Inspection Pipeline**  
NIST SP 800-218 Aligned · IBM Granite 3.3 · Zero-Trust Architecture

---

## Overview

SovereignShield is a universally adaptable, enterprise-grade, crash-resistant security auditing three-agent AI pipeline. It treats all incoming software updates, binaries, and dependencies as potentially hostile. SovereignShield cross-examines vendor-declared SBOMs against deep-scan results, checks compile provenance against strict zero-trust policies, and issues a confidence-scored, evidence-backed **BLOCK** or **ALLOW** verdict — automatically generating a high-fidelity Executive Security Dashboard.

```text
[Software Target] → [Deep Scan / Manifest Discovery] → [Python Pre-Processor]
                                                     → [Decomposition Agent]
                                                     → [Provenance Agent]
                                                     → [Arbiter Agent]
                                                     → [Inspection Dashboard (BLOCK | ALLOW)]
```

---

## Key Capabilities

- **Production-Hardened CLI:** Strictly enforced CLI interface geared for seamless CI/CD integration. No legacy mock environments or fallback demo modes.
- **High-Fidelity Executive Dashboard:** Generates dynamic, glassmorphism-styled HTML reports incorporating an interactive Risk Profile Index (Chart.js), dark-mode styling, and accessible UI indicators.
- **Dynamic Manifest Discovery:** Automatically discovers and aggregates diverse package manifests (lockfiles, POMs, SBOMs, etc.) from live targets.
- **Resilient AI Pipeline:** Highly reliable agentic loop with custom token-limit management to handle large dependency graphs without context exhaustion.
- **NIST SP 800-218 Alignment:** Fully implements SSDF practices for origin verification and risk assessment.

| Agent | Practice | Requirement |
|---|---|---|
| Decomposition Agent | **PO.1.1** | Identify and document all software components and dependencies |
| Provenance Agent | **PO.3.2** | Verify the provenance and integrity of third-party components |
| Arbiter Agent | **RV.1.3** | Analyze identified vulnerabilities to determine risk and response |

---

## Quick Start

### 1. Prerequisites

- Python 3.10+
- An [IBM Cloud account](https://cloud.ibm.com/) with a watsonx.ai project

### 2. Configure Credentials

Edit `.env` in the project root:

```env
WATSONX_API_KEY=<your IBM Cloud API key>
WATSONX_PROJECT_ID=<your watsonx.ai project ID>
WATSONX_URL=https://us-south.ml.cloud.ibm.com
```

### 3. Activate the Virtual Environment

```bash
# Windows
python -m venv .venv

.\venv\Scripts\Activate.ps1

# macOS/Linux
python -m venv .venv

source .venv/bin/activate
```

> If you need to recreate it: `python -m venv .venv && pip install -r requirements.txt`

### 4. Run the Pipeline

SovereignShield runs against source code repositories or build artifact directories, enforcing target specificity to ensure operational fidelity during the CI/CD build phase before deployment. 

**Standard Source Code Scan:**
```bash
python run.py --target /path/to/target/source_directory
```

**Source Code Scan with Vendor Overrides:**
```bash
python run.py --target /path/to/target/source_directory --policy /path/to/custom_policy.txt --vendor-sbom /path/to/vendor.sbom.json
```

---

## Output

After a successful run, reports are deterministically generated in specific `data/reports/<target_name>/` directories:

| File | Description |
|---|---|
| `<target_name>_timestamp.json` | Parsable JSON matrix ready for ingestion by SIEM tools and CI/CD pipelines. |
| `<target_name>_timestamp.html` | A highly polished, interactive Security Dashboard mapping out identified threats. |

Open the HTML report in any browser to interact with risk profile charts, metadata statistics, and interactive confidence matrices.

---

## Project Structure

```text
sovereignshield/
├── data/
│   ├── assets/                    # Dynamic UI assets (e.g. SovereignShield pristine logo)
│   └── reports/                   # Live, per-target nested reports generated at runtime
├── sovereignshield/
│   ├── agents/
│   │   ├── decomposition_agent.py # NIST PO.1.1 (Dissects artifacts and dependencies)
│   │   ├── provenance_agent.py    # NIST PO.3.2 (Verifies signatures and zero-trust policy)
│   │   └── arbiter_agent.py       # NIST RV.1.3 (Computes composite confidence and final block/allow)
│   ├── config.py                  # Centralized operational thresholds and endpoint parameters
│   ├── main.py                    # Pipeline orchestrator and HTML dashboard engine
│   ├── preprocessor.py            # AI-less Python-based mathematical diff engine
│   └── scanner.py                 # Live target deep scan & smart manifest discovery
├── run.py                         # Enterprise CI/CD Launcher 
├── .env                           # Credentials (never commit)
└── requirements.txt
```

---

## Model Configuration

All three agents exclusively utilize **IBM Granite 3.3 8B Instruct** (`ibm/granite-3-3-8b-instruct`) running on watsonx.ai.

The pipeline is tuned with an absolute zero-temperature (`0.0`) configuration for rigid, deterministic security verdicts avoiding LLM hallucinations, while keeping robust token limits enabling it to inspect extensive and nested dependency chains successfully without context overflow.

---

## Deep Dive: How the Pipeline Works

SovereignShield breaks down its inspection protocol into five highly specialized, sequential phases. The output of one phase inherently informs the next, culminating in a synthesized, deterministic final verdict.

### Phase 1: Source Code & Artifact Ingestion & Manifest Discovery
- **Action:** The target source code directory or build artifact undergoes a deep scan. SovereignShield features a "Smart Router" that automatically discovers relevant package manifests (e.g., `package.json`, `pom.xml`, embedded `sbom.json`) avoiding full, heavy directory parsing unless absolutely necessary.
- **Output:** An aggregated listing of all deeply nested dependencies bundled within the target.
- **Connection:** This raw scan data is piped directly to the pure-Python Pre-Processing engine.

### Phase 2: Python Pre-Processing & RAG (Retrieval-Augmented Generation)
- **Action:** Before any LLM tokens are consumed, a fast Python diff engine compares the *vendor-declared SBOM* (what the vendor claims is inside) against the *Deep Scan SBOM* (what is actually inside). It mathematically computes any discrepancies, tracking "hidden dependencies" and "version drift." 
- **Where RAG Happens:** For every hidden dependency detected, the pipeline automatically searches against a live ExploitDB database. It fetches known CVE records and cross-references them to the undisclosed packages. This **Retrieval-Augmented Generation** pattern guarantees the AI agents base their analysis on real-world threat intelligence rather than hallucinated or stale information.
- **Output:** A strict, pre-computed delta of hidden dependencies with their associated CVE matches.
- **Connection:** This structured diff is sent to the Decomposition Agent for AI interpretation.

### Phase 3: Decomposition Agent 
- **Action:** Acting under NIST SP 800-218 PO.1.1, the Decomposition Agent analyzes the diff provided by the pre-processor. Rather than parsing thousands of raw dependencies, it focuses solely on the discrepancies. It scores each undisclosed package assessing the exploit vector probability based on the injected RAG context.
- **Output:** A confidence-scored JSON payload cataloging all hidden dependencies and their associated severity.

### Phase 4: Provenance Agent
- **Action:** Acting under NIST SP 800-218 PO.3.2, this agent runs in parallel assessing non-code artifacts (e.g., compile origins, digital signatures, certificate expiry) against the specific rules of the configured Zero-Trust Policy.
- **Output:** A confidence-scored JSON payload identifying cryptographic, signature, and origin policy violations (e.g., mismatching hashes or expired vendor certs).

### Phase 5: Arbiter Agent & The Final Verdict
- **Action:** As the ultimate authority conforming to NIST RV.1.3, the Arbiter Agent synthesizes the structured, confidence-scored JSON outputs from both the Decomposition and Provenance agents. 
- **Feedback Loop:** If either upstream agent returns a confidence score below the `0.75` threshold, the Arbiter flags the inspection for secondary review, preventing automated hallucinated blocks.
- **How the Verdict is Determined:** 
  The Arbiter evaluates the aggregated findings using strict, hardcoded logic priorities embedded in its prompt:
  1. **Immediate BLOCK** if *any* single confirmed threat carries a **CRITICAL** severity.
  2. **Immediate BLOCK** if the total sum of confirmed threats plus policy violations is `>= 2`.
  3. **Immediate BLOCK** if any upstream agent tripped the low-confidence flag.
  4. **Immediate BLOCK** if cryptographic signatures are mismatched or certificates are expired.
  5. **ALLOW** is strictly reserved for payloads passing *all* criteria with zero critical hits, perfect provenance, and high-confidence AI reasoning across all agents.
- **Output:** The final definitive ALLOW/BLOCK label, a human-readable threat rationale, and actionable remediation instructions documented in both a parsable JSON payload and a fully-styled interactive HTML dashboard.
