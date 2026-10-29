# AcquiSense — Production-Ready Multi-Agent M&A Due Diligence Platform

AcquiSense is a reproducible, multi-agent Merger & Acquisition (M&A) due-diligence platform integrating **Google Agent Development Kit (ADK)**, **CrewAI**, **GPT-4o via the AICredits OpenAI-compatible endpoint (`https://api.aicredits.in/v1`)**, **Model Context Protocol (MCP)**, **Agent-to-Agent (A2A) HTTP interoperability**, a **Durable SQLite-WAL / PostgreSQL Blackboard**, and **Deterministic Python Corporate Finance & Risk Scoring**.

## 1. Architecture & Specialist Agents

The platform preserves six domain specialists split across two independently addressable HTTP A2A service clusters:
1. **`ADK_Legal_Agent`** (*Google ADK*): Audits litigation dockets, statutory compliance, and Change-of-Control clauses.
2. **`ADK_Financial_Agent`** (*Google ADK*): Executes the 5-year FCFF Enterprise Value $\rightarrow$ Equity Value $\rightarrow$ Direct Price Reduction vs. Indemnity Escrow bridge and the leak-free in-fold L2 Logistic Regression PMI forecaster, and performs direct A2A cross-verification with `CrewAI_Cyber_Agent`.
3. **`CrewAI_Tech_Agent`** (*CrewAI*): Evaluates cloud/monolith architecture, SLA availability, and refactoring capex.
4. **`CrewAI_Cyber_Agent`** (*CrewAI*): Matches target SBOM components against vulnerability advisories and SOC2/HITRUST controls.
5. **`CrewAI_HR_Agent`** (*CrewAI*): Benchmarks engineering attrition and structures executive retention lockup pools.
6. **`CrewAI_ESG_Agent`** (*CrewAI*): Evaluates Scope-2 carbon alignment and board independence.

## 2. Separation of LLM Reasoning vs. Deterministic Business Logic

Even in `live` mode, GPT-4o is restricted to structured fact and clause extraction (`LLMExtractedDomainFacts`). All numerical risk scores (`compute_deterministic_domain_score`), severity escalations (`CRITICAL` floor $\ge 76.0$), DCF Enterprise-to-Equity reconciliations, escrow holdbacks, and final committee decisions (`GO`, `CONDITIONAL_GO`, `NO_GO`, `INSUFFICIENT_EVIDENCE_HOLD`) are computed by deterministic, versioned Python functions (`policy-v4.2.0`).

First-time live model generation can still vary even at `LLM_TEMPERATURE=0.0`; exact repeatability is guaranteed through our **Persistent SQLite LLM Response Cache (`PersistentLLMCache`)** keyed by SHA-256 of `(model_id, prompt_version, system_instructions, input_sha256, temperature, top_p, max_tokens)`.

## 3. Environment Variables

Copy `.env.example` to `.env`. Never commit `.env` to version control:
- **Required for Local Deterministic Mode (`EXECUTION_MODE=deterministic`)**: Zero external API keys or internet access required.
- **Required for Live Mode (`EXECUTION_MODE=live`)**: `AICREDITS_API_KEY`, `AICREDITS_BASE_URL=https://api.aicredits.in/v1`, `AICREDITS_MODEL=openai/gpt-4o`. By default, `ALLOW_DETERMINISTIC_FALLBACK=false` so failed live calls raise `LiveExecutionError` rather than silently falling back.
- **Required for Opt-In Cloud Run Deployment (`DEPLOY_TARGET=cloud_run`)**: `CONFIRM_CLOUD_DEPLOY=true`, `GCP_PROJECT_ID`, `GCP_REGION`, `GCP_ARTIFACT_REPOSITORY`, and a durable Cloud SQL `DATABASE_URL` (`postgresql://...`).

## 4. Running Tests & Local Services

```bash
# Run the 18-point automated acceptance suite (works offline in deterministic mode)
python3 -m unittest discover -s tests -p "test_*.py" -v

# Start the production FastAPI server locally
uvicorn app:acquisense_cloud_app --host 127.0.0.1 --port 8080

# Verify opt-in deployment preflight (safe no-op by default)
python3 deploy.py --target none
```

## 5. Honest Capability Status Matrix

| Capability | Status | Verification Details |
|---|---|---|
| **6 Specialist Agents, Deterministic Scoring, & DCF/Escrow Bridge** | **Implemented & Verified** | Verified across `NovaPay FinTech Corp` ($420M) and `CloudMed AI Corp` ($185M) with zero cross-target contamination. |
| **Durable SQLite-WAL Blackboard & Optimistic Concurrency Recovery** | **Implemented & Verified** | Persists across restarts and separate OS processes; verifies 64-hex SHA-256 hash chain and automatic conflict recovery. |
| **Sequential, Parallel, Hierarchical & Bounded P2P Workflows** | **Implemented & Verified** | Benchmarked across 48 matched runs with Friedman & Wilcoxon paired tests; incomplete P2P context triggers `INSUFFICIENT_EVIDENCE_HOLD`. |
| **MCP Streamable HTTP Server/Client & A2A Cross-Service Interop** | **Implemented & Verified** | Full JSON schemas, error contracts, RBAC, and direct `ADK_Financial_Agent` $\rightarrow$ `CrewAI_Cyber_Agent` HTTP A2A sub-tasks. |
| **Live AICredits GPT-4o (`https://api.aicredits.in/v1`) Execution** | **Implemented (Blocked in Offline Sandbox)** | Full adapter, preflight check, and no-silent-fallback logic implemented; live external calls require a valid `AICREDITS_API_KEY` and outbound internet access. |
| **Cloud Run Deployment (`deploy.py` & `cloudbuild.yaml`)** | **Prepared & Opt-In Verified Locally via Uvicorn Subprocess** | Complete multi-module container bundle tested via live `uvicorn app:acquisense_cloud_app` subprocess; cloud deployment is opt-in and requires `GCP_PROJECT_ID` + Cloud SQL. |
