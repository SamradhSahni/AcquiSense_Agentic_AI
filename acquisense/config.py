"""
Centralized configuration, AICredits GPT-4o model adapter, and persistent LLM response cache.
Reads all 20 canonical environment variables and prevents secret leakage in logs or outputs.
"""

import os
import json
import time
import uuid
import sqlite3
import hashlib
import secrets
import tempfile
import threading
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from acquisense import __version__, POLICY_VERSION, PROMPT_VERSION, DATASET_VERSION

# Check SDK availability without claiming live execution
try:
    from google.adk.agents import LlmAgent as ADKLlmAgent
    from google.adk.runners import Runner as ADKRunner
    from google.adk.sessions import InMemorySessionService as ADKSessionService
    try:
        from google.adk.models.lite_llm import LiteLlm as ADKLiteLlm
    except ImportError:
        ADKLiteLlm = None
    ADK_SDK_AVAILABLE = True
except ImportError:
    ADKLlmAgent = None
    ADKRunner = None
    ADKSessionService = None
    ADKLiteLlm = None
    ADK_SDK_AVAILABLE = False

try:
    import crewai
    from crewai import Agent as CrewAIAgent, Task as CrewAITask, Crew as CrewAICrew, Process as CrewAIProcess
    CREWAI_SDK_AVAILABLE = True
    CREWAI_VERSION = getattr(crewai, "__version__", "installed")
except ImportError:
    CrewAIAgent = None
    CrewAITask = None
    CrewAICrew = None
    CrewAIProcess = None
    CREWAI_SDK_AVAILABLE = False
    CREWAI_VERSION = "not_installed"

try:
    import mcp
    from mcp.server.fastmcp import FastMCP as OfficialFastMCP
    MCP_SDK_AVAILABLE = True
    MCP_VERSION = getattr(mcp, "__version__", "installed")
except ImportError:
    OfficialFastMCP = None
    MCP_SDK_AVAILABLE = False
    MCP_VERSION = "not_installed"


def redact_secret(value: Optional[str]) -> str:
    """Redacts API keys and secrets so raw credentials never appear in logs or notebook outputs."""
    if not value:
        return "<NOT_SET>"
    s = str(value).strip()
    if len(s) <= 8:
        return "***REDACTED***"
    return f"{s[:4]}...{s[-4:]} (REDACTED, len={len(s)})"


def _parse_bool(val: Optional[str], default: bool = False) -> bool:
    if val is None:
        return default
    return str(val).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class AcquiSenseConfig:
    """
    Canonical configuration loaded from the 20 required environment variables.
    Never hard-codes API keys or fabricates live credentials.
    """
    aicredits_api_key: str = ""
    aicredits_base_url: str = "https://api.aicredits.in/v1"
    aicredits_model: str = "openai/gpt-4o"
    execution_mode: str = "deterministic"  # "deterministic" or "live"
    llm_temperature: float = 0.0
    llm_top_p: float = 1.0
    llm_max_tokens: int = 2048
    llm_timeout_seconds: float = 30.0
    llm_max_retries: int = 2
    llm_cache_enabled: bool = True
    deterministic_scoring: bool = True
    allow_deterministic_fallback: bool = False
    acquisense_jwt_secret: str = ""
    acquisense_a2a_secret: str = ""
    database_url: str = ""
    deploy_target: str = "none"            # "none" or "cloud_run"
    confirm_cloud_deploy: bool = False
    gcp_project_id: str = ""
    gcp_region: str = "us-central1"
    gcp_artifact_repository: str = "acquisense-repo"
    runtime_dir: str = ""

    @classmethod
    def from_env(cls, override_env: Optional[Dict[str, str]] = None) -> "AcquiSenseConfig":
        env = dict(os.environ)
        if override_env:
            env.update(override_env)

        runtime_dir = env.get("ACQUISENSE_RUNTIME_DIR") or os.path.join(tempfile.gettempdir(), "acquisense_prod_runtime")
        os.makedirs(runtime_dir, exist_ok=True)

        default_sqlite_path = os.path.join(runtime_dir, "acquisense_durable_state.db")
        db_url = env.get("DATABASE_URL") or f"sqlite:///{default_sqlite_path}"

        # Ephemeral local secrets generated only if not provided in environment
        jwt_sec = env.get("ACQUISENSE_JWT_SECRET") or os.environ.setdefault("ACQUISENSE_JWT_SECRET", secrets.token_hex(32))
        a2a_sec = env.get("ACQUISENSE_A2A_SECRET") or os.environ.setdefault("ACQUISENSE_A2A_SECRET", secrets.token_hex(32))

        req_mode = (env.get("EXECUTION_MODE") or "deterministic").strip().lower()
        if req_mode not in ("deterministic", "live"):
            raise ValueError(f"Invalid EXECUTION_MODE='{req_mode}'. Must be 'deterministic' or 'live'.")

        deploy_tgt = (env.get("DEPLOY_TARGET") or "none").strip().lower()
        if deploy_tgt not in ("none", "cloud_run"):
            raise ValueError(f"Invalid DEPLOY_TARGET='{deploy_tgt}'. Must be 'none' or 'cloud_run'.")

        return cls(
            aicredits_api_key=(env.get("AICREDITS_API_KEY") or "").strip(),
            aicredits_base_url=(env.get("AICREDITS_BASE_URL") or "https://api.aicredits.in/v1").strip().rstrip("/"),
            aicredits_model=(env.get("AICREDITS_MODEL") or "openai/gpt-4o").strip(),
            execution_mode=req_mode,
            llm_temperature=float(env.get("LLM_TEMPERATURE", "0.0")),
            llm_top_p=float(env.get("LLM_TOP_P", "1.0")),
            llm_max_tokens=int(env.get("LLM_MAX_TOKENS", "2048")),
            llm_timeout_seconds=float(env.get("LLM_TIMEOUT_SECONDS", "30.0")),
            llm_max_retries=int(env.get("LLM_MAX_RETRIES", "2")),
            llm_cache_enabled=_parse_bool(env.get("LLM_CACHE_ENABLED"), default=True),
            deterministic_scoring=_parse_bool(env.get("DETERMINISTIC_SCORING"), default=True),
            allow_deterministic_fallback=_parse_bool(env.get("ALLOW_DETERMINISTIC_FALLBACK"), default=False),
            acquisense_jwt_secret=jwt_sec,
            acquisense_a2a_secret=a2a_sec,
            database_url=db_url,
            deploy_target=deploy_tgt,
            confirm_cloud_deploy=_parse_bool(env.get("CONFIRM_CLOUD_DEPLOY"), default=False),
            gcp_project_id=(env.get("GCP_PROJECT_ID") or "").strip(),
            gcp_region=(env.get("GCP_REGION") or "us-central1").strip(),
            gcp_artifact_repository=(env.get("GCP_ARTIFACT_REPOSITORY") or "acquisense-repo").strip(),
            runtime_dir=runtime_dir,
        )

    @property
    def sqlite_db_path(self) -> str:
        if self.database_url.startswith("sqlite:"):
            raw = self.database_url
            for prefix in ("sqlite:///", "sqlite://", "sqlite:"):
                if raw.startswith(prefix):
                    raw = raw[len(prefix):]
                    break
            expanded = os.path.expanduser(os.path.expandvars(raw))
            if not os.path.isabs(expanded):
                project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                expanded = os.path.abspath(os.path.join(project_root, expanded))
            parent = os.path.dirname(expanded)
            if parent:
                os.makedirs(parent, exist_ok=True)
            return expanded
        return os.path.join(self.runtime_dir, "acquisense_durable_state.db")

    @property
    def gateway_model_name_for_http(self) -> str:
        """
        Maps `AICREDITS_MODEL=openai/gpt-4o` to the model identifier expected by
        LiteLLM vs direct OpenAI-compatible `/v1/chat/completions` endpoints.
        """
        return self.aicredits_model

    def redacted_summary(self) -> Dict[str, Any]:
        return {
            "AICREDITS_API_KEY": redact_secret(self.aicredits_api_key),
            "AICREDITS_BASE_URL": self.aicredits_base_url,
            "AICREDITS_MODEL": self.aicredits_model,
            "EXECUTION_MODE": self.execution_mode,
            "LLM_TEMPERATURE": self.llm_temperature,
            "LLM_TOP_P": self.llm_top_p,
            "LLM_MAX_TOKENS": self.llm_max_tokens,
            "LLM_TIMEOUT_SECONDS": self.llm_timeout_seconds,
            "LLM_MAX_RETRIES": self.llm_max_retries,
            "LLM_CACHE_ENABLED": self.llm_cache_enabled,
            "DETERMINISTIC_SCORING": self.deterministic_scoring,
            "ALLOW_DETERMINISTIC_FALLBACK": self.allow_deterministic_fallback,
            "ACQUISENSE_JWT_SECRET": redact_secret(self.acquisense_jwt_secret),
            "ACQUISENSE_A2A_SECRET": redact_secret(self.acquisense_a2a_secret),
            "DATABASE_URL": self.database_url,
            "DEPLOY_TARGET": self.deploy_target,
            "CONFIRM_CLOUD_DEPLOY": self.confirm_cloud_deploy,
            "GCP_PROJECT_ID": self.gcp_project_id or "<NOT_SET>",
            "GCP_REGION": self.gcp_region,
            "GCP_ARTIFACT_REPOSITORY": self.gcp_artifact_repository,
        }


class LiveExecutionError(RuntimeError):
    """Raised when EXECUTION_MODE='live' fails and ALLOW_DETERMINISTIC_FALLBACK is False."""
    pass


class PersistentLLMCache:
    """
    Persistent SQLite-backed LLM response cache keyed by SHA-256 of:
    (model_id, prompt_version, system_instructions, input_sha256, temperature, top_p, max_tokens).
    Separately tracks cache_hits, cache_misses, and fresh_live_requests.
    """
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.RLock()
        self.cache_hits: int = 0
        self.cache_misses: int = 0
        self._init_table()

    def _init_table(self) -> None:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS llm_response_cache (
                cache_key TEXT PRIMARY KEY,
                created_at_utc TEXT,
                requested_model TEXT,
                returned_model TEXT,
                prompt_version TEXT,
                input_sha256 TEXT,
                response_json TEXT,
                prompt_tokens INTEGER,
                completion_tokens INTEGER,
                total_tokens INTEGER
            )
        """)
        conn.commit()
        conn.close()

    @staticmethod
    def compute_cache_key(
        model_id: str,
        prompt_version: str,
        system_instructions: str,
        validated_input: Any,
        temperature: float,
        top_p: float,
        max_tokens: int,
    ) -> Tuple[str, str]:
        input_serialized = json.dumps(validated_input, sort_keys=True, default=str)
        input_sha256 = hashlib.sha256(input_serialized.encode("utf-8")).hexdigest()
        composite = json.dumps({
            "model_id": model_id,
            "prompt_version": prompt_version,
            "system_instructions": system_instructions,
            "input_sha256": input_sha256,
            "temperature": temperature,
            "top_p": top_p,
            "max_tokens": max_tokens,
        }, sort_keys=True)
        cache_key = hashlib.sha256(composite.encode("utf-8")).hexdigest()
        return cache_key, input_sha256

    def get(self, cache_key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM llm_response_cache WHERE cache_key = ?", (cache_key,))
            row = cur.fetchone()
            conn.close()
            if row is not None:
                self.cache_hits += 1
                return {
                    "cache_key": row["cache_key"],
                    "created_at_utc": row["created_at_utc"],
                    "requested_model": row["requested_model"],
                    "returned_model": row["returned_model"],
                    "prompt_version": row["prompt_version"],
                    "input_sha256": row["input_sha256"],
                    "response_data": json.loads(row["response_json"]),
                    "prompt_tokens": int(row["prompt_tokens"]),
                    "completion_tokens": int(row["completion_tokens"]),
                    "total_tokens": int(row["total_tokens"]),
                    "from_cache": True,
                }
            self.cache_misses += 1
            return None

    def put(
        self,
        cache_key: str,
        requested_model: str,
        returned_model: str,
        prompt_version: str,
        input_sha256: str,
        response_data: Dict[str, Any],
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        total_tokens: int = 0,
    ) -> None:
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cur = conn.cursor()
            cur.execute(
                """
                INSERT OR REPLACE INTO llm_response_cache
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cache_key,
                    datetime.now(timezone.utc).isoformat(),
                    requested_model,
                    returned_model,
                    prompt_version,
                    input_sha256,
                    json.dumps(response_data, sort_keys=True, default=str),
                    int(prompt_tokens),
                    int(completion_tokens),
                    int(total_tokens),
                ),
            )
            conn.commit()
            conn.close()


class AICreditsModelGateway:
    """
    Centralized model-configuration and gateway adapter for:
      1. Google ADK (`LlmAgent` with `LiteLlm` pointed at `https://api.aicredits.in/v1` and `openai/gpt-4o`)
      2. CrewAI (`Agent` / `LLM` pointed at `https://api.aicredits.in/v1` and `openai/gpt-4o`)
      3. Direct OpenAI-compatible `/chat/completions` smoke testing
    Never sends requests to api.openai.com or direct Gemini endpoints.
    """
    def __init__(self, config: AcquiSenseConfig, cache: PersistentLLMCache):
        self.config = config
        self.cache = cache
        self._lock = threading.RLock()
        self.live_requests_attempted: int = 0
        self.live_requests_succeeded: int = 0
        self.live_requests_failed: int = 0
        self.total_retries: int = 0
        self.deterministic_executions: int = 0
        self.last_returned_model: Optional[str] = None

    def verify_live_preflight(self) -> Dict[str, Any]:
        """
        Preflight check for live mode. Refuses to claim live readiness if AICREDITS_API_KEY is absent.
        """
        if not self.config.aicredits_api_key:
            raise LiveExecutionError(
                "Live mode preflight failed: AICREDITS_API_KEY is missing or empty. "
                "Set AICREDITS_API_KEY in environment or run with EXECUTION_MODE=deterministic."
            )
        if "aicredits.in" not in self.config.aicredits_base_url and "127.0.0.1" not in self.config.aicredits_base_url:
            raise LiveExecutionError(
                f"Invalid AICREDITS_BASE_URL='{self.config.aicredits_base_url}'. Must point to AICredits gateway."
            )
        return {
            "preflight_passed": True,
            "base_url": self.config.aicredits_base_url,
            "configured_model": self.config.aicredits_model,
            "adk_sdk_available": ADK_SDK_AVAILABLE,
            "crewai_sdk_available": CREWAI_SDK_AVAILABLE,
        }

    def build_adk_litellm_adapter(self) -> Any:
        """Builds the native Google ADK LiteLLM model adapter pointed at AICredits."""
        self.verify_live_preflight()
        if not ADK_SDK_AVAILABLE:
            raise LiveExecutionError("google-adk package is not installed in the current Python environment.")
        if ADKLiteLlm is not None:
            return ADKLiteLlm(
                model=self.config.aicredits_model,
                api_base=self.config.aicredits_base_url,
                api_key=self.config.aicredits_api_key,
            )
        return self.config.aicredits_model

    def build_crewai_llm_adapter(self) -> Any:
        """Builds the native CrewAI LLM adapter pointed at AICredits."""
        self.verify_live_preflight()
        if not CREWAI_SDK_AVAILABLE:
            raise LiveExecutionError("crewai package is not installed in the current Python environment.")
        if hasattr(crewai, "LLM"):
            return crewai.LLM(
                model=self.config.aicredits_model,
                base_url=self.config.aicredits_base_url,
                api_key=self.config.aicredits_api_key,
                temperature=self.config.llm_temperature,
                max_tokens=self.config.llm_max_tokens,
            )
        return self.config.aicredits_model

    def run_gateway_smoke_test(self) -> Dict[str, Any]:
        """
        Executes a live chat completion smoke test against `{AICREDITS_BASE_URL}/chat/completions`
        and records the returned model identifier and token usage.
        """
        self.verify_live_preflight()
        url = f"{self.config.aicredits_base_url}/chat/completions"
        # Normalize model ID if the OpenAI-compatible HTTP endpoint expects 'gpt-4o' or 'openai/gpt-4o'
        model_for_wire = self.config.aicredits_model
        payload = {
            "model": model_for_wire,
            "messages": [
                {"role": "system", "content": "You are the AcquiSense M&A verification probe. Reply with JSON: {\"status\": \"OK\"}."},
                {"role": "user", "content": "Verify AICredits GPT-4o gateway connectivity."},
            ],
            "temperature": self.config.llm_temperature,
            "top_p": self.config.llm_top_p,
            "max_tokens": 64,
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.aicredits_api_key}",
        }
        last_err = None
        for attempt in range(self.config.llm_max_retries + 1):
            with self._lock:
                self.live_requests_attempted += 1
                if attempt > 0:
                    self.total_retries += 1
            t0 = time.perf_counter()
            try:
                req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=self.config.llm_timeout_seconds) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                    latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                    ret_model = body.get("model", model_for_wire)
                    usage = body.get("usage", {})
                    with self._lock:
                        self.live_requests_succeeded += 1
                        self.last_returned_model = ret_model
                    return {
                        "smoke_test_passed": True,
                        "endpoint": url,
                        "requested_model": self.config.aicredits_model,
                        "returned_model": ret_model,
                        "latency_ms": latency_ms,
                        "prompt_tokens": usage.get("prompt_tokens", 0),
                        "completion_tokens": usage.get("completion_tokens", 0),
                        "total_tokens": usage.get("total_tokens", 0),
                        "content": body.get("choices", [{}])[0].get("message", {}).get("content", ""),
                    }
            except Exception as ex:
                last_err = str(ex)
        with self._lock:
            self.live_requests_failed += 1
        raise LiveExecutionError(f"AICredits gateway smoke test failed after {self.config.llm_max_retries + 1} attempts: {last_err}")

    def runtime_telemetry_summary(self) -> Dict[str, Any]:
        return {
            "requested_execution_mode": self.config.execution_mode,
            "configured_base_url": self.config.aicredits_base_url,
            "configured_model": self.config.aicredits_model,
            "last_returned_model": self.last_returned_model,
            "live_requests_attempted": self.live_requests_attempted,
            "live_requests_succeeded": self.live_requests_succeeded,
            "live_requests_failed": self.live_requests_failed,
            "total_retries": self.total_retries,
            "deterministic_executions": self.deterministic_executions,
            "cache_hits": self.cache.cache_hits,
            "cache_misses": self.cache.cache_misses,
        }
