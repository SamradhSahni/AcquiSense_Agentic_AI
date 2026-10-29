"""
Production FastAPI Application (`app.py`) for AcquiSense.
Executes the REAL shared `AcquiSenseRuntimeCluster` orchestration pipeline (never returns
hard-coded company reports!). Enforces:
  - 16 KB Request Payload Size Limit (`HTTP 413`)
  - JWT HS256 Authentication (`Authorization: Bearer <jwt>` -> `HTTP 401`)
  - Deal-Level RBAC (`allowed_targets` claim -> `HTTP 403`)
  - Cross-Instance SQLite-WAL Rate Limiting (`HTTP 429`)
  - Prompt Injection Gate (`HTTP 400`) & Unknown Target Check (`HTTP 404`)
"""

import os
import sys
from typing import Any, Dict, Optional

try:
    from dotenv import load_dotenv
    load_dotenv(override=False)
except ImportError:
    pass
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from acquisense.config import LiveExecutionError
from acquisense.mcp_service import TARGET_PROFILES
from acquisense.security import verify_jwt_token, check_distributed_rate_limit
from acquisense.orchestrator import AcquiSenseRuntimeCluster

RUNTIME_CLUSTER = AcquiSenseRuntimeCluster()

acquisense_cloud_app = FastAPI(
    title="AcquiSense Enterprise M&A Due Diligence Platform API",
    version="4.2.0",
    description="Production Multi-Agent M&A Due Diligence API (Google ADK + CrewAI + GPT-4o via AICredits + MCP + A2A + Durable Blackboard).",
)

MAX_BODY_BYTES = 16384


@acquisense_cloud_app.middleware("http")
async def enforce_payload_size_limit(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl and int(cl) > MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": f"Payload Too Large: exceeds {MAX_BODY_BYTES} bytes."})
    return await call_next(request)


class EvaluateDealRequest(BaseModel):
    target_company: str
    user_prompt: str
    design_pattern: str = "Hierarchical"
    messaging_mode: str = "Blackboard"
    reasoning_mode: str = "ReAct"
    persona_name: str = "API_Client"
    random_seed: int = 2026
    execution_mode: Optional[str] = None


def _authenticate_and_authorize(authorization: Optional[str], required_target: Optional[str] = None) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: Missing Bearer JWT token.")
    token = authorization.replace("Bearer ", "", 1).strip()
    try:
        claims = verify_jwt_token(token, secret_key=RUNTIME_CLUSTER.config.acquisense_jwt_secret)
    except PermissionError as pe:
        raise HTTPException(status_code=401, detail=f"Unauthorized: {pe}")

    try:
        check_distributed_rate_limit(
            RUNTIME_CLUSTER.config.sqlite_db_path,
            client_sub=claims["sub"],
            max_requests_per_min=40,
        )
    except OverflowError as oe:
        raise HTTPException(status_code=429, detail=str(oe))

    if required_target and required_target not in claims.get("allowed_targets", []):
        raise HTTPException(
            status_code=403,
            detail=f"Forbidden: Subject '{claims['sub']}' is not authorized for deal '{required_target}'.",
        )
    return claims


@acquisense_cloud_app.get("/healthz")
def healthz() -> Dict[str, Any]:
    return {
        "status": "HEALTHY",
        "service": "acquisense-production-api-v4.2",
        "server_pid": os.getpid(),
        "configured_execution_mode": RUNTIME_CLUSTER.config.execution_mode,
        "mcp_endpoint": RUNTIME_CLUSTER.mcp_server.endpoint_url,
        "adk_a2a_endpoint": RUNTIME_CLUSTER.adk_a2a_service.base_url,
        "crewai_a2a_endpoint": RUNTIME_CLUSTER.crewai_a2a_service.base_url,
        "jwt_hs256_enforced": True,
        "durable_blackboard_db": os.path.basename(RUNTIME_CLUSTER.config.sqlite_db_path),
    }


@acquisense_cloud_app.get("/.well-known/agent.json")
def agent_cards(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    _authenticate_and_authorize(authorization)
    return {
        "platform": "AcquiSense_Enterprise_MAS",
        "version": "4.2.0",
        "services": RUNTIME_CLUSTER.a2a_client.discover_all_services(),
    }


@acquisense_cloud_app.post("/api/v1/due-diligence/evaluate")
def evaluate_deal(req: EvaluateDealRequest, authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if req.target_company not in TARGET_PROFILES:
        raise HTTPException(status_code=404, detail=f"Target '{req.target_company}' not found in VDR.")
    claims = _authenticate_and_authorize(authorization, required_target=req.target_company)

    try:
        report, _, metrics = RUNTIME_CLUSTER.orchestrator.run_due_diligence_workflow(
            target_company=req.target_company,
            user_prompt=req.user_prompt,
            design_pattern=req.design_pattern,
            messaging_mode=req.messaging_mode,
            reasoning_mode=req.reasoning_mode,
            persona_name=f"{claims['sub']}:{req.persona_name}",
            random_seed=req.random_seed,
            requested_execution_mode=req.execution_mode,
            hard_reject_on_injection=True,
        )
        return {
            "status": "COMPLETED",
            "served_by_pid": os.getpid(),
            "authorized_subject": claims["sub"],
            "metrics": metrics,
            "report": report.model_dump(),
        }
    except PermissionError as pe:
        raise HTTPException(status_code=400, detail=str(pe))
    except LiveExecutionError as le:
        raise HTTPException(status_code=503, detail=str(le))
    except ValueError as ve:
        raise HTTPException(status_code=422, detail=str(ve))


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(
        "app:acquisense_cloud_app",
        host="127.0.0.1",
        port=port,
        reload=False,
        log_level="info",
    )
