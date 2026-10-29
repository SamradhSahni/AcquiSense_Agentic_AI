"""
Standards-compliant A2A HTTP Services and Federated Client.
Exposes Google ADK and CrewAI as independently addressable HTTP services on separate ports,
validates JWT authentication, deadlines (`deadline_epoch_ms`), `deal_id`, `request_id`,
`correlation_id`, and demonstrates direct ADK-to-CrewAI cross-service A2A requests.
"""

import json
import time
import uuid
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

from acquisense.config import AcquiSenseConfig, LiveExecutionError
from acquisense.schemas import DomainRiskAssessment
from acquisense.security import create_jwt_token, verify_jwt_token
from acquisense.observability import AgentMonitoringCallbackHandler
from acquisense.blackboard import DueDiligenceBlackboard
from acquisense.mcp_service import TARGET_PROFILES
from acquisense.agents import DomainSpecialistAgent


ACTIVE_WORKFLOW_CONTEXTS: Dict[str, Dict[str, Any]] = {}
_WORKFLOW_CTX_LOCK = threading.RLock()


class StandardA2AServiceCluster:
    """
    Independently addressable HTTP service implementing the Google A2A protocol:
      - `GET /.well-known/agent.json`: Standard A2A AgentCard
      - `POST /a2a`: JSON-RPC 2.0 `tasks/send`, `tasks/get`, `tasks/cancel`, and `tasks/verify_subtask`
    Enforces Bearer JWT authentication, deadline checks, and deal/request correlation ID preservation.
    """
    def __init__(
        self,
        service_name: str,
        framework: str,
        agents_dict: Dict[str, DomainSpecialistAgent],
        config: AcquiSenseConfig,
        monitor: AgentMonitoringCallbackHandler,
    ):
        self.service_name = service_name
        self.framework = framework
        self.agents_dict = agents_dict
        self.config = config
        self.monitor = monitor
        self.tasks_store: Dict[str, Dict[str, Any]] = {}
        self.store_lock = threading.RLock()

        parent_service = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                if self.path == "/.well-known/agent.json":
                    port = self.server.server_address[1]
                    skills = [
                        {
                            "id": ag.agent_id,
                            "name": ag.name,
                            "description": ag.role_goal,
                            "tags": [ag.framework, ag.domain.value, "M&A_Due_Diligence"],
                            "examples": [f"Evaluate {ag.domain.value} risks for target company."],
                        }
                        for ag in parent_service.agents_dict.values()
                    ]
                    card = {
                        "name": parent_service.service_name,
                        "description": f"Standards-compliant A2A Service hosting {parent_service.framework} specialists.",
                        "url": f"http://127.0.0.1:{port}/a2a",
                        "version": "1.0.0",
                        "provider": {"organization": "AcquiSense Enterprise MAS", "url": f"http://127.0.0.1:{port}"},
                        "capabilities": {
                            "streaming": False,
                            "pushNotifications": False,
                            "stateTransitionHistory": True,
                        },
                        "authentication": {"schemes": ["Bearer"]},
                        "defaultInputModes": ["text/plain", "application/json"],
                        "defaultOutputModes": ["application/json"],
                        "skills": skills,
                    }
                    body = json.dumps(card).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self) -> None:
                if self.path != "/a2a":
                    self.send_response(404)
                    self.end_headers()
                    return

                auth_hdr = self.headers.get("Authorization", "")
                if not auth_hdr.startswith("Bearer "):
                    err = json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": "Missing Bearer JWT token"}}).encode("utf-8")
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err)))
                    self.end_headers()
                    self.wfile.write(err)
                    return

                try:
                    jwt_claims = verify_jwt_token(auth_hdr.replace("Bearer ", "", 1))
                except Exception as auth_ex:
                    err = json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": str(auth_ex)}}).encode("utf-8")
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err)))
                    self.end_headers()
                    self.wfile.write(err)
                    return

                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length).decode("utf-8")
                try:
                    rpc = json.loads(raw_body)
                    req_id = rpc.get("id")
                    method = rpc.get("method", "")
                    params = rpc.get("params", {})

                    if method == "tasks/send":
                        task_id = params.get("id") or f"task-{uuid.uuid4().hex[:10]}"
                        session_id = params.get("sessionId") or f"sess-{uuid.uuid4().hex[:8]}"
                        message = params.get("message", {})
                        parts = message.get("parts", [])
                        prompt_text = ""
                        task_data: Dict[str, Any] = {}
                        for p in parts:
                            if p.get("type") == "text":
                                prompt_text = p.get("text", "")
                            elif p.get("type") == "data":
                                task_data = p.get("data", {})

                        # Validate deadline if specified
                        deadline_ms = task_data.get("deadline_epoch_ms")
                        if deadline_ms is not None and (time.time() * 1000.0) > float(deadline_ms):
                            raise TimeoutError(f"A2A task '{task_id}' deadline exceeded prior to execution.")

                        skill_id = task_data.get("skill_id")
                        if skill_id not in parent_service.agents_dict:
                            raise KeyError(f"Skill/Agent '{skill_id}' not hosted on {parent_service.service_name}")

                        target_co = task_data["target_company"]
                        if target_co not in jwt_claims.get("allowed_targets", []):
                            raise PermissionError(f"A2A Deal RBAC Denied for '{target_co}'.")

                        deal_id = task_data.get("deal_id", "deal-default")
                        correlation_id = task_data.get("correlation_id", req_id)

                        # Support lightweight cross-agent verification sub-tasks (e.g. ADK_Financial_Agent -> CrewAI_Cyber_Agent)
                        if task_data.get("subtask_type") == "verify_cyber_escrow_readiness":
                            parent_service.monitor.on_context_interaction(
                                task_data.get("sender_agent", "ADK_Financial_Agent"), skill_id, weight=2
                            )
                            reg_check = parent_service.agents_dict[skill_id].mcp_client.call_tool(
                                trace_id=task_data.get("trace_id", uuid.uuid4().hex),
                                parent_span_id=task_data.get("parent_span_id"),
                                caller_agent=skill_id,
                                framework=parent_service.framework,
                                tool_name="regulatory_compliance_db_lookup",
                                arguments={"target_company": target_co, "check_scope": "A2A_PEER_VERIFICATION"},
                            )
                            sub_artifact = {
                                "responder": skill_id,
                                "responder_framework": parent_service.framework,
                                "deal_id": deal_id,
                                "correlation_id": correlation_id,
                                "target_company": target_co,
                                "critical_cves": reg_check["matched_critical_cve_count"],
                                "soc2_status": reg_check["soc2_status"],
                            }
                            t_now = datetime.now(timezone.utc).isoformat()
                            task_record = {
                                "id": task_id,
                                "sessionId": session_id,
                                "dealId": deal_id,
                                "correlationId": correlation_id,
                                "status": {"state": "completed", "timestamp": t_now},
                                "stateTransitionHistory": [
                                    {"state": "submitted", "timestamp": t_now},
                                    {"state": "working", "timestamp": t_now},
                                    {"state": "completed", "timestamp": t_now},
                                ],
                                "history": [message, {"role": "agent", "parts": [{"type": "data", "data": sub_artifact}]}],
                                "artifacts": [{"name": "a2a_peer_verification", "index": 0, "parts": [{"type": "data", "data": sub_artifact}]}],
                            }
                            with parent_service.store_lock:
                                parent_service.tasks_store[task_id] = task_record
                            result = task_record
                        else:
                            t_submitted = datetime.now(timezone.utc).isoformat()
                            with _WORKFLOW_CTX_LOCK:
                                wf_ctx = ACTIVE_WORKFLOW_CONTEXTS.get(session_id, {})
                            bb_id = task_data.get("blackboard_id")
                            p2p_bus = wf_ctx.get("p2p_bus")

                            if wf_ctx.get("blackboard") is not None:
                                bb_handle: Optional[DueDiligenceBlackboard] = wf_ctx["blackboard"]
                            elif bb_id:
                                ask_p = float(TARGET_PROFILES[target_co]["asking_price_musd"])
                                bb_handle = DueDiligenceBlackboard(
                                    target_co, ask_p, parent_service.monitor,
                                    wal_db_path=parent_service.config.sqlite_db_path,
                                    blackboard_id=bb_id, deal_id=deal_id,
                                )
                            else:
                                bb_handle = None

                            agent_obj = parent_service.agents_dict[skill_id]
                            parent_service.monitor.on_context_interaction(
                                task_data.get("sender_agent", "ADK_Orchestrator"), skill_id, weight=2
                            )
                            t_working = datetime.now(timezone.utc).isoformat()
                            assessment = agent_obj.execute_domain_evaluation(
                                trace_id=task_data["trace_id"],
                                parent_span_id=task_data.get("parent_span_id"),
                                deal_id=deal_id,
                                request_id=correlation_id,
                                target_company=target_co,
                                user_prompt=prompt_text,
                                reasoning_mode=task_data.get("reasoning_mode", "ReAct"),
                                persona_name=task_data.get("persona_name", "Managing_Director"),
                                random_seed=int(task_data.get("random_seed", 2026)),
                                requested_mode_override=task_data.get("requested_execution_mode"),
                                blackboard=bb_handle,
                                p2p_bus=p2p_bus,
                            )
                            t_completed = datetime.now(timezone.utc).isoformat()

                            agent_reply_msg = {
                                "role": "agent",
                                "parts": [
                                    {"type": "text", "text": f"Completed {assessment.domain.value} assessment."},
                                    {"type": "data", "data": assessment.model_dump()},
                                ],
                            }
                            task_record = {
                                "id": task_id,
                                "sessionId": session_id,
                                "dealId": deal_id,
                                "correlationId": correlation_id,
                                "status": {"state": "completed", "timestamp": t_completed},
                                "stateTransitionHistory": [
                                    {"state": "submitted", "timestamp": t_submitted},
                                    {"state": "working", "timestamp": t_working},
                                    {"state": "completed", "timestamp": t_completed},
                                ],
                                "history": [message, agent_reply_msg],
                                "artifacts": [
                                    {
                                        "name": "domain_risk_assessment",
                                        "index": 0,
                                        "parts": [{"type": "data", "data": assessment.model_dump()}],
                                    }
                                ],
                            }
                            with parent_service.store_lock:
                                parent_service.tasks_store[task_id] = task_record
                            result = task_record

                    elif method == "tasks/get":
                        tid = params.get("id")
                        with parent_service.store_lock:
                            if tid not in parent_service.tasks_store:
                                raise KeyError(f"Task '{tid}' not found")
                            result = parent_service.tasks_store[tid]

                    elif method == "tasks/cancel":
                        tid = params.get("id")
                        with parent_service.store_lock:
                            if tid not in parent_service.tasks_store:
                                raise KeyError(f"Task '{tid}' not found")
                            parent_service.tasks_store[tid]["status"] = {
                                "state": "canceled",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }
                            result = parent_service.tasks_store[tid]
                    else:
                        raise ValueError(f"Unsupported A2A JSON-RPC method '{method}'")

                    resp_bytes = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp_bytes)))
                    self.end_headers()
                    self.wfile.write(resp_bytes)
                except PermissionError as pe:
                    err_bytes = json.dumps({"jsonrpc": "2.0", "id": 0, "error": {"code": -32001, "message": str(pe), "error_type": "PermissionError"}}).encode("utf-8")
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err_bytes)))
                    self.end_headers()
                    self.wfile.write(err_bytes)
                except TimeoutError as te:
                    err_bytes = json.dumps({"jsonrpc": "2.0", "id": 0, "error": {"code": -32003, "message": str(te), "error_type": "TimeoutError"}}).encode("utf-8")
                    self.send_response(408)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err_bytes)))
                    self.end_headers()
                    self.wfile.write(err_bytes)
                except LiveExecutionError as le:
                    err_bytes = json.dumps({"jsonrpc": "2.0", "id": 0, "error": {"code": -32603, "message": str(le), "error_type": "LiveExecutionError"}}).encode("utf-8")
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err_bytes)))
                    self.end_headers()
                    self.wfile.write(err_bytes)
                except Exception as ex:
                    err_bytes = json.dumps({"jsonrpc": "2.0", "id": 0, "error": {"code": -32603, "message": str(ex), "error_type": ex.__class__.__name__}}).encode("utf-8")
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err_bytes)))
                    self.end_headers()
                    self.wfile.write(err_bytes)

        self.http_server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.http_server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.http_server.serve_forever, name=f"{service_name}Thread", daemon=True)
        self.thread.start()


class StandardA2AFederatedClient:
    def __init__(self, service_urls: List[str]):
        self.service_urls = service_urls
        self.service_cards: List[Dict[str, Any]] = []
        self.skill_to_endpoint: Dict[str, str] = {}
        self.http_exchange_log: List[Dict[str, Any]] = []
        self.discover_all_services()

    def discover_all_services(self) -> List[Dict[str, Any]]:
        self.service_cards = []
        for base_u in self.service_urls:
            req = urllib.request.Request(f"{base_u}/.well-known/agent.json", method="GET")
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                card = json.loads(resp.read().decode("utf-8"))
                self.service_cards.append(card)
                for sk in card.get("skills", []):
                    self.skill_to_endpoint[sk["id"]] = card["url"]
        return self.service_cards

    def send_peer_verification_subtask(
        self,
        sender_agent: str,
        receiver_skill_id: str,
        target_company: str,
        deal_id: str,
        deadline_ms_from_now: float = 10000.0,
    ) -> Dict[str, Any]:
        """
        Direct Agent-to-Agent request from an ADK specialist (e.g. ADK_Financial_Agent)
        to a CrewAI specialist (e.g. CrewAI_Cyber_Agent) on the remote CrewAI A2A service.
        """
        endpoint_url = self.skill_to_endpoint[receiver_skill_id]
        task_id = f"a2a-subtask-{uuid.uuid4().hex[:10]}"
        corr_id = f"corr-{uuid.uuid4().hex[:8]}"
        jwt_tok = create_jwt_token(subject=sender_agent, allowed_targets=[target_company])
        rpc_payload = {
            "jsonrpc": "2.0",
            "id": f"rpc-{uuid.uuid4().hex[:8]}",
            "method": "tasks/send",
            "params": {
                "id": task_id,
                "sessionId": f"sub-{uuid.uuid4().hex[:8]}",
                "message": {
                    "role": "user",
                    "parts": [
                        {"type": "text", "text": f"Cross-verify SBOM CVE escrow readiness for {target_company}."},
                        {
                            "type": "data",
                            "data": {
                                "subtask_type": "verify_cyber_escrow_readiness",
                                "skill_id": receiver_skill_id,
                                "sender_agent": sender_agent,
                                "target_company": target_company,
                                "deal_id": deal_id,
                                "correlation_id": corr_id,
                                "deadline_epoch_ms": time.time() * 1000.0 + deadline_ms_from_now,
                            },
                        },
                    ],
                },
            },
        }
        req = urllib.request.Request(
            endpoint_url,
            data=json.dumps(rpc_payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {jwt_tok}"},
            method="POST",
        )
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                rpc_resp = json.loads(resp.read().decode("utf-8"))
                task_obj = rpc_resp["result"]
                artifact = task_obj["artifacts"][0]["parts"][0]["data"]
                self.http_exchange_log.append({
                    "task_id": task_id,
                    "sender": sender_agent,
                    "receiver": receiver_skill_id,
                    "endpoint": endpoint_url,
                    "deal_id": task_obj["dealId"],
                    "correlation_id": task_obj["correlationId"],
                    "state": task_obj["status"]["state"],
                    "rtt_ms": round((time.perf_counter() - t0) * 1000.0, 2),
                })
                return artifact
        except urllib.error.HTTPError as he:
            err_body = he.read().decode("utf-8", errors="replace")
            try:
                err_data = json.loads(err_body)
                err_info = err_data.get("error", {})
                err_msg = err_info.get("message", err_body)
                err_type = err_info.get("error_type", "")
                if err_type == "LiveExecutionError" or "Live execution failed" in err_msg or "LiveExecutionError" in err_msg:
                    raise LiveExecutionError(err_msg) from he
                if err_type == "PermissionError" or he.code == 403:
                    raise PermissionError(err_msg) from he
                if err_type == "TimeoutError" or he.code == 408:
                    raise TimeoutError(err_msg) from he
            except (json.JSONDecodeError, KeyError):
                pass
            if "Live execution failed" in err_body or "LiveExecutionError" in err_body:
                raise LiveExecutionError(f"A2A HTTP {he.code} error from {endpoint_url}: {err_body}") from he
            raise RuntimeError(f"A2A HTTP {he.code} error from {endpoint_url}: {err_body}") from he

    def send_a2a_task(
        self,
        session_id: str,
        deal_id: str,
        request_id: str,
        sender_agent: str,
        skill_id: str,
        target_company: str,
        user_prompt: str,
        trace_id: str,
        parent_span_id: Optional[str],
        reasoning_mode: str = "ReAct",
        persona_name: str = "Managing_Director",
        random_seed: int = 2026,
        requested_execution_mode: str = "deterministic",
        blackboard_id: Optional[str] = None,
        deadline_ms_from_now: float = 30000.0,
    ) -> Tuple[Dict[str, Any], DomainRiskAssessment]:
        if skill_id not in self.skill_to_endpoint:
            raise KeyError(f"Skill '{skill_id}' not discovered in federated A2A directory.")
        endpoint_url = self.skill_to_endpoint[skill_id]
        task_id = f"a2a-task-{uuid.uuid4().hex[:10]}"
        jwt_tok = create_jwt_token(subject=sender_agent, allowed_targets=[target_company])

        rpc_payload = {
            "jsonrpc": "2.0",
            "id": f"rpc-{uuid.uuid4().hex[:8]}",
            "method": "tasks/send",
            "params": {
                "id": task_id,
                "sessionId": session_id,
                "message": {
                    "role": "user",
                    "parts": [
                        {"type": "text", "text": user_prompt},
                        {
                            "type": "data",
                            "data": {
                                "skill_id": skill_id,
                                "sender_agent": sender_agent,
                                "deal_id": deal_id,
                                "correlation_id": request_id,
                                "target_company": target_company,
                                "trace_id": trace_id,
                                "parent_span_id": parent_span_id,
                                "reasoning_mode": reasoning_mode,
                                "persona_name": persona_name,
                                "random_seed": random_seed,
                                "requested_execution_mode": requested_execution_mode,
                                "blackboard_id": blackboard_id,
                                "deadline_epoch_ms": time.time() * 1000.0 + deadline_ms_from_now,
                            },
                        },
                    ],
                },
            },
        }
        req = urllib.request.Request(
            endpoint_url,
            data=json.dumps(rpc_payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {jwt_tok}"},
            method="POST",
        )
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=25.0) as resp:
                rpc_resp = json.loads(resp.read().decode("utf-8"))
                task_obj = rpc_resp["result"]
                artifact_data = task_obj["artifacts"][0]["parts"][0]["data"]
                assessment = DomainRiskAssessment(**artifact_data)
                rtt_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                self.http_exchange_log.append({
                    "task_id": task_id,
                    "sender": sender_agent,
                    "receiver": skill_id,
                    "endpoint": endpoint_url,
                    "deal_id": task_obj["dealId"],
                    "correlation_id": task_obj["correlationId"],
                    "state": task_obj["status"]["state"],
                    "rtt_ms": rtt_ms,
                })
                return task_obj, assessment
        except urllib.error.HTTPError as he:
            err_body = he.read().decode("utf-8", errors="replace")
            try:
                err_data = json.loads(err_body)
                err_info = err_data.get("error", {})
                err_msg = err_info.get("message", err_body)
                err_type = err_info.get("error_type", "")
                if err_type == "LiveExecutionError" or "Live execution failed" in err_msg or "LiveExecutionError" in err_msg:
                    raise LiveExecutionError(err_msg) from he
                if err_type == "PermissionError" or he.code == 403:
                    raise PermissionError(err_msg) from he
                if err_type == "TimeoutError" or he.code == 408:
                    raise TimeoutError(err_msg) from he
            except (json.JSONDecodeError, KeyError):
                pass
            if "Live execution failed" in err_body or "LiveExecutionError" in err_body:
                raise LiveExecutionError(f"A2A HTTP {he.code} error from {endpoint_url}: {err_body}") from he
            raise RuntimeError(f"A2A HTTP {he.code} error from {endpoint_url}: {err_body}") from he

    def get_a2a_task(self, skill_id: str, task_id: str, target_company: str) -> Dict[str, Any]:
        endpoint_url = self.skill_to_endpoint[skill_id]
        jwt_tok = create_jwt_token(subject="A2A_Task_Inspector", allowed_targets=[target_company])
        rpc_payload = {"jsonrpc": "2.0", "id": "get-1", "method": "tasks/get", "params": {"id": task_id}}
        req = urllib.request.Request(
            endpoint_url,
            data=json.dumps(rpc_payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {jwt_tok}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return json.loads(resp.read().decode("utf-8"))["result"]
