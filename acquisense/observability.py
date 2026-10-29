"""
OpenTelemetry-compatible tracing, monotonic wall-clock measurement, parent-child span context,
and strict separation of provider-reported live token/cost usage vs. deterministic/cached runs.
"""

import os
import json
import time
import uuid
import hashlib
import threading
import contextlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import pandas as pd

try:
    from opentelemetry import trace as otel_trace
    from opentelemetry.sdk.trace import TracerProvider as OtelTracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor as OtelSpanProcessor, InMemorySpanExporter as OtelInMemoryExporter
    OTEL_SDK_INSTALLED = True
except ImportError:
    OTEL_SDK_INSTALLED = False


@dataclass
class TraceSpan:
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    span_category: str  # "API_REQUEST", "AGENT_INVOCATION", "LLM_REQUEST", "MCP_CALL", "A2A_REQUEST", "BLACKBOARD_IO", "VALIDATION"
    agent_id: str
    framework: str
    stage: str
    execution_mode: str  # "deterministic", "live", "live_cache_replay"
    model_id: str
    process_pid: int
    thread_name: str
    start_time_unix_ns: int
    end_time_unix_ns: int
    start_time_ms: float
    end_time_ms: float
    duration_ms: float
    retry_count: int
    cache_hit: bool
    provider_reported_tokens: Optional[int]
    provider_reported_cost_usd: Optional[float]
    input_sha256: str
    output_sha256: str
    status: str = "STATUS_CODE_OK"
    error_detail: Optional[str] = None


class ObservabilityTraceManager:
    def __init__(self, otlp_export_path: str):
        self._lock = threading.RLock()
        self.otlp_export_path = otlp_export_path
        self.t0_monotonic_ms = time.perf_counter() * 1000.0
        self.spans: List[TraceSpan] = []
        self.provenance_records: List[Dict[str, Any]] = []
        if OTEL_SDK_INSTALLED:
            self.otel_exporter = OtelInMemoryExporter()
            provider = OtelTracerProvider()
            provider.add_span_processor(OtelSpanProcessor(self.otel_exporter))
            self.otel_tracer = provider.get_tracer("acquisense.mas.otel")
        else:
            self.otel_tracer = None

    def now_monotonic_ms(self) -> float:
        return round(time.perf_counter() * 1000.0 - self.t0_monotonic_ms, 3)

    def record_completed_span(
        self,
        trace_id: str,
        parent_span_id: Optional[str],
        span_category: str,
        agent_id: str,
        framework: str,
        stage: str,
        execution_mode: str,
        model_id: str,
        start_ns: int,
        end_ns: int,
        start_rel_ms: float,
        end_rel_ms: float,
        input_payload: Any,
        output_payload: Any,
        retry_count: int = 0,
        cache_hit: bool = False,
        provider_reported_tokens: Optional[int] = None,
        provider_reported_cost_usd: Optional[float] = None,
        status: str = "STATUS_CODE_OK",
        error_detail: Optional[str] = None,
    ) -> str:
        span_id = uuid.uuid4().hex[:16]
        in_sha = hashlib.sha256(json.dumps(input_payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        out_sha = hashlib.sha256(json.dumps(output_payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        dur_ms = max(0.01, round(end_rel_ms - start_rel_ms, 3))

        if self.otel_tracer is not None:
            with self.otel_tracer.start_as_current_span(f"{agent_id}.{stage}") as ot_span:
                ot_span.set_attribute("acquisense.span_category", span_category)
                ot_span.set_attribute("acquisense.agent_id", agent_id)
                ot_span.set_attribute("acquisense.framework", framework)
                ot_span.set_attribute("acquisense.stage", stage)
                ot_span.set_attribute("acquisense.execution_mode", execution_mode)
                ot_span.set_attribute("acquisense.model_id", model_id)
                ot_span.set_attribute("acquisense.duration_ms", dur_ms)

        sp = TraceSpan(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            span_category=span_category,
            agent_id=agent_id,
            framework=framework,
            stage=stage,
            execution_mode=execution_mode,
            model_id=model_id,
            process_pid=os.getpid(),
            thread_name=threading.current_thread().name,
            start_time_unix_ns=start_ns,
            end_time_unix_ns=end_ns,
            start_time_ms=round(start_rel_ms, 3),
            end_time_ms=round(end_rel_ms, 3),
            duration_ms=dur_ms,
            retry_count=retry_count,
            cache_hit=cache_hit,
            provider_reported_tokens=provider_reported_tokens,
            provider_reported_cost_usd=provider_reported_cost_usd,
            input_sha256=in_sha,
            output_sha256=out_sha,
            status=status,
            error_detail=error_detail,
        )
        with self._lock:
            self.spans.append(sp)
        return span_id

    def export_otlp_json(self) -> str:
        with self._lock:
            otlp_spans = []
            for s in self.spans:
                otlp_spans.append({
                    "traceId": s.trace_id,
                    "spanId": s.span_id,
                    "parentSpanId": s.parent_span_id or "",
                    "name": f"{s.agent_id}/{s.stage}",
                    "kind": "SPAN_KIND_INTERNAL",
                    "startTimeUnixNano": str(s.start_time_unix_ns),
                    "endTimeUnixNano": str(s.end_time_unix_ns),
                    "attributes": [
                        {"key": "span.category", "value": {"stringValue": s.span_category}},
                        {"key": "agent.id", "value": {"stringValue": s.agent_id}},
                        {"key": "agent.framework", "value": {"stringValue": s.framework}},
                        {"key": "execution.stage", "value": {"stringValue": s.stage}},
                        {"key": "execution.mode", "value": {"stringValue": s.execution_mode}},
                        {"key": "model.id", "value": {"stringValue": s.model_id}},
                        {"key": "cache.hit", "value": {"boolValue": s.cache_hit}},
                        {"key": "retry.count", "value": {"intValue": str(s.retry_count)}},
                        {"key": "process.pid", "value": {"intValue": str(s.process_pid)}},
                        {"key": "input.sha256", "value": {"stringValue": s.input_sha256}},
                        {"key": "output.sha256", "value": {"stringValue": s.output_sha256}},
                    ],
                    "status": {"code": s.status, "message": s.error_detail or ""},
                })
            otlp_doc = {
                "resourceSpans": [
                    {
                        "resource": {
                            "attributes": [
                                {"key": "service.name", "value": {"stringValue": "acquisense-due-diligence-mas"}},
                                {"key": "service.version", "value": {"stringValue": "4.2.0"}},
                            ]
                        },
                        "scopeSpans": [
                            {
                                "scope": {"name": "acquisense.observability.otlp", "version": "4.2.0"},
                                "spans": otlp_spans,
                            }
                        ],
                    }
                ]
            }
            with open(self.otlp_export_path, "w", encoding="utf-8") as f:
                json.dump(otlp_doc, f, indent=2)
            return self.otlp_export_path

    def record_provenance(
        self,
        trace_id: str,
        deal_id: str,
        target_company: str,
        evidence_id: str,
        file_path: str,
        byte_offset_start: int,
        byte_offset_end: int,
        file_sha256: str,
        consumer_agent: str,
        classification_status: str,
    ) -> None:
        verified = False
        excerpt = ""
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                raw = f.read()
            verified = (hashlib.sha256(raw).hexdigest() == file_sha256)
            excerpt = raw[byte_offset_start:byte_offset_end].decode("utf-8", errors="replace")
        with self._lock:
            self.provenance_records.append({
                "trace_id": trace_id,
                "deal_id": deal_id,
                "target_company": target_company,
                "evidence_id": evidence_id,
                "source_file": os.path.basename(file_path),
                "byte_range": f"{byte_offset_start}:{byte_offset_end}",
                "sha256_verified": verified,
                "full_sha256": file_sha256,
                "consumer_agent": consumer_agent,
                "classification": classification_status,
                "clause_excerpt": excerpt[:62] + "...",
            })

    def to_dataframe(self) -> pd.DataFrame:
        with self._lock:
            return pd.DataFrame([s.__dict__ for s in self.spans])


class AgentMonitoringCallbackHandler:
    ORDERED_STAGES = [
        "1_Prompt_Guardrail",
        "2_Context_Read",
        "3_MCP_Tool_Call",
        "4_Agent_Reasoning",
        "5_Pydantic_Validation",
        "6_Context_Write",
    ]

    STAGE_TO_CATEGORY = {
        "1_Prompt_Guardrail": "VALIDATION",
        "2_Context_Read": "BLACKBOARD_IO",
        "3_MCP_Tool_Call": "MCP_CALL",
        "4_Agent_Reasoning": "LLM_REQUEST",
        "5_Pydantic_Validation": "VALIDATION",
        "6_Context_Write": "BLACKBOARD_IO",
    }

    def __init__(self, tracer: ObservabilityTraceManager):
        self._lock = threading.RLock()
        self.tracer = tracer
        self.stage_latency_totals: Dict[str, Dict[str, float]] = {}
        self.stage_call_counts: Dict[str, Dict[str, int]] = {}
        self.cross_agent_matrix: Dict[str, Dict[str, int]] = {}
        self.error_events: List[Dict[str, Any]] = []

    def _ensure_agent(self, agent_id: str) -> None:
        if agent_id not in self.stage_latency_totals:
            self.stage_latency_totals[agent_id] = {s: 0.0 for s in self.ORDERED_STAGES}
            self.stage_call_counts[agent_id] = {s: 0 for s in self.ORDERED_STAGES}
        if agent_id not in self.cross_agent_matrix:
            self.cross_agent_matrix[agent_id] = {}

    @contextlib.contextmanager
    def track_stage(
        self,
        trace_id: str,
        parent_span_id: Optional[str],
        agent_id: str,
        framework: str,
        stage: str,
        input_data: Any,
        execution_mode: str = "deterministic",
        model_id: str = "deterministic-rule-engine-v4.2",
        span_category: Optional[str] = None,
    ):
        start_ns = time.time_ns()
        start_ms = self.tracer.now_monotonic_ms()
        cat = span_category or self.STAGE_TO_CATEGORY.get(stage, "AGENT_INVOCATION")
        span_ctx: Dict[str, Any] = {
            "span_id": None,
            "output": None,
            "retry_count": 0,
            "cache_hit": False,
            "provider_reported_tokens": None,
            "provider_reported_cost_usd": None,
            "model_id": model_id,
            "execution_mode": execution_mode,
        }
        try:
            yield span_ctx
            end_ns = time.time_ns()
            end_ms = self.tracer.now_monotonic_ms()
            dur_ms = max(0.01, end_ms - start_ms)
            with self._lock:
                self._ensure_agent(agent_id)
                if stage in self.stage_latency_totals[agent_id]:
                    self.stage_latency_totals[agent_id][stage] += dur_ms
                    self.stage_call_counts[agent_id][stage] += 1
            sid = self.tracer.record_completed_span(
                trace_id=trace_id,
                parent_span_id=parent_span_id,
                span_category=cat,
                agent_id=agent_id,
                framework=framework,
                stage=stage,
                execution_mode=span_ctx["execution_mode"],
                model_id=span_ctx["model_id"],
                start_ns=start_ns,
                end_ns=end_ns,
                start_rel_ms=start_ms,
                end_rel_ms=end_ms,
                input_payload=input_data,
                output_payload=span_ctx.get("output"),
                retry_count=span_ctx["retry_count"],
                cache_hit=span_ctx["cache_hit"],
                provider_reported_tokens=span_ctx["provider_reported_tokens"],
                provider_reported_cost_usd=span_ctx["provider_reported_cost_usd"],
                status="STATUS_CODE_OK",
            )
            span_ctx["span_id"] = sid
        except Exception as ex:
            end_ns = time.time_ns()
            end_ms = self.tracer.now_monotonic_ms()
            with self._lock:
                self.error_events.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "trace_id": trace_id,
                    "agent_id": agent_id,
                    "stage": stage,
                    "error": str(ex),
                })
            self.tracer.record_completed_span(
                trace_id=trace_id,
                parent_span_id=parent_span_id,
                span_category=cat,
                agent_id=agent_id,
                framework=framework,
                stage=stage,
                execution_mode=span_ctx["execution_mode"],
                model_id=span_ctx["model_id"],
                start_ns=start_ns,
                end_ns=end_ns,
                start_rel_ms=start_ms,
                end_rel_ms=end_ms,
                input_payload=input_data,
                output_payload={"error": str(ex)},
                retry_count=span_ctx["retry_count"],
                cache_hit=span_ctx["cache_hit"],
                status="STATUS_CODE_ERROR",
                error_detail=str(ex),
            )
            raise

    def on_context_interaction(self, source_entity: str, target_entity: str, weight: int = 1) -> None:
        with self._lock:
            self._ensure_agent(source_entity)
            self._ensure_agent(target_entity)
            self.cross_agent_matrix[source_entity][target_entity] = (
                self.cross_agent_matrix[source_entity].get(target_entity, 0) + weight
            )
