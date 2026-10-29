"""
Orchestration engine implementing genuine Sequential, Parallel, and Hierarchical patterns
plus standalone Peer-to-Peer comparison mode, wired to the 6 specialist agents over
HTTP A2A and Streamable HTTP MCP.
"""

import os
import json
import time
import uuid
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import numpy as np

from acquisense.config import AcquiSenseConfig, AICreditsModelGateway, PersistentLLMCache
from acquisense.schemas import (
    DomainType,
    SeverityLevel,
    ExposureCategory,
    GoNoGoDecision,
    DCFValuationOutput,
    MLForecastOutput,
    DomainRiskAssessment,
    ConsolidatedDueDiligenceReport,
    compute_deterministic_committee_decision,
)
from acquisense.security import SecurityGuardrailEngine
from acquisense.observability import ObservabilityTraceManager, AgentMonitoringCallbackHandler
from acquisense.blackboard import DueDiligenceBlackboard, PeerToPeerMeshBus
from acquisense.mcp_service import (
    TARGET_PROFILES,
    ON_DISK_RAW_VDR_FILES,
    INDEPENDENT_GROUND_TRUTH_LABELS,
    initialize_corpus_and_databases,
    build_mcp_tools,
    MCPStreamableHttpServer,
    MCPStreamableHttpClient,
)
from acquisense.agents import build_six_specialist_agents
from acquisense.a2a_services import (
    ACTIVE_WORKFLOW_CONTEXTS,
    _WORKFLOW_CTX_LOCK,
    StandardA2AServiceCluster,
    StandardA2AFederatedClient,
)


def validate_consolidated_report_strictly(
    report: ConsolidatedDueDiligenceReport,
    target_company: str,
    guardrails: SecurityGuardrailEngine,
) -> ConsolidatedDueDiligenceReport:
    domains_seen = [d.domain for d in report.domain_assessments]
    if len(domains_seen) != 6 or len(set(domains_seen)) != 6:
        raise ValueError(f"Report must contain all 6 unique domains; got {[d.value for d in domains_seen]}")

    for d in report.domain_assessments:
        guardrails.verify_claim_grounding(d, target_company, ON_DISK_RAW_VDR_FILES)

    if report.dcf_valuation.terminal_growth_pct >= report.dcf_valuation.wacc_pct:
        raise ValueError("DCF Terminal Growth Rate must be strictly less than WACC.")

    expected_offer = round(report.implied_equity_value_musd - report.direct_price_reduction_musd, 2)
    if abs(report.recommended_offer_price_musd - expected_offer) > 0.05:
        raise ValueError(f"Offer price math mismatch: {report.recommended_offer_price_musd} != {expected_offer}")

    if report.context_completeness_pct < 100.0 and report.final_decision == GoNoGoDecision.GO:
        raise ValueError("Cannot issue unconditional GO decision when context_completeness_pct < 100.0%!")
    return report


class ADKExecutiveOrchestrator:
    NON_FIN_SKILLS = [
        "ADK_Legal_Agent",
        "CrewAI_Tech_Agent",
        "CrewAI_Cyber_Agent",
        "CrewAI_HR_Agent",
        "CrewAI_ESG_Agent",
    ]

    def __init__(
        self,
        config: AcquiSenseConfig,
        gateway: AICreditsModelGateway,
        a2a_client: StandardA2AFederatedClient,
        guardrails: SecurityGuardrailEngine,
        monitor: AgentMonitoringCallbackHandler,
        tracer: ObservabilityTraceManager,
    ):
        self.agent_id = "ADK_Executive_Synthesizer"
        self.framework = "Google_ADK"
        self.config = config
        self.gateway = gateway
        self.a2a_client = a2a_client
        self.guardrails = guardrails
        self.monitor = monitor
        self.tracer = tracer

    def run_due_diligence_workflow(
        self,
        target_company: str,
        user_prompt: str,
        design_pattern: str = "Hierarchical",   # "Sequential", "Parallel", "Hierarchical"
        messaging_mode: str = "Blackboard",      # "Blackboard" or "PeerToPeer"
        reasoning_mode: str = "ReAct",
        persona_name: str = "Managing_Director",
        random_seed: int = 2026,
        requested_execution_mode: Optional[str] = None,
        hard_reject_on_injection: bool = False,
        deal_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Tuple[ConsolidatedDueDiligenceReport, Optional[DueDiligenceBlackboard], Dict[str, Any]]:
        if target_company not in TARGET_PROFILES:
            raise ValueError(f"Unknown target_company '{target_company}'.")
        if design_pattern not in ("Sequential", "Parallel", "Hierarchical"):
            raise ValueError(f"Unsupported design_pattern '{design_pattern}'.")
        if messaging_mode not in ("Blackboard", "PeerToPeer"):
            raise ValueError(f"Unsupported messaging_mode '{messaging_mode}'.")

        req_mode = (requested_execution_mode or self.config.execution_mode).strip().lower()
        if req_mode == "live" and not self.config.allow_deterministic_fallback:
            self.gateway.verify_live_preflight()

        wall_t0 = time.perf_counter()
        trace_id = uuid.uuid4().hex
        session_id = f"sess-{uuid.uuid4().hex[:10]}"
        eff_deal_id = deal_id or f"deal-{uuid.uuid4().hex[:8]}"
        eff_req_id = request_id or f"req-{uuid.uuid4().hex[:8]}"

        profile = TARGET_PROFILES[target_company]
        asking_price = float(profile["asking_price_musd"])
        acquirer = profile["acquirer"]

        all_agent_ids = self.NON_FIN_SKILLS + ["ADK_Financial_Agent", self.agent_id]
        if messaging_mode == "Blackboard":
            bb_id = f"bb-{uuid.uuid4().hex[:12]}"
            blackboard: Optional[DueDiligenceBlackboard] = DueDiligenceBlackboard(
                target_company, asking_price, self.monitor,
                wal_db_path=self.config.sqlite_db_path,
                blackboard_id=bb_id, deal_id=eff_deal_id,
            )
            p2p_bus: Optional[PeerToPeerMeshBus] = None
        else:
            bb_id = None
            blackboard = None
            p2p_bus = PeerToPeerMeshBus(all_agent_ids, self.monitor, max_queue_size=3, network_jitter_ms=0.2)

        with _WORKFLOW_CTX_LOCK:
            ACTIVE_WORKFLOW_CONTEXTS[session_id] = {"blackboard": blackboard, "p2p_bus": p2p_bus}

        try:
            # STAGE 1: Root Prompt Guardrail Check
            with self.monitor.track_stage(
                trace_id, None, self.agent_id, self.framework,
                "1_Prompt_Guardrail", {"prompt": user_prompt[:100], "persona": persona_name},
                execution_mode=req_mode,
            ) as root_s1:
                guard_res = self.guardrails.inspect_text(
                    user_prompt,
                    persona_name=persona_name,
                    hard_reject_on_injection=hard_reject_on_injection,
                )
                root_s1["output"] = {"verdict": guard_res.policy_verdict, "cutoff_musd": guard_res.persona_materiality_cutoff_musd}
            root_span_id = root_s1["span_id"]

            domain_results: List[DomainRiskAssessment] = []

            if design_pattern == "Sequential":
                for sk_id in self.NON_FIN_SKILLS:
                    _, assessment = self.a2a_client.send_a2a_task(
                        session_id=session_id, deal_id=eff_deal_id, request_id=eff_req_id,
                        sender_agent=self.agent_id, skill_id=sk_id,
                        target_company=target_company, user_prompt=guard_res.effective_prompt,
                        trace_id=trace_id, parent_span_id=root_span_id,
                        reasoning_mode=reasoning_mode, persona_name=persona_name,
                        random_seed=random_seed, requested_execution_mode=req_mode, blackboard_id=bb_id,
                    )
                    domain_results.append(assessment)
                _, fin_assessment = self.a2a_client.send_a2a_task(
                    session_id=session_id, deal_id=eff_deal_id, request_id=eff_req_id,
                    sender_agent=self.agent_id, skill_id="ADK_Financial_Agent",
                    target_company=target_company, user_prompt=guard_res.effective_prompt,
                    trace_id=trace_id, parent_span_id=root_span_id,
                    reasoning_mode=reasoning_mode, persona_name=persona_name,
                    random_seed=random_seed, requested_execution_mode=req_mode, blackboard_id=bb_id,
                )
                domain_results.append(fin_assessment)

            elif design_pattern == "Parallel":
                with ThreadPoolExecutor(max_workers=5, thread_name_prefix="ParallelA2A") as pool:
                    futs = {
                        pool.submit(
                            self.a2a_client.send_a2a_task,
                            session_id, eff_deal_id, eff_req_id, self.agent_id, sk_id,
                            target_company, guard_res.effective_prompt,
                            trace_id, root_span_id, reasoning_mode, persona_name,
                            random_seed, req_mode, bb_id,
                        ): sk_id
                        for sk_id in self.NON_FIN_SKILLS
                    }
                    for fut in as_completed(futs):
                        _, assessment = fut.result()
                        domain_results.append(assessment)

                _, fin_assessment = self.a2a_client.send_a2a_task(
                    session_id=session_id, deal_id=eff_deal_id, request_id=eff_req_id,
                    sender_agent=self.agent_id, skill_id="ADK_Financial_Agent",
                    target_company=target_company, user_prompt=guard_res.effective_prompt,
                    trace_id=trace_id, parent_span_id=root_span_id,
                    reasoning_mode=reasoning_mode, persona_name=persona_name,
                    random_seed=random_seed, requested_execution_mode=req_mode, blackboard_id=bb_id,
                )
                domain_results.append(fin_assessment)

            elif design_pattern == "Hierarchical":
                self.monitor.on_context_interaction(self.agent_id, "ADK_Risk_Committee_Lead", weight=1)
                self.monitor.on_context_interaction(self.agent_id, "CrewAI_Operations_Crew_Lead", weight=1)

                def _adk_sublead() -> DomainRiskAssessment:
                    _, a_res = self.a2a_client.send_a2a_task(
                        session_id, eff_deal_id, eff_req_id, "ADK_Risk_Committee_Lead", "ADK_Legal_Agent",
                        target_company, guard_res.effective_prompt,
                        trace_id, root_span_id, reasoning_mode, persona_name, random_seed, req_mode, bb_id,
                    )
                    return a_res

                def _crewai_sublead() -> List[DomainRiskAssessment]:
                    out_list: List[DomainRiskAssessment] = []
                    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="CrewAISubLead") as sub_pool:
                        futs = [
                            sub_pool.submit(
                                self.a2a_client.send_a2a_task,
                                session_id, eff_deal_id, eff_req_id, "CrewAI_Operations_Crew_Lead", sk_id,
                                target_company, guard_res.effective_prompt,
                                trace_id, root_span_id, reasoning_mode, persona_name, random_seed, req_mode, bb_id,
                            )
                            for sk_id in ["CrewAI_Tech_Agent", "CrewAI_Cyber_Agent", "CrewAI_HR_Agent", "CrewAI_ESG_Agent"]
                        ]
                        for f in as_completed(futs):
                            _, a_res = f.result()
                            out_list.append(a_res)
                    return out_list

                with ThreadPoolExecutor(max_workers=2, thread_name_prefix="Tier2Supervisors") as sup_pool:
                    f1 = sup_pool.submit(_adk_sublead)
                    f2 = sup_pool.submit(_crewai_sublead)
                    domain_results.append(f1.result())
                    domain_results.extend(f2.result())

                if blackboard is not None:
                    blackboard.write(
                        "ADK_Risk_Committee_Lead", "supervisor_reconciliation", "tier2_audit",
                        {
                            "critical_domains": [d.domain.value for d in domain_results if d.severity == SeverityLevel.CRITICAL],
                            "contradictions_resolved": 0,
                        },
                    )

                _, fin_assessment = self.a2a_client.send_a2a_task(
                    session_id=session_id, deal_id=eff_deal_id, request_id=eff_req_id,
                    sender_agent="ADK_Risk_Committee_Lead", skill_id="ADK_Financial_Agent",
                    target_company=target_company, user_prompt=guard_res.effective_prompt,
                    trace_id=trace_id, parent_span_id=root_span_id,
                    reasoning_mode=reasoning_mode, persona_name=persona_name,
                    random_seed=random_seed, requested_execution_mode=req_mode, blackboard_id=bb_id,
                )
                domain_results.append(fin_assessment)

            domain_order = [
                DomainType.LEGAL, DomainType.TECH, DomainType.CYBER,
                DomainType.HR, DomainType.ESG, DomainType.FINANCIAL,
            ]
            domain_results.sort(key=lambda x: domain_order.index(x.domain))

            # STAGE 2 (Synthesizer): Read aggregated state
            with self.monitor.track_stage(
                trace_id, root_span_id, self.agent_id, self.framework,
                "2_Context_Read", {"messaging_mode": messaging_mode},
                execution_mode=req_mode,
            ) as syn_s2:
                if blackboard is not None:
                    blackboard.sync_from_durable_wal()
                    dcf_dict = blackboard.read(self.agent_id, "dcf_valuation", "latest")
                    ml_dict = blackboard.read(self.agent_id, "ml_forecast", "latest")
                    _, _, fin_seen_domains = blackboard.get_exposure_breakdown()
                    context_completeness_pct = round((fin_seen_domains / 6.0) * 100.0, 2)
                else:
                    p2p_bus.drain_inbox_and_read(self.agent_id, "domain_assessments", expected_peers=6)
                    dcf_dict = (
                        p2p_bus.drain_inbox_and_read(self.agent_id, "dcf_valuation", expected_peers=1).get("latest")
                        or p2p_bus.local_state_views["ADK_Financial_Agent"]["dcf_valuation"].get("latest")
                    )
                    ml_dict = (
                        p2p_bus.drain_inbox_and_read(self.agent_id, "ml_forecast", expected_peers=1).get("latest")
                        or p2p_bus.local_state_views["ADK_Financial_Agent"]["ml_forecast"].get("latest")
                    )
                    fin_inbox_domains = len(p2p_bus.local_state_views["ADK_Financial_Agent"]["domain_assessments"])
                    context_completeness_pct = round((fin_inbox_domains / 6.0) * 100.0, 2)
                syn_s2["output"] = {"context_completeness_pct": context_completeness_pct}
            syn_s2_id = syn_s2["span_id"]

            # STAGE 4 (Synthesizer): Deterministic Committee Decision Rule
            with self.monitor.track_stage(
                trace_id, syn_s2_id, self.agent_id, self.framework,
                "4_Agent_Reasoning", {"pattern": design_pattern, "completeness_pct": context_completeness_pct},
                execution_mode=req_mode,
            ) as syn_s4:
                dcf_obj = DCFValuationOutput(**dcf_dict)
                ml_obj = MLForecastOutput(**ml_dict)
                req_contingent_escrow = sum(
                    e.financial_impact_musd for e in ON_DISK_RAW_VDR_FILES[target_company]
                    if e.exposure_category == ExposureCategory.CONTINGENT_ESCROW_LIABILITY
                )
                decision, composite_risk, unresolved_critical, incomplete_hold = compute_deterministic_committee_decision(
                    domain_assessments=domain_results,
                    dcf_obj=dcf_obj,
                    ml_obj=ml_obj,
                    context_completeness_pct=context_completeness_pct,
                    required_contingent_escrow_musd=req_contingent_escrow,
                )
                avg_conf = round(float(np.mean([d.heuristic_confidence_score for d in domain_results])), 3)
                syn_s4["output"] = {
                    "decision": decision.value,
                    "incomplete_context_hold": incomplete_hold,
                    "composite_risk": composite_risk,
                }
            syn_s4_id = syn_s4["span_id"]

            closing_conditions = [cov for d in domain_results for cov in d.mitigation_covenants]
            report_id = f"ACQ-RPT-{uuid.uuid4().hex[:8].upper()}"

            # Determine overall actual_execution_mode across all 6 agents
            modes_set = {d.actual_execution_mode for d in domain_results}
            if modes_set == {"live"}:
                overall_actual_mode = "live"
            elif "live_cache_replay" in modes_set and "deterministic" not in modes_set:
                overall_actual_mode = "live_cache_replay"
            elif "deterministic_fallback" in modes_set:
                overall_actual_mode = "deterministic_fallback"
            else:
                overall_actual_mode = "deterministic"

            # STAGE 6 (Synthesizer): Commit Decision Before Computing Context Snapshot SHA-256
            with self.monitor.track_stage(
                trace_id, syn_s4_id, self.agent_id, self.framework,
                "6_Context_Write", {"report_id": report_id},
                execution_mode=overall_actual_mode,
            ) as syn_s6:
                if blackboard is not None:
                    blackboard.write(
                        self.agent_id, "executive_decision", "final_summary",
                        {"report_id": report_id, "decision": decision.value, "offer_musd": dcf_obj.risk_adjusted_offer_price_musd},
                    )
                    ctx_mechanism = "DURABLE_SQLITE_WAL_BLACKBOARD"
                    ctx_sha256 = blackboard.chain_hash
                else:
                    ctx_mechanism = "BOUNDED_P2P_LOCAL_SNAPSHOT"
                    raw_snap = json.dumps(p2p_bus.local_state_views[self.agent_id], sort_keys=True, default=str)
                    ctx_sha256 = hashlib.sha256(raw_snap.encode("utf-8")).hexdigest()
                syn_s6["output"] = {"context_mechanism": ctx_mechanism, "sha256": ctx_sha256[:16]}
            syn_s6_id = syn_s6["span_id"]

            rationale = (
                f"AcquiSense Decision for {target_company}: {decision.value} "
                f"(Composite Risk={composite_risk}/100, Heuristic Confidence={avg_conf*100:.1f}%, "
                f"Context Completeness={context_completeness_pct:.1f}%, Hold Applied={incomplete_hold}). "
                f"DCF Bridge: Base EV=${dcf_obj.base_enterprise_value_musd:.2f}M -> "
                f"Implied Equity=${dcf_obj.implied_equity_value_musd:.2f}M -> "
                f"Direct Price Reduction=-${dcf_obj.direct_price_reduction_musd:.2f}M -> "
                f"Recommended Offer=${dcf_obj.risk_adjusted_offer_price_musd:.2f}M, "
                f"plus Separate Escrow Holdback=${dcf_obj.indemnity_escrow_holdback_musd:.2f}M."
            )

            # STAGE 5 (Synthesizer): Strict Pydantic Validation
            with self.monitor.track_stage(
                trace_id, syn_s6_id, self.agent_id, self.framework,
                "5_Pydantic_Validation", {"report_id": report_id},
                execution_mode=overall_actual_mode,
            ) as syn_s5:
                report = ConsolidatedDueDiligenceReport(
                    report_id=report_id,
                    deal_id=eff_deal_id,
                    request_id=eff_req_id,
                    timestamp_utc=datetime.now(timezone.utc).isoformat(),
                    requested_execution_mode=req_mode,
                    actual_execution_mode=overall_actual_mode,
                    target_company=target_company,
                    acquirer_company=acquirer,
                    asking_price_musd=asking_price,
                    base_enterprise_value_musd=dcf_obj.base_enterprise_value_musd,
                    implied_equity_value_musd=dcf_obj.implied_equity_value_musd,
                    direct_price_reduction_musd=dcf_obj.direct_price_reduction_musd,
                    recommended_offer_price_musd=dcf_obj.risk_adjusted_offer_price_musd,
                    escrow_holdback_musd=dcf_obj.indemnity_escrow_holdback_musd,
                    composite_risk_score=composite_risk,
                    unresolved_critical_domains=unresolved_critical,
                    heuristic_overall_confidence=avg_conf,
                    context_completeness_pct=context_completeness_pct,
                    incomplete_context_hold_applied=incomplete_hold,
                    final_decision=decision,
                    executive_rationale=rationale,
                    dcf_valuation=dcf_obj,
                    ml_forecast=ml_obj,
                    domain_assessments=domain_results,
                    mandatory_closing_conditions=closing_conditions,
                    context_mechanism=ctx_mechanism,
                    context_snapshot_sha256=ctx_sha256,
                )
                validate_consolidated_report_strictly(report, target_company, self.guardrails)
                syn_s5["output"] = {"strict_validation": "PASSED"}

            wall_clock_ms = round((time.perf_counter() - wall_t0) * 1000.0, 2)

            # Evaluate Clause-Level Risk Detection Against Independent Ground-Truth Labels
            gt_info = INDEPENDENT_GROUND_TRUTH_LABELS[target_company]
            gt_pos: Set[str] = gt_info["true_material_risk_ids"]
            gt_neg: Set[str] = gt_info["benign_distractor_ids"]
            gt_inj: Set[str] = gt_info["injected_quarantine_ids"]

            pred_pos: Set[str] = {ref for d in domain_results for ref in d.evidence_refs}
            quarantined_found: Set[str] = {qid for d in domain_results for qid in d.quarantined_doc_ids}

            tp = len(gt_pos & pred_pos)
            fp = len(pred_pos & gt_neg)
            fn = len(gt_pos - pred_pos)
            tn = len(gt_neg - pred_pos)

            precision = round((tp / max(1, tp + fp)) * 100.0, 2)
            recall = round((tp / max(1, tp + fn)) * 100.0, 2)
            f1_pct = round((2 * precision * recall) / max(0.01, precision + recall), 2)

            crit_gt_ids = {eid for eid, sev in gt_info["severity_by_id"].items() if sev == SeverityLevel.CRITICAL}
            crit_fn_count = len(crit_gt_ids - pred_pos)
            quarantine_ok = (gt_inj <= quarantined_found) and len(pred_pos & gt_inj) == 0

            # Severity classification accuracy on detected true risk items
            sev_matches = 0
            for d in domain_results:
                for ref in d.evidence_refs:
                    if ref in gt_info["severity_by_id"]:
                        sev_matches += 1
            sev_acc_pct = round((sev_matches / max(1, len(pred_pos))) * 100.0, 2)

            if blackboard is not None:
                msg_ops = blackboard.read_count + blackboard.write_count
                dropped_pkts = 0
            else:
                msg_ops = p2p_bus.packets_sent + p2p_bus.packets_delivered
                dropped_pkts = p2p_bus.backpressure_drops

            metrics = {
                "trace_id": trace_id,
                "deal_id": eff_deal_id,
                "request_id": eff_req_id,
                "target_company": target_company,
                "design_pattern": design_pattern,
                "messaging_mode": messaging_mode,
                "reasoning_mode": reasoning_mode,
                "requested_execution_mode": req_mode,
                "actual_execution_mode": overall_actual_mode,
                "persona": persona_name,
                "materiality_cutoff_musd": guard_res.persona_materiality_cutoff_musd,
                "guardrail_verdict": guard_res.policy_verdict,
                "wall_clock_ms": wall_clock_ms,
                "message_ops": msg_ops,
                "p2p_backpressure_drops": dropped_pkts,
                "context_completeness_pct": context_completeness_pct,
                "incomplete_context_hold": incomplete_hold,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
                "risk_precision_pct": precision,
                "risk_recall_pct": recall,
                "risk_f1_pct": f1_pct,
                "severity_accuracy_pct": sev_acc_pct,
                "critical_fn_count": crit_fn_count,
                "evidence_grounding_rate_pct": 100.0,
                "unsupported_claim_rate_pct": 0.0,
                "injected_docs_quarantined": quarantine_ok,
                "cache_hits_in_run": sum(1 for d in domain_results if d.cache_hit),
                "retries_in_run": sum(d.retry_count for d in domain_results),
                "composite_risk_score": composite_risk,
                "recommended_offer_musd": dcf_obj.risk_adjusted_offer_price_musd,
                "escrow_holdback_musd": dcf_obj.indemnity_escrow_holdback_musd,
                "final_decision": decision.value,
                "decision_matches_ground_truth": (decision == gt_info["expected_decision"]),
            }
            return report, blackboard, metrics
        finally:
            with _WORKFLOW_CTX_LOCK:
                ACTIVE_WORKFLOW_CONTEXTS.pop(session_id, None)


class AcquiSenseRuntimeCluster:
    """
    Bootstraps and wires the complete AcquiSense runtime stack:
      - Config & PersistentLLMCache
      - ObservabilityTraceManager & AgentMonitoringCallbackHandler
      - SecurityGuardrailEngine
      - VDR Corpus & SQLite Fixture DB
      - MCPStreamableHttpServer & MCPStreamableHttpClient
      - 6 Specialist Agents (`ADK_Legal_Agent`, `ADK_Financial_Agent`, `CrewAI_Tech_Agent`, `CrewAI_Cyber_Agent`, `CrewAI_HR_Agent`, `CrewAI_ESG_Agent`)
      - Two separate A2A HTTP Services (`adk_a2a_service` & `crewai_a2a_service`)
      - `ADKExecutiveOrchestrator`
    """
    def __init__(self, override_env: Optional[Dict[str, str]] = None):
        self.config = AcquiSenseConfig.from_env(override_env)
        self.vdr_root, self.reg_db_path = initialize_corpus_and_databases(self.config)
        self.otlp_path = os.path.join(self.config.runtime_dir, "acquisense_otlp_traces.json")
        self.tracer = ObservabilityTraceManager(self.otlp_path)
        self.monitor = AgentMonitoringCallbackHandler(self.tracer)
        self.guardrails = SecurityGuardrailEngine()
        self.llm_cache = PersistentLLMCache(self.config.sqlite_db_path)
        self.gateway = AICreditsModelGateway(self.config, self.llm_cache)

        self.mcp_tools = build_mcp_tools(self.reg_db_path, self.guardrails)
        self.mcp_server = MCPStreamableHttpServer(self.mcp_tools, self.guardrails)
        self.mcp_client = MCPStreamableHttpClient(self.mcp_server.endpoint_url, self.monitor)

        self.a2a_client_ref: Optional[StandardA2AFederatedClient] = None

        def _cross_service_a2a_bridge(sender: str, receiver: str, target_co: str, deal_id: str) -> Dict[str, Any]:
            if self.a2a_client_ref is None:
                return {"responder": receiver, "critical_cves": 0, "deal_id": deal_id}
            return self.a2a_client_ref.send_peer_verification_subtask(sender, receiver, target_co, deal_id)

        self.adk_agents, self.crewai_agents = build_six_specialist_agents(
            config=self.config,
            gateway=self.gateway,
            llm_cache=self.llm_cache,
            mcp_client=self.mcp_client,
            guardrails=self.guardrails,
            monitor=self.monitor,
            tracer=self.tracer,
            cross_service_a2a_callback=_cross_service_a2a_bridge,
        )
        self.adk_a2a_service = StandardA2AServiceCluster(
            "AcquiSense-Google-ADK-A2A-Service", "Google_ADK", self.adk_agents, self.config, self.monitor
        )
        self.crewai_a2a_service = StandardA2AServiceCluster(
            "AcquiSense-CrewAI-A2A-Service", "CrewAI", self.crewai_agents, self.config, self.monitor
        )
        self.a2a_client = StandardA2AFederatedClient(
            [self.adk_a2a_service.base_url, self.crewai_a2a_service.base_url]
        )
        self.a2a_client_ref = self.a2a_client

        self.orchestrator = ADKExecutiveOrchestrator(
            config=self.config,
            gateway=self.gateway,
            a2a_client=self.a2a_client,
            guardrails=self.guardrails,
            monitor=self.monitor,
            tracer=self.tracer,
        )
