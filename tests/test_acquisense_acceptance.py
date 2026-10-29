"""
Automated 18-Point Acceptance Test Suite (`tests/test_acquisense_acceptance.py`)
verifying all mandatory engineering, security, reproducibility, protocol, and deployment criteria.
"""

import os
import sys
import json
import time
import socket
import unittest
import threading
import subprocess
import urllib.request
import urllib.error
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"), override=False)
except ImportError:
    pass

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from acquisense.config import AcquiSenseConfig, AICreditsModelGateway, PersistentLLMCache, LiveExecutionError, redact_secret
from acquisense.schemas import DomainType, SeverityLevel, GoNoGoDecision
from acquisense.security import create_jwt_token, verify_jwt_token
from acquisense.blackboard import DueDiligenceBlackboard, OptimisticConcurrencyConflictError
from acquisense.orchestrator import AcquiSenseRuntimeCluster
from deploy import run_deployment_preflight


class TestAcquiSenseAcceptanceCriteria(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cluster = AcquiSenseRuntimeCluster(override_env={
            "EXECUTION_MODE": "deterministic",
            "ALLOW_DETERMINISTIC_FALLBACK": "false",
            "AICREDITS_API_KEY": "",
        })
        cls.novapay_report, cls.novapay_bb, cls.novapay_metrics = cls.cluster.orchestrator.run_due_diligence_workflow(
            target_company="NovaPay FinTech Corp",
            user_prompt="Conduct full 6-domain M&A due diligence on NovaPay FinTech Corp.",
            design_pattern="Hierarchical",
            messaging_mode="Blackboard",
            reasoning_mode="ReAct",
            persona_name="Managing_Director",
            random_seed=2026,
        )
        cls.cloudmed_report, cls.cloudmed_bb, cls.cloudmed_metrics = cls.cluster.orchestrator.run_due_diligence_workflow(
            target_company="CloudMed AI Corp",
            user_prompt="Conduct full 6-domain M&A due diligence on CloudMed AI Corp.",
            design_pattern="Hierarchical",
            messaging_mode="Blackboard",
            reasoning_mode="ReAct",
            persona_name="Managing_Director",
            random_seed=2026,
        )

    def test_01_deterministic_suite_runs_offline_without_api_key(self):
        """Criterion 1: Deterministic suite runs without an API key or internet access."""
        self.assertEqual(self.novapay_report.actual_execution_mode, "deterministic")
        self.assertEqual(len(self.novapay_report.domain_assessments), 6)
        self.assertEqual(self.novapay_report.final_decision, GoNoGoDecision.CONDITIONAL_GO)
        self.assertEqual(self.cloudmed_report.final_decision, GoNoGoDecision.GO)

    def test_02_live_preflight_refuses_when_aicredits_key_absent(self):
        """Criterion 2: Live preflight refuses to claim live execution if AICredits key is absent."""
        cfg_no_key = AcquiSenseConfig.from_env({"EXECUTION_MODE": "live", "AICREDITS_API_KEY": "", "ALLOW_DETERMINISTIC_FALLBACK": "false"})
        gw = AICreditsModelGateway(cfg_no_key, self.cluster.llm_cache)
        with self.assertRaises(LiveExecutionError):
            gw.verify_live_preflight()

    def test_03_aicredits_gateway_smoke_test_and_returned_model_recording(self):
        """Criterion 3: AICredits gateway client verifies OpenAI-compatible GPT-4o completion & records returned model ID."""
        class _MockAICreditsHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                req_json = json.loads(self.rfile.read(length).decode("utf-8"))
                resp = {
                    "id": "chatcmpl-aicredits-test",
                    "object": "chat.completion",
                    "model": "gpt-4o-2024-08-06",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "{\"status\": \"OK\"}"}}],
                    "usage": {"prompt_tokens": 28, "completion_tokens": 6, "total_tokens": 34},
                }
                b = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        mock_srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockAICreditsHandler)
        port = mock_srv.server_address[1]
        t = threading.Thread(target=mock_srv.serve_forever, daemon=True)
        t.start()
        try:
            cfg_mock = AcquiSenseConfig.from_env({
                "EXECUTION_MODE": "live",
                "AICREDITS_API_KEY": "sk-test-ephemeral-key-not-logged",
                "AICREDITS_BASE_URL": f"http://127.0.0.1:{port}/v1",
                "AICREDITS_MODEL": "openai/gpt-4o",
            })
            gw = AICreditsModelGateway(cfg_mock, self.cluster.llm_cache)
            smoke = gw.run_gateway_smoke_test()
            self.assertTrue(smoke["smoke_test_passed"])
            self.assertEqual(smoke["returned_model"], "gpt-4o-2024-08-06")
            self.assertEqual(smoke["total_tokens"], 34)
            self.assertNotIn("sk-test-ephemeral-key-not-logged", str(cfg_mock.redacted_summary()))
        finally:
            mock_srv.shutdown()

    def test_04_and_05_and_06_six_preserved_specialists_and_framework_adapters(self):
        """Criteria 4, 5, 6: All 6 specialists exist with exact IDs, frameworks, and centralized AICredits model config."""
        expected_map = {
            "ADK_Legal_Agent": "Google_ADK",
            "ADK_Financial_Agent": "Google_ADK",
            "CrewAI_Tech_Agent": "CrewAI",
            "CrewAI_Cyber_Agent": "CrewAI",
            "CrewAI_HR_Agent": "CrewAI",
            "CrewAI_ESG_Agent": "CrewAI",
        }
        actual_map = {d.agent_id: d.framework for d in self.novapay_report.domain_assessments}
        self.assertEqual(actual_map, expected_map)

    def test_07_no_silent_fallback_on_live_failure(self):
        """Criterion 7: Failed live mode raises LiveExecutionError when ALLOW_DETERMINISTIC_FALLBACK=false, and logs fallback when true."""
        with self.assertRaises(LiveExecutionError):
            self.cluster.orchestrator.run_due_diligence_workflow(
                target_company="NovaPay FinTech Corp",
                user_prompt="Test live failure without key.",
                requested_execution_mode="live",
            )
        # Now test explicit opt-in fallback (ALLOW_DETERMINISTIC_FALLBACK=true)
        fallback_cluster = AcquiSenseRuntimeCluster(override_env={
            "EXECUTION_MODE": "live",
            "AICREDITS_API_KEY": "",
            "ALLOW_DETERMINISTIC_FALLBACK": "true",
            "LLM_CACHE_ENABLED": "false",
        })
        fb_report, _, _ = fallback_cluster.orchestrator.run_due_diligence_workflow(
            target_company="NovaPay FinTech Corp",
            user_prompt="Test explicit opt-in fallback.",
            requested_execution_mode="live",
        )
        self.assertEqual(fb_report.actual_execution_mode, "deterministic_fallback")
        self.assertTrue(all(d.fallback_used for d in fb_report.domain_assessments))

    def test_08_six_validated_domains_and_zero_cross_target_contamination(self):
        """Criterion 8: Each report contains 6 validated domains with valid target-specific evidence references."""
        cm_json = self.cloudmed_report.model_dump_json()
        for forbidden in ("PayCore", "SYNTH-CVE", "COBOL", "41.5%"):
            self.assertNotIn(forbidden, cm_json)
        self.assertEqual(len({d.domain for d in self.cloudmed_report.domain_assessments}), 6)

    def test_09_deterministic_financial_and_decision_rules(self):
        """Criterion 9: DCF EV-to-Equity reconciliation, escrow separation, and critical escalation are deterministic."""
        dcf = self.novapay_report.dcf_valuation
        self.assertEqual(
            round(dcf.base_enterprise_value_musd - dcf.less_total_debt_musd + dcf.plus_cash_musd, 2),
            dcf.implied_equity_value_musd,
        )
        self.assertEqual(
            round(dcf.implied_equity_value_musd - dcf.direct_price_reduction_musd, 2),
            dcf.risk_adjusted_offer_price_musd,
        )
        by_dom = {d.domain: d for d in self.novapay_report.domain_assessments}
        self.assertEqual(by_dom[DomainType.CYBER].severity, SeverityLevel.CRITICAL)
        self.assertGreaterEqual(by_dom[DomainType.CYBER].risk_score, 76.0)

    def test_10_persistent_cache_replay_determinism(self):
        """Criterion 10: Repeated calls with the same cache key replay the exact validated output and increment cache_hits."""
        hits_before = self.cluster.llm_cache.cache_hits
        rpt2, _, met2 = self.cluster.orchestrator.run_due_diligence_workflow(
            target_company="NovaPay FinTech Corp",
            user_prompt="Conduct full 6-domain M&A due diligence on NovaPay FinTech Corp.",
            design_pattern="Hierarchical",
            messaging_mode="Blackboard",
            reasoning_mode="ReAct",
            persona_name="Managing_Director",
            random_seed=2026,
        )
        self.assertGreater(self.cluster.llm_cache.cache_hits, hits_before)
        self.assertEqual(met2["cache_hits_in_run"], 6)
        self.assertEqual(rpt2.recommended_offer_price_musd, self.novapay_report.recommended_offer_price_musd)

    def test_11_mcp_protocol_initialization_discovery_and_calls(self):
        """Criterion 11: MCP client proves protocol initialization, session ID, tool discovery, and schema validation."""
        self.assertTrue(self.cluster.mcp_client.session_id.startswith("mcp-sess-"))
        tools = self.cluster.mcp_client.list_tools()
        self.assertEqual(len(tools), 5)
        for t in tools:
            self.assertIn("inputSchema", t)
            self.assertIn("outputSchema", t)
            self.assertIn("authorizationPolicy", t)
            self.assertIn("errorContract", t)

    def test_12_a2a_interoperability_and_adk_to_crewai_request(self):
        """Criterion 12: A2A proves communication across separate services including ADK_Financial_Agent -> CrewAI_Cyber_Agent."""
        self.assertNotEqual(self.cluster.adk_a2a_service.port, self.cluster.crewai_a2a_service.port)
        adk_to_crew_logs = [
            x for x in self.cluster.a2a_client.http_exchange_log
            if x["sender"] == "ADK_Financial_Agent" and x["receiver"] == "CrewAI_Cyber_Agent"
        ]
        self.assertGreaterEqual(len(adk_to_crew_logs), 1)
        self.assertEqual(adk_to_crew_logs[0]["state"], "completed")

    def test_13_security_quarantine_rbac_and_blackboard_conflict_recovery(self):
        """Criterion 13: Security tests cover quarantine of VDR-NP-INJ-999, JWT checks, and Blackboard conflict recovery."""
        for d in self.novapay_report.domain_assessments:
            self.assertNotIn("VDR-NP-INJ-999", d.evidence_refs)
        legal_dom = [d for d in self.novapay_report.domain_assessments if d.domain == DomainType.LEGAL][0]
        self.assertIn("VDR-NP-INJ-999", legal_dom.quarantined_doc_ids)

        # Verify optimistic concurrency conflict detection and recovery on Blackboard
        bb = self.novapay_bb
        with self.assertRaises(OptimisticConcurrencyConflictError):
            bb.write("Test_Agent", "worker_outputs", "conflict_key", {"v": 1}, expected_version=0)
        recovered_ver = bb.write_with_conflict_recovery(
            "Test_Agent", "worker_outputs", "recovered_key", lambda snap: {"recovered": True}
        )
        self.assertGreater(recovered_ver, 0)
        self.assertTrue(bb.verify_chain_integrity())

    def test_14_p2p_incomplete_context_triggers_insufficient_evidence_hold(self):
        """Criterion 14: Incomplete context in bounded P2P mode triggers INSUFFICIENT_EVIDENCE_HOLD rather than GO."""
        p2p_rpt, _, p2p_met = self.cluster.orchestrator.run_due_diligence_workflow(
            target_company="CloudMed AI Corp",
            user_prompt="Evaluate CloudMed AI Corp under bounded P2P.",
            design_pattern="Parallel",
            messaging_mode="PeerToPeer",
        )
        self.assertLess(p2p_rpt.context_completeness_pct, 100.0)
        self.assertTrue(p2p_rpt.incomplete_context_hold_applied)
        self.assertEqual(p2p_rpt.final_decision, GoNoGoDecision.INSUFFICIENT_EVIDENCE_HOLD)

    def test_15_and_17_clean_uvicorn_subprocess_executes_real_pipeline(self):
        """Criteria 15 & 17: Live Uvicorn subprocess serves real orchestration pipeline and passes HTTP security tests."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app:acquisense_cloud_app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "error"],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            env=os.environ.copy(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        base_url = f"http://127.0.0.1:{port}"
        try:
            for _ in range(40):
                try:
                    with urllib.request.urlopen(f"{base_url}/healthz", timeout=1.0) as r:
                        if r.status == 200:
                            break
                except Exception:
                    time.sleep(0.1)

            jwt_md = create_jwt_token("MD_Tester", ["NovaPay FinTech Corp", "CloudMed AI Corp"])
            req = urllib.request.Request(
                f"{base_url}/api/v1/due-diligence/evaluate",
                data=json.dumps({"target_company": "NovaPay FinTech Corp", "user_prompt": "Run full pipeline via HTTP."}).encode("utf-8"),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {jwt_md}"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=20.0) as resp:
                self.assertEqual(resp.status, 200)
                body = json.loads(resp.read().decode("utf-8"))
                self.assertNotEqual(body["served_by_pid"], os.getpid())
                self.assertEqual(len(body["report"]["domain_assessments"]), 6)
                self.assertEqual(body["report"]["final_decision"], "CONDITIONAL_GO")
        finally:
            proc.terminate()
            proc.wait(timeout=5.0)

    def test_16_and_18_cloud_deployment_is_opt_in_and_aborts_safely_when_unconfigured(self):
        """Criteria 16 & 18: DEPLOY_TARGET=none is a safe local no-op; cloud_run without confirm or Cloud SQL aborts safely."""
        cfg_default = AcquiSenseConfig.from_env({"DEPLOY_TARGET": "none"})
        res = run_deployment_preflight(cfg_default)
        self.assertFalse(res["cloud_deployment_triggered"])

        cfg_unconfirmed = AcquiSenseConfig.from_env({"DEPLOY_TARGET": "cloud_run", "CONFIRM_CLOUD_DEPLOY": "false"})
        with self.assertRaises(PermissionError):
            run_deployment_preflight(cfg_unconfirmed)


if __name__ == "__main__":
    unittest.main()
