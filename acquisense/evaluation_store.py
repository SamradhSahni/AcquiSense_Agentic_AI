"""
Evaluation and Test Results Persistence Store (`acquisense/evaluation_store.py`)
AcquiSense Multi-Agent M&A Due Diligence Platform

Manages durable SQLite tables for:
  - `evaluation_runs`: Comprehensive multi-agent run ledger across all evaluation parameters.
  - `evaluation_domain_results`: 6-domain breakdown per run (ADK & CrewAI specialist agents).
"""

import os
import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


class EvaluationStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        parent_dir = os.path.dirname(os.path.abspath(self.db_path))
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS evaluation_runs (
                    run_id TEXT PRIMARY KEY,
                    timestamp_utc TEXT NOT NULL,
                    target_company TEXT NOT NULL,
                    acquirer_company TEXT NOT NULL,
                    design_pattern TEXT NOT NULL,
                    reasoning_mode TEXT NOT NULL,
                    messaging_mode TEXT NOT NULL,
                    persona TEXT NOT NULL,
                    requested_execution_mode TEXT NOT NULL,
                    actual_execution_mode TEXT NOT NULL,
                    final_decision TEXT NOT NULL,
                    decision_matches_ground_truth INTEGER NOT NULL,
                    composite_risk_score REAL NOT NULL,
                    heuristic_confidence_pct REAL NOT NULL,
                    context_completeness_pct REAL NOT NULL,
                    risk_precision_pct REAL NOT NULL,
                    risk_recall_pct REAL NOT NULL,
                    risk_f1_pct REAL NOT NULL,
                    severity_accuracy_pct REAL NOT NULL,
                    critical_fn_count INTEGER NOT NULL,
                    injected_docs_quarantined INTEGER NOT NULL,
                    asking_price_musd REAL NOT NULL,
                    base_enterprise_value_musd REAL NOT NULL,
                    implied_equity_value_musd REAL NOT NULL,
                    direct_price_reduction_musd REAL NOT NULL,
                    recommended_offer_musd REAL NOT NULL,
                    escrow_holdback_musd REAL NOT NULL,
                    wall_clock_ms REAL NOT NULL,
                    message_ops INTEGER NOT NULL,
                    cache_hits INTEGER NOT NULL,
                    retries_count INTEGER NOT NULL,
                    report_id TEXT NOT NULL,
                    trace_id TEXT NOT NULL,
                    deal_id TEXT NOT NULL,
                    notes TEXT
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS evaluation_domain_results (
                    result_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    severity TEXT NOT NULL,
                    quantified_exposure_musd REAL NOT NULL,
                    deterministic_adjustment_musd REAL NOT NULL,
                    contingent_escrow_exposure_musd REAL NOT NULL,
                    heuristic_confidence REAL NOT NULL,
                    actual_mode TEXT NOT NULL,
                    findings_count INTEGER NOT NULL,
                    covenants_count INTEGER NOT NULL,
                    evidence_refs_count INTEGER NOT NULL,
                    quarantined_count INTEGER NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES evaluation_runs(run_id) ON DELETE CASCADE
                );
            """)

            cur.execute("CREATE INDEX IF NOT EXISTS idx_eval_target ON evaluation_runs(target_company);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_eval_pattern ON evaluation_runs(design_pattern);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_eval_mode ON evaluation_runs(actual_execution_mode);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_eval_domain_run ON evaluation_domain_results(run_id);")
            conn.commit()

    def record_run(self, report: Any, metrics: Dict[str, Any], notes: str = "") -> str:
        """
        Atomically records an evaluation run along with all 6 domain results.
        """
        run_id = f"RUN-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{report.report_id[-6:]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO evaluation_runs (
                    run_id, timestamp_utc, target_company, acquirer_company,
                    design_pattern, reasoning_mode, messaging_mode, persona,
                    requested_execution_mode, actual_execution_mode,
                    final_decision, decision_matches_ground_truth,
                    composite_risk_score, heuristic_confidence_pct, context_completeness_pct,
                    risk_precision_pct, risk_recall_pct, risk_f1_pct, severity_accuracy_pct,
                    critical_fn_count, injected_docs_quarantined,
                    asking_price_musd, base_enterprise_value_musd, implied_equity_value_musd,
                    direct_price_reduction_musd, recommended_offer_musd, escrow_holdback_musd,
                    wall_clock_ms, message_ops, cache_hits, retries_count,
                    report_id, trace_id, deal_id, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                run_id,
                now_iso,
                report.target_company,
                report.acquirer_company,
                metrics.get("design_pattern", "Hierarchical"),
                metrics.get("reasoning_mode", "ReAct"),
                metrics.get("messaging_mode", "Blackboard"),
                metrics.get("persona", "Managing_Director"),
                metrics.get("requested_execution_mode", report.requested_execution_mode),
                report.actual_execution_mode,
                report.final_decision.value if hasattr(report.final_decision, "value") else str(report.final_decision),
                1 if metrics.get("decision_matches_ground_truth", True) else 0,
                round(float(report.composite_risk_score), 2),
                round(float(report.heuristic_overall_confidence * 100.0), 2),
                round(float(report.context_completeness_pct), 2),
                round(float(metrics.get("risk_precision_pct", 100.0)), 2),
                round(float(metrics.get("risk_recall_pct", 100.0)), 2),
                round(float(metrics.get("risk_f1_pct", 100.0)), 2),
                round(float(metrics.get("severity_accuracy_pct", 100.0)), 2),
                int(metrics.get("critical_fn_count", 0)),
                1 if metrics.get("injected_docs_quarantined", True) else 0,
                round(float(report.asking_price_musd), 2),
                round(float(report.base_enterprise_value_musd), 2),
                round(float(report.implied_equity_value_musd), 2),
                round(float(report.direct_price_reduction_musd), 2),
                round(float(report.recommended_offer_price_musd), 2),
                round(float(report.escrow_holdback_musd), 2),
                round(float(metrics.get("wall_clock_ms", 0.0)), 2),
                int(metrics.get("message_ops", 0)),
                int(metrics.get("cache_hits_in_run", 0)),
                int(metrics.get("retries_in_run", 0)),
                report.report_id,
                report.dcf_valuation.trace_id if hasattr(report, "dcf_valuation") and hasattr(report.dcf_valuation, "trace_id") else metrics.get("trace_id", ""),
                report.deal_id,
                notes,
            ))

            for d in report.domain_assessments:
                res_id = f"{run_id}-{d.agent_id}"
                domain_val = d.domain.value if hasattr(d.domain, "value") else str(d.domain)
                sev_val = d.severity.value if hasattr(d.severity, "value") else str(d.severity)
                cur.execute("""
                    INSERT OR REPLACE INTO evaluation_domain_results (
                        result_id, run_id, domain, agent_id, framework,
                        risk_score, severity, quantified_exposure_musd,
                        deterministic_adjustment_musd, contingent_escrow_exposure_musd,
                        heuristic_confidence, actual_mode, findings_count,
                        covenants_count, evidence_refs_count, quarantined_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    res_id,
                    run_id,
                    domain_val,
                    d.agent_id,
                    d.framework,
                    round(float(d.risk_score), 2),
                    sev_val,
                    round(float(d.quantified_exposure_musd), 2),
                    round(float(d.deterministic_adjustment_musd), 2),
                    round(float(d.contingent_escrow_exposure_musd), 2),
                    round(float(d.heuristic_confidence_score), 2),
                    d.actual_execution_mode,
                    len(d.key_findings or []),
                    len(d.mitigation_covenants or []),
                    len(d.evidence_refs or []),
                    len(d.quarantined_doc_ids or []),
                ))

            conn.commit()
        return run_id

    def get_total_runs_count(self) -> int:
        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM evaluation_runs")
            return cur.fetchone()[0]

    def list_runs(
        self,
        limit: int = 50,
        target_company: Optional[str] = None,
        design_pattern: Optional[str] = None,
        execution_mode: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM evaluation_runs WHERE 1=1"
        params: List[Any] = []
        if target_company:
            query += " AND target_company = ?"
            params.append(target_company)
        if design_pattern:
            query += " AND design_pattern = ?"
            params.append(design_pattern)
        if execution_mode:
            query += " AND actual_execution_mode = ?"
            params.append(execution_mode)
        query += " ORDER BY timestamp_utc DESC LIMIT ?"
        params.append(limit)

        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, tuple(params))
            return [dict(r) for r in cur.fetchall()]

    def get_run_details(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM evaluation_runs WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
            if not row:
                return None
            run_dict = dict(row)
            cur.execute("SELECT * FROM evaluation_domain_results WHERE run_id = ?", (run_id,))
            run_dict["domain_results"] = [dict(r) for r in cur.fetchall()]
            return run_dict

    def get_parameter_summary(self) -> Dict[str, Any]:
        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            total_runs = cur.execute("SELECT COUNT(*) FROM evaluation_runs").fetchone()[0]
            if total_runs == 0:
                return {"total_runs": 0}

            avg_f1 = cur.execute("SELECT AVG(risk_f1_pct) FROM evaluation_runs").fetchone()[0] or 0.0
            avg_time = cur.execute("SELECT AVG(wall_clock_ms) FROM evaluation_runs").fetchone()[0] or 0.0
            gt_accuracy = cur.execute("SELECT AVG(decision_matches_ground_truth) FROM evaluation_runs").fetchone()[0] or 0.0

            cur.execute("SELECT design_pattern, COUNT(*), AVG(risk_f1_pct), AVG(wall_clock_ms) FROM evaluation_runs GROUP BY design_pattern")
            by_pattern = [
                {"pattern": r[0], "count": r[1], "avg_f1": round(r[2], 2), "avg_time_ms": round(r[3], 2)}
                for r in cur.fetchall()
            ]

            cur.execute("SELECT target_company, COUNT(*), AVG(composite_risk_score), AVG(recommended_offer_musd) FROM evaluation_runs GROUP BY target_company")
            by_target = [
                {"target": r[0], "count": r[1], "avg_risk": round(r[2], 2), "avg_offer_musd": round(r[3], 2)}
                for r in cur.fetchall()
            ]

            cur.execute("SELECT actual_execution_mode, COUNT(*), AVG(wall_clock_ms) FROM evaluation_runs GROUP BY actual_execution_mode")
            by_mode = [
                {"mode": r[0], "count": r[1], "avg_time_ms": round(r[2], 2)}
                for r in cur.fetchall()
            ]

            cur.execute("SELECT final_decision, COUNT(*) FROM evaluation_runs GROUP BY final_decision")
            by_decision = {r[0]: r[1] for r in cur.fetchall()}

            return {
                "total_runs": total_runs,
                "avg_risk_f1_pct": round(avg_f1, 2),
                "avg_wall_clock_ms": round(avg_time, 2),
                "ground_truth_accuracy_pct": round(gt_accuracy * 100.0, 2),
                "by_pattern": by_pattern,
                "by_target": by_target,
                "by_mode": by_mode,
                "by_decision": by_decision,
            }

    def export_to_csv(self, runs_csv_path: str, domain_csv_path: str) -> Tuple[str, str]:
        import csv
        os.makedirs(os.path.dirname(os.path.abspath(runs_csv_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(domain_csv_path)), exist_ok=True)

        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM evaluation_runs ORDER BY timestamp_utc DESC")
            run_rows = cur.fetchall()
            if run_rows:
                keys = run_rows[0].keys()
                with open(runs_csv_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(keys)
                    for r in run_rows:
                        writer.writerow([r[k] for k in keys])

            cur.execute("SELECT * FROM evaluation_domain_results ORDER BY run_id, domain")
            dom_rows = cur.fetchall()
            if dom_rows:
                dom_keys = dom_rows[0].keys()
                with open(domain_csv_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(dom_keys)
                    for r in dom_rows:
                        writer.writerow([r[k] for k in dom_keys])

        return runs_csv_path, domain_csv_path
