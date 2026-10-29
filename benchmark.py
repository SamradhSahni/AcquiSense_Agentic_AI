#!/usr/bin/env python3
"""
Benchmark & Parameter Evaluation CLI (`benchmark.py`)
AcquiSense Multi-Agent M&A Due Diligence Platform

Measures, tracks, and inspects multi-agent performance across:
  - Evaluation Parameters: Target Companies, Orchestration Patterns, Reasoning Modes, Personas, Execution Modes
  - Evaluation Metrics: Clause-level Risk F1, Ground-Truth Accuracy, 6-Domain Exposure, Valuation Bridge, Wall-Clock Latency
  - Persistent Ledger: Stored in local SQLite database (acquisense_local.db)

Usage:
  python benchmark.py --summary
  python benchmark.py --list-runs
  python benchmark.py --show-run <run_id>
  python benchmark.py --run-matrix [--mode deterministic|live]
  python benchmark.py --export-csv [output_dir]
"""

import os
import sys
import argparse
import warnings
from datetime import datetime, timezone
from typing import Dict, List, Optional

warnings.filterwarnings("ignore", category=Warning)

try:
    from dotenv import load_dotenv
    load_dotenv(override=False)
except ImportError:
    pass

from acquisense.config import AcquiSenseConfig
from acquisense.evaluation_store import EvaluationStore
from acquisense.orchestrator import AcquiSenseRuntimeCluster
from acquisense.mcp_service import TARGET_PROFILES


def get_store() -> EvaluationStore:
    cfg = AcquiSenseConfig.from_env()
    return EvaluationStore(cfg.sqlite_db_path)


def print_summary(store: EvaluationStore):
    summary = store.get_parameter_summary()
    total = summary.get("total_runs", 0)

    print("\n" + "=" * 80)
    print("        AcquiSense Multi-Agent Evaluation & Benchmark Summary")
    print(f"        Persistent Database: {store.db_path}")
    print("=" * 80)
    print(f"[*] Total Evaluation Runs Executed : {total}")
    if total == 0:
        print("\nNo evaluation runs have been recorded yet.")
        print("Run 'python demo.py' or 'python benchmark.py --run-matrix' to generate evaluation data.\n")
        return

    print(f"[*] Average Risk F1 Score          : {summary.get('avg_risk_f1_pct', 0.0):.2f}%")
    print(f"[*] Ground-Truth Decision Accuracy : {summary.get('ground_truth_accuracy_pct', 0.0):.1f}%")
    print(f"[*] Average Wall Clock Time        : {summary.get('avg_wall_clock_ms', 0.0):.2f} ms")
    print("-" * 80)

    # By Target Company
    print("\n[+] Breakdown by Target Company:")
    print(f"    {'Target Company':<30} | {'Runs':<6} | {'Avg Risk Score':<15} | {'Avg Offer ($M)':<15}")
    print("    " + "-" * 72)
    for t in summary.get("by_target", []):
        print(f"    {t['target']:<30} | {t['count']:<6} | {t['avg_risk']:<15.2f} | ${t['avg_offer_musd']:<14.2f}")

    # By Orchestration Pattern
    print("\n[+] Breakdown by Orchestration Design Pattern:")
    print(f"    {'Orchestration Pattern':<25} | {'Runs':<6} | {'Avg F1 (%)':<12} | {'Avg Time (ms)':<15}")
    print("    " + "-" * 66)
    for p in summary.get("by_pattern", []):
        print(f"    {p['pattern']:<25} | {p['count']:<6} | {p['avg_f1']:<12.1f} | {p['avg_time_ms']:<15.2f}")

    # By Execution Mode
    print("\n[+] Breakdown by Actual Execution Mode:")
    print(f"    {'Execution Mode':<25} | {'Runs':<6} | {'Avg Time (ms)':<15}")
    print("    " + "-" * 52)
    for m in summary.get("by_mode", []):
        print(f"    {m['mode']:<25} | {m['count']:<6} | {m['avg_time_ms']:<15.2f}")

    # By Final Decision
    print("\n[+] Investment Committee Decision Distribution:")
    for dec, cnt in summary.get("by_decision", {}).items():
        pct = (cnt / total) * 100.0
        print(f"    • {dec:<30} : {cnt} run(s) ({pct:.1f}%)")
    print("=" * 80 + "\n")


def print_list_runs(store: EvaluationStore, limit: int = 50, target: Optional[str] = None):
    runs = store.list_runs(limit=limit, target_company=target)
    total = len(runs)
    print("\n" + "=" * 110)
    print(f"  AcquiSense Evaluation Runs Ledger (Showing {total} most recent runs)")
    print("=" * 110)
    if not runs:
        print("  No runs found. Execute 'python demo.py' or 'python benchmark.py --run-matrix' to generate runs.\n")
        return

    header = f"{'Run ID':<26} | {'Target Company':<22} | {'Pattern':<12} | {'Mode':<14} | {'Decision':<14} | {'F1 %':<6} | {'Time (s)':<8}"
    print(header)
    print("-" * 110)
    for r in runs:
        sec = r["wall_clock_ms"] / 1000.0
        time_str = f"{sec:.2f}s" if sec >= 1.0 else f"{r['wall_clock_ms']:.0f}ms"
        print(f"{r['run_id']:<26} | {r['target_company'][:22]:<22} | {r['design_pattern']:<12} | {r['actual_execution_mode'][:14]:<14} | {r['final_decision'][:14]:<14} | {r['risk_f1_pct']:<6.1f} | {time_str:<8}")
    print("=" * 110)
    print(f"Inspect any run in detail with: python benchmark.py --show-run <Run_ID>\n")


def print_run_details(store: EvaluationStore, run_id: str):
    run = store.get_run_details(run_id)
    if not run:
        print(f"\n[!] Error: Run '{run_id}' not found in SQLite store ({store.db_path}).\n")
        return

    print("\n" + "=" * 85)
    print(f"                    EVALUATION RUN DETAILS: {run['run_id']}")
    print("=" * 85)
    print(f"[*] Timestamp (UTC)       : {run['timestamp_utc']}")
    print(f"[*] Target Company        : {run['target_company']} (Acquirer: {run['acquirer_company']})")
    print(f"[*] Orchestration Pattern : {run['design_pattern']} | Persona: {run['persona']}")
    print(f"[*] Reasoning Mode        : {run['reasoning_mode']} | Messaging Mode: {run['messaging_mode']}")
    print(f"[*] Execution Mode        : Requested='{run['requested_execution_mode']}', Actual='{run['actual_execution_mode']}'")
    print(f"[*] Wall-Clock Duration   : {run['wall_clock_ms']:.2f} ms ({run['wall_clock_ms']/1000.0:.2f} s)")
    print(f"[*] Blackboard Operations : {run['message_ops']} read/writes (Cache hits: {run['cache_hits']})")
    print("-" * 85)
    print(f"[*] Committee Decision    : {run['final_decision']} (Matches Ground Truth: {'YES' if run['decision_matches_ground_truth'] else 'NO'})")
    print(f"[*] Composite Risk Score  : {run['composite_risk_score']:.2f} / 100.0 (Confidence: {run['heuristic_confidence_pct']:.1f}%)")
    print(f"[*] Risk Clause Detection : F1={run['risk_f1_pct']:.1f}% (Precision={run['risk_precision_pct']:.1f}%, Recall={run['risk_recall_pct']:.1f}%)")
    print(f"[*] Severity Accuracy     : {run['severity_accuracy_pct']:.1f}% (Critical False Negatives: {run['critical_fn_count']})")
    print(f"[*] Injected Docs Quarantined: {'YES' if run['injected_docs_quarantined'] else 'NO'}")
    print("-" * 85)
    print("                         FINANCIAL VALUATION BRIDGE")
    print(f"    Seller Asking Price        : ${run['asking_price_musd']:.2f}M USD")
    print(f"    Base Enterprise Value (DCF): ${run['base_enterprise_value_musd']:.2f}M USD")
    print(f"    Implied Equity Value       : ${run['implied_equity_value_musd']:.2f}M USD")
    print(f"    Direct Price Reduction     : -${run['direct_price_reduction_musd']:.2f}M USD")
    print(f"    RECOMMENDED OFFER PRICE    : ${run['recommended_offer_musd']:.2f}M USD")
    print(f"    Indemnity Escrow Holdback  : ${run['escrow_holdback_musd']:.2f}M USD")
    print("=" * 85)

    print("\n[+] 6-Domain Specialist Agent Breakdown:")
    dom_results = run.get("domain_results", [])
    if dom_results:
        print(f"    {'Domain':<28} | {'Specialist Agent':<20} | {'Score':<6} | {'Severity':<10} | {'Exposure ($M)':<12} | {'Findings'}")
        print("    " + "-" * 88)
        for d in dom_results:
            print(f"    {d['domain']:<28} | {d['agent_id']:<20} | {d['risk_score']:<6.1f} | {d['severity']:<10} | ${d['quantified_exposure_musd']:<11.2f} | {d['findings_count']} finding(s)")
    print("\n" + "=" * 85 + "\n")


def run_benchmark_matrix(mode: str = "deterministic"):
    print("\n" + "=" * 85)
    print(f"    Executing Multi-Parameter Evaluation Matrix (Mode: {mode})")
    print("    Evaluating across Targets, Orchestration Patterns, and Reasoning Modes")
    print("=" * 85)

    targets = list(TARGET_PROFILES.keys())
    patterns = ["Hierarchical", "Parallel", "Sequential"]
    reasoning_modes = ["ReAct", "Direct"]

    cluster = AcquiSenseRuntimeCluster(override_env={"EXECUTION_MODE": mode})
    store = cluster.eval_store

    total_combinations = len(targets) * len(patterns)
    current = 0

    results = []
    for target in targets:
        for pattern in patterns:
            current += 1
            print(f"[*] [{current}/{total_combinations}] Evaluating: Target='{target}', Pattern='{pattern}'...", end=" ", flush=True)
            t0 = datetime.now()
            report, blackboard, metrics = cluster.orchestrator.run_due_diligence_workflow(
                target_company=target,
                user_prompt=f"Perform parameter evaluation benchmark on {target}.",
                design_pattern=pattern,
                messaging_mode="Blackboard",
                reasoning_mode="ReAct",
                persona_name="Managing_Director",
                random_seed=2026,
                requested_execution_mode=mode,
            )
            run_id = metrics.get("evaluation_run_id", "N/A")
            sec = metrics.get("wall_clock_ms", 0) / 1000.0
            print(f"DONE in {sec:.2f}s -> Decision: {report.final_decision.value}, F1: {metrics.get('risk_f1_pct'):.1f}%, Run: {run_id}")
            results.append({
                "run_id": run_id,
                "target": target,
                "pattern": pattern,
                "decision": report.final_decision.value,
                "f1": metrics.get("risk_f1_pct"),
                "time_ms": metrics.get("wall_clock_ms"),
                "offer_musd": report.recommended_offer_price_musd,
                "escrow_musd": report.escrow_holdback_musd,
            })

    print("\n" + "=" * 85)
    print("                    BENCHMARK MATRIX RESULTS SUMMARY")
    print("=" * 85)
    print(f"{'Target Company':<24} | {'Pattern':<14} | {'Decision':<16} | {'F1 (%)':<8} | {'Offer ($M)':<11} | {'Time (s)'}")
    print("-" * 85)
    for r in results:
        print(f"{r['target'][:24]:<24} | {r['pattern']:<14} | {r['decision'][:16]:<16} | {r['f1']:<8.1f} | ${r['offer_musd']:<10.2f} | {r['time_ms']/1000.0:.2f}s")
    print("=" * 85)
    print(f"[+] All {len(results)} runs permanently stored in SQLite database ({store.db_path}).\n")


def export_csv(store: EvaluationStore, output_dir: str = "reports"):
    runs_path = os.path.join(output_dir, "evaluation_runs.csv")
    dom_path = os.path.join(output_dir, "evaluation_domain_results.csv")
    r_path, d_path = store.export_to_csv(runs_path, dom_path)
    print(f"\n[+] Successfully exported evaluation datasets:")
    print(f"    • Runs Ledger:    {os.path.abspath(r_path)}")
    print(f"    • Domain Results: {os.path.abspath(d_path)}\n")


def main():
    parser = argparse.ArgumentParser(description="AcquiSense Multi-Agent Benchmark & Parameter Evaluation CLI")
    parser.add_argument("--summary", action="store_true", help="Print overall evaluation and parameter summary")
    parser.add_argument("--list-runs", action="store_true", help="List all recorded evaluation runs")
    parser.add_argument("--limit", type=int, default=50, help="Maximum runs to display in --list-runs (default: 50)")
    parser.add_argument("--target", default=None, help="Filter runs by target company")
    parser.add_argument("--show-run", default=None, help="Show full domain and parameter details for a specific Run ID")
    parser.add_argument("--run-matrix", action="store_true", help="Execute multi-parameter benchmark matrix")
    parser.add_argument("--mode", choices=["deterministic", "live"], default="deterministic", help="Execution mode for benchmark matrix (default: deterministic)")
    parser.add_argument("--export-csv", default=None, nargs="?", const="reports", help="Export runs and domain metrics to CSV files (default dir: reports)")

    args = parser.parse_args()
    store = get_store()

    if args.summary:
        print_summary(store)
    elif args.list_runs:
        print_list_runs(store, limit=args.limit, target=args.target)
    elif args.show_run:
        print_run_details(store, args.show_run)
    elif args.run_matrix:
        run_benchmark_matrix(mode=args.mode)
    elif args.export_csv:
        export_csv(store, output_dir=args.export_csv)
    else:
        # Default action: display summary
        print_summary(store)


if __name__ == "__main__":
    main()

