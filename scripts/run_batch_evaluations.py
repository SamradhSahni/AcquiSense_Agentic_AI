"""
Batch Evaluation Runner (`scripts/run_batch_evaluations.py`)
AcquiSense Multi-Agent M&A Due Diligence Platform

Executes 25+ diverse multi-parameter due diligence runs across:
  - Target Companies: NovaPay FinTech Corp, CloudMed AI Corp
  - Orchestration Patterns: Hierarchical, Parallel, Sequential
  - Reasoning Modes: ReAct, Direct
  - Personas: Managing_Director, Risk_Auditor, Tech_Lead, Investment_Associate
  - Communication Modes: Blackboard, PeerToPeer
  - Random Seeds: 2024, 2025, 2026, 2027
All results are automatically persisted to the local SQLite evaluation ledger.
"""

import os
import sys
import time
import warnings
from datetime import datetime, timezone

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"), override=False)
except ImportError:
    pass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
warnings.filterwarnings("ignore", category=Warning)

from acquisense.config import AcquiSenseConfig
from acquisense.orchestrator import AcquiSenseRuntimeCluster
from acquisense.evaluation_store import EvaluationStore
from acquisense.mcp_service import TARGET_PROFILES


def main():
    print("=" * 80)
    print("  AcquiSense Multi-Agent Batch Parameter Evaluation Suite (30+ Runs Target)")
    print("=" * 80)

    cluster = AcquiSenseRuntimeCluster(override_env={"EXECUTION_MODE": "deterministic"})
    store = cluster.eval_store

    initial_runs = store.get_total_runs_count()
    print(f"[*] Initial runs in SQLite ledger: {initial_runs}")

    targets = list(TARGET_PROFILES.keys())
    patterns = ["Hierarchical", "Parallel", "Sequential"]
    reasoning_modes = ["ReAct", "Direct"]
    personas = ["Managing_Director", "Risk_Auditor", "Investment_Associate", "Tech_Lead"]
    messaging_modes = ["Blackboard", "PeerToPeer"]
    seeds = [2024, 2025, 2026, 2027]

    # Generate a balanced set of 28 test permutations
    permutations = []
    seed_idx = 0
    for target in targets:
        for pattern in patterns:
            for r_mode in reasoning_modes:
                for persona in [personas[0], personas[1]]:
                    msg_mode = "Blackboard" if pattern != "Parallel" else "PeerToPeer"
                    seed = seeds[seed_idx % len(seeds)]
                    seed_idx += 1
                    permutations.append({
                        "target": target,
                        "pattern": pattern,
                        "reasoning": r_mode,
                        "persona": persona,
                        "messaging": msg_mode,
                        "seed": seed,
                    })

    # Add 4 additional targeted variations (Tech_Lead & Investment_Associate)
    for p in [personas[2], personas[3]]:
        for target in targets:
            permutations.append({
                "target": target,
                "pattern": "Hierarchical",
                "reasoning": "ReAct",
                "persona": p,
                "messaging": "Blackboard",
                "seed": 2026,
            })

    total_to_run = len(permutations)
    print(f"[*] Executing {total_to_run} automated evaluation permutations...")
    print("-" * 80)

    t_start = time.perf_counter()
    completed = 0
    for idx, p in enumerate(permutations, 1):
        target = p["target"]
        pattern = p["pattern"]
        r_mode = p["reasoning"]
        persona = p["persona"]
        msg_mode = p["messaging"]
        seed = p["seed"]

        print(f"[{idx:02d}/{total_to_run}] Target='{target[:16]}', Pattern='{pattern[:12]}', Reasoning='{r_mode}', Persona='{persona[:14]}', Msg='{msg_mode}'...", end=" ", flush=True)

        report, blackboard, metrics = cluster.orchestrator.run_due_diligence_workflow(
            target_company=target,
            user_prompt=f"Comprehensive {r_mode} M&A audit for {target} by {persona}.",
            design_pattern=pattern,
            messaging_mode=msg_mode,
            reasoning_mode=r_mode,
            persona_name=persona,
            random_seed=seed,
            requested_execution_mode="deterministic",
        )

        completed += 1
        sec = metrics.get("wall_clock_ms", 0.0) / 1000.0
        f1 = metrics.get("risk_f1_pct", 0.0)
        run_id = metrics.get("evaluation_run_id", "N/A")
        print(f"DONE in {sec:.2f}s -> Decision: {report.final_decision.value}, Offer: ${report.recommended_offer_price_musd:.2f}M, Run: {run_id}")

    t_end = time.perf_counter()
    total_in_store = store.get_total_runs_count()

    print("=" * 80)
    print(f"[+] Successfully executed {completed} parameter runs in {t_end - t_start:.2f} seconds!")
    print(f"[+] Master SQLite Ledger now contains: {total_in_store} evaluation runs.")
    print("=" * 80)

    # Re-export CSVs
    store.export_to_csv("reports/evaluation_runs.csv", "reports/evaluation_domain_results.csv")
    print("[+] Updated reports/evaluation_runs.csv and reports/evaluation_domain_results.csv")


if __name__ == "__main__":
    main()
