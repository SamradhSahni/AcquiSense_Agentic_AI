#!/usr/bin/env python3
"""
Interactive Demonstration & Executive Report Generator (`demo.py`)
AcquiSense Multi-Agent M&A Due Diligence Platform

Demonstrates:
  - 6 Specialist Agents (Google ADK & CrewAI)
  - 3 Orchestration Patterns (Hierarchical, Parallel, Sequential)
  - Deterministic & Live GPT-4o Execution Modes
  - DCF Valuation & Price Haircut vs. Escrow Bridge
  - Durable Blackboard State & A2A Communication
"""

import os
import sys
import argparse
from datetime import datetime, timezone

try:
    from dotenv import load_dotenv
    load_dotenv(override=False)
except ImportError:
    pass

from acquisense.mcp_service import TARGET_PROFILES
from acquisense.orchestrator import AcquiSenseRuntimeCluster
from acquisense.schemas import SeverityLevel, GoNoGoDecision


def print_banner():
    banner = """
================================================================================
           AcquiSense — Multi-Agent M&A Due Diligence Platform
    Google ADK + CrewAI + GPT-4o + MCP Tools + A2A HTTP + Durable Blackboard
================================================================================
"""
    print(banner)


def run_demo(target_company: str, pattern: str = "Hierarchical", mode: str = "deterministic", export_path: str = None):
    print_banner()
    print(f"[*] Target Company       : {target_company}")
    print(f"[*] Orchestration Pattern: {pattern}")
    print(f"[*] Requested Mode       : {mode}")
    print(f"[*] Initializing Multi-Agent Runtime Cluster...\n")

    override_env = {}
    if mode:
        override_env["EXECUTION_MODE"] = mode

    cluster = AcquiSenseRuntimeCluster(override_env=override_env)

    print("[*] Launching 6 Specialist Agents:")
    print("    • [Google ADK] ADK_Legal_Agent          (Auditing litigation & IP dockets)")
    print("    • [Google ADK] ADK_Financial_Agent      (5-yr DCF, valuation bridge & A2A cross-check)")
    print("    • [CrewAI]     CrewAI_Tech_Agent        (Cloud/monolith stack & refactoring capex)")
    print("    • [CrewAI]     CrewAI_Cyber_Agent       (SBOM vulnerabilities & CVE matching)")
    print("    • [CrewAI]     CrewAI_HR_Agent          (Engineering attrition & retention lockups)")
    print("    • [CrewAI]     CrewAI_ESG_Agent         (Scope-2 emissions & board independence)")
    print()

    print("[*] Executing due diligence workflow... Please wait...")
    report, blackboard, metrics = cluster.orchestrator.run_due_diligence_workflow(
        target_company=target_company,
        user_prompt=f"Perform complete 6-domain M&A due diligence evaluation on {target_company}.",
        design_pattern=pattern,
        messaging_mode="Blackboard",
        reasoning_mode="ReAct",
        persona_name="Managing_Director",
        random_seed=2026,
        requested_execution_mode=mode,
    )
    print("[+] Workflow completed successfully!\n")

    # Display Decision & Valuation Bridge
    decision_color = {
        GoNoGoDecision.GO: "APPROVED (GO)",
        GoNoGoDecision.CONDITIONAL_GO: "CONDITIONAL GO (Subject to Escrow & Covenants)",
        GoNoGoDecision.NO_GO: "REJECTED (NO GO)",
        GoNoGoDecision.INSUFFICIENT_EVIDENCE_HOLD: "ON HOLD (Insufficient Evidence)",
    }.get(report.final_decision, report.final_decision.value)

    print("=" * 80)
    print("                        EXECUTIVE INVESTMENT COMMITTEE SUMMARY")
    print("=" * 80)
    print(f"  Final Decision            : {decision_color}")
    print(f"  Acquirer                  : {report.acquirer_company}")
    print(f"  Composite Risk Score      : {report.composite_risk_score:.2f} / 100.0")
    print(f"  Confidence Level          : {report.heuristic_overall_confidence * 100.0:.1f}%")
    print(f"  Context Completeness      : {report.context_completeness_pct:.1f}%")
    print("-" * 80)
    print("                             FINANCIAL VALUATION BRIDGE")
    print("-" * 80)
    print(f"  Seller Asking Price       : ${report.asking_price_musd:10.2f}M USD")
    print(f"  DCF Base Enterprise Value : ${report.base_enterprise_value_musd:10.2f}M USD (5-yr FCFF, WACC {report.dcf_valuation.wacc_pct:.1f}%)")
    print(f"  Implied Equity Value      : ${report.implied_equity_value_musd:10.2f}M USD (Adjusted for cash/debt)")
    print(f"  Direct Price Reduction    : -${report.direct_price_reduction_musd:9.2f}M USD (Off-balance-sheet & pre-close liabilities)")
    print(f"  -------------------------------------------------------------")
    print(f"  RECOMMENDED OFFER PRICE   : ${report.recommended_offer_price_musd:10.2f}M USD (Net Price Adjustment: -{((report.asking_price_musd - report.recommended_offer_price_musd)/report.asking_price_musd)*100.0:.1f}%)")
    print(f"  INDEMNITY ESCROW HOLDBACK : ${report.escrow_holdback_musd:10.2f}M USD (Dedicated contingent liability escrow)")
    print("=" * 80)

    # Domain breakdown table
    print("\n" + "=" * 80)
    print("                       6-DOMAIN RISK ASSESSMENT BREAKDOWN")
    print("=" * 80)
    print(f"{'Domain':<24} | {'Specialist Agent':<20} | {'Framework':<11} | {'Score':<5} | {'Severity':<9} | {'Exposure'}")
    print("-" * 80)
    for d in report.domain_assessments:
        exposure = f"${d.quantified_exposure_musd:.2f}M" if d.quantified_exposure_musd > 0 else "$0.00M"
        print(f"{d.domain.value:<24} | {d.agent_id:<20} | {d.framework:<11} | {d.risk_score:5.1f} | {d.severity.value:<9} | {exposure}")
    print("=" * 80)

    # Executive Rationale & Closing Conditions
    print("\n[*] Executive Rationale:")
    print(f"    {report.executive_rationale}\n")

    if report.mandatory_closing_conditions:
        print("[*] Mandatory Closing Conditions & Covenants:")
        for idx, cond in enumerate(report.mandatory_closing_conditions, 1):
            print(f"    {idx}. {cond}")
        print()

    # Metrics
    wall_ms = metrics.get('wall_clock_ms', 0)
    print("[*] Execution & Runtime Metrics:")
    print(f"    • Actual Execution Mode : {report.actual_execution_mode}")
    print(f"    • Total Wall Clock Time : {wall_ms:.2f} ms ({wall_ms/1000.0:.2f} seconds)")
    print(f"    • Messaging Operations  : {metrics.get('message_ops', 0)} blackboard read/writes")
    print(f"    • Cache Hits in Run     : {metrics.get('cache_hits_in_run', 0)} hit(s)")
    print(f"    • In-Fold ML F1 Score   : {metrics.get('risk_f1_pct', 0):.1f}%")

    # Export report if requested
    if not export_path:
        reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        slug = TARGET_PROFILES[target_company]["slug"]
        export_path = os.path.join(reports_dir, f"diligence_report_{slug}.md")

    generate_markdown_report(report, metrics, export_path)
    print(f"\n[+] Full Markdown Diligence Report exported to:\n    {export_path}\n")


def generate_markdown_report(report, metrics, filepath: str):
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"# AcquiSense M&A Due Diligence Executive Report: {report.target_company}\n\n")
        f.write(f"**Date Generated (UTC)**: `{report.timestamp_utc}`  \n")
        f.write(f"**Acquiring Entity**: `{report.acquirer_company}`  \n")
        f.write(f"**Evaluation Mode**: `{report.actual_execution_mode}`  \n")
        f.write(f"**Final Committee Decision**: **{report.final_decision.value}**  \n\n")

        f.write("## 1. Executive Summary & Valuation Bridge\n\n")
        f.write("| Metric | Value |\n")
        f.write("| :--- | :--- |\n")
        f.write(f"| **Seller Asking Price** | **${report.asking_price_musd:.2f}M USD** |\n")
        f.write(f"| **Base Enterprise Value (DCF)** | ${report.base_enterprise_value_musd:.2f}M USD |\n")
        f.write(f"| **Implied Equity Value** | ${report.implied_equity_value_musd:.2f}M USD |\n")
        f.write(f"| **Direct Purchase Price Deduction** | -${report.direct_price_reduction_musd:.2f}M USD |\n")
        f.write(f"| **Recommended Offer Price** | **${report.recommended_offer_price_musd:.2f}M USD** |\n")
        f.write(f"| **Dedicated Indemnity Escrow Pool** | **${report.escrow_holdback_musd:.2f}M USD** |\n")
        f.write(f"| **Composite Target Risk Score** | {report.composite_risk_score:.2f} / 100.0 |\n")
        f.write(f"| **Overall Confidence** | {report.heuristic_overall_confidence * 100.0:.1f}% |\n\n")

        f.write(f"### Investment Committee Rationale\n\n>{report.executive_rationale}\n\n")

        f.write("## 2. Six-Domain Specialist Risk Breakdown\n\n")
        f.write("| Domain | Specialist Agent | Framework | Risk Score | Severity | Exposure (M USD) |\n")
        f.write("| :--- | :--- | :--- | :---: | :---: | :---: |\n")
        for d in report.domain_assessments:
            exp = f"${d.quantified_exposure_musd:.2f}M" if d.quantified_exposure_musd > 0 else "$0.00M"
            f.write(f"| {d.domain.value} | `{d.agent_id}` | {d.framework} | {d.risk_score:.1f} | `{d.severity.value}` | {exp} |\n")
        f.write("\n")

        f.write("## 3. Extracted Material Findings & Mitigations\n\n")
        for d in report.domain_assessments:
            f.write(f"### {d.domain.value} ({d.agent_id} - {d.framework})\n")
            f.write(f"- **Domain Severity**: `{d.severity.value}` (Risk Score: {d.risk_score:.1f}/100)\n")
            f.write(f"- **Total Quantified Exposure**: `${d.quantified_exposure_musd:.2f}M` (Direct Haircut: `${d.deterministic_adjustment_musd:.2f}M`, Escrow Liability: `${d.contingent_escrow_exposure_musd:.2f}M`)\n")
            f.write(f"- **Worker Verification**: {d.worker_verification_summary}\n")
            if d.key_findings:
                f.write(f"- **Key Findings**:\n")
                for kf in d.key_findings:
                    f.write(f"  - {kf}\n")
            if d.mitigation_covenants:
                f.write(f"- **Recommended Mitigation Covenants**:\n")
                for cov in d.mitigation_covenants:
                    f.write(f"  - {cov}\n")
            if d.evidence_refs:
                f.write(f"- **VDR Evidence Citations**: `{', '.join(d.evidence_refs)}`\n")
            f.write("\n")

        if report.mandatory_closing_conditions:
            f.write("## 4. Mandatory Closing Conditions & Covenants\n\n")
            for idx, c in enumerate(report.mandatory_closing_conditions, 1):
                f.write(f"{idx}. {c}\n")
            f.write("\n")

        f.write("## 5. Multi-Agent System Execution Metrics\n\n")
        f.write(f"- **Workflow Wall Clock Duration**: `{metrics.get('workflow_wall_time_ms', 0):.2f} ms`\n")
        f.write(f"- **A2A HTTP Protocol Exchanges**: `{metrics.get('http_a2a_exchanges_count', 0)}`\n")
        f.write(f"- **LLM Cache Hits**: `{metrics.get('llm_cache_hits', 0)}`\n")
        f.write(f"- **LLM Cache Misses**: `{metrics.get('llm_cache_misses', 0)}`\n")
        f.write(f"- **Blackboard Commits**: `{metrics.get('blackboard_commits_count', 0)}`\n")


def main():
    parser = argparse.ArgumentParser(description="AcquiSense M&A Due Diligence Demonstration Runner")
    parser.add_argument(
        "--target",
        choices=list(TARGET_PROFILES.keys()),
        default="NovaPay FinTech Corp",
        help="Target company to evaluate (default: 'NovaPay FinTech Corp')",
    )
    parser.add_argument(
        "--pattern",
        choices=["Hierarchical", "Parallel", "Sequential"],
        default="Hierarchical",
        help="Multi-agent orchestration pattern (default: 'Hierarchical')",
    )
    parser.add_argument(
        "--mode",
        choices=["deterministic", "live"],
        default="deterministic",
        help="Execution mode (default: 'deterministic')",
    )
    parser.add_argument(
        "--export",
        default=None,
        help="Optional custom output path for markdown report",
    )
    args = parser.parse_args()

    run_demo(target_company=args.target, pattern=args.pattern, mode=args.mode, export_path=args.export)


if __name__ == "__main__":
    main()
