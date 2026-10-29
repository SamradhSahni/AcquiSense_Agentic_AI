"""
Strict Pydantic schemas, versioned VDR datasets, and deterministic Python business logic
for risk scoring, DCF valuation, EV-to-Equity reconciliation, escrow calculation, and
final Go / Conditional-Go / No-Go / Insufficient-Evidence-Hold decision rules.
"""

import os
import json
import sqlite3
import hashlib
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
import numpy as np
from scipy import stats, optimize
import pydantic
from pydantic import BaseModel as _RawBaseModel, Field as _RawField

from acquisense import POLICY_VERSION, PROMPT_VERSION, DATASET_VERSION

PYDANTIC_VERSION_STR = pydantic.__version__
PYDANTIC_V2 = int(PYDANTIC_VERSION_STR.split(".")[0]) >= 2


def Field(*args, **kwargs):
    if not PYDANTIC_V2 and "pattern" in kwargs:
        kwargs["regex"] = kwargs.pop("pattern")
    return _RawField(*args, **kwargs)


class StrictBaseModel(_RawBaseModel):
    if PYDANTIC_V2:
        model_config = pydantic.ConfigDict(extra="forbid", validate_assignment=True)
    else:
        class Config:
            extra = "forbid"
            validate_assignment = True

        def model_dump(self, *args, **kwargs) -> Dict[str, Any]:
            return json.loads(self.json(*args, **kwargs))

        def model_dump_json(self, *args, **kwargs) -> str:
            return self.json(*args, **kwargs)


class DomainType(str, Enum):
    FINANCIAL = "Financial Performance"
    LEGAL = "Legal & Regulatory"
    TECH = "Technology & Architecture"
    CYBER = "Cybersecurity & Threat Posture"
    HR = "Human Resources & Talent"
    ESG = "ESG & Sustainability"


class SeverityLevel(str, Enum):
    BENIGN = "BENIGN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ExposureCategory(str, Enum):
    DETERMINISTIC_PRICE_REDUCTION = "DETERMINISTIC_PRICE_REDUCTION"
    CONTINGENT_ESCROW_LIABILITY = "CONTINGENT_ESCROW_LIABILITY"
    BENIGN_ROUTINE_EXPENSE = "BENIGN_ROUTINE_EXPENSE"


class GoNoGoDecision(str, Enum):
    GO = "GO"
    CONDITIONAL_GO = "CONDITIONAL_GO"
    NO_GO = "NO_GO"
    INSUFFICIENT_EVIDENCE_HOLD = "INSUFFICIENT_EVIDENCE_HOLD"


class EvidenceItem(StrictBaseModel):
    evidence_id: str = Field(..., min_length=5)
    target_company: str = Field(..., min_length=3)
    source_doc: str = Field(..., min_length=5)
    file_path: str = Field(..., min_length=5)
    byte_offset_start: int = Field(..., ge=0)
    byte_offset_end: int = Field(..., gt=0)
    domain: DomainType
    clause_summary: str = Field(..., min_length=15)
    financial_impact_musd: float = Field(..., ge=0.0, le=1000.0)
    currency_unit: str = Field(default="USD_MILLIONS", pattern="^USD_MILLIONS$")
    exposure_category: ExposureCategory
    severity: SeverityLevel
    sha256_hash: str = Field(..., min_length=64, max_length=64)


class LLMExtractedDomainFacts(StrictBaseModel):
    """
    Structured output schema for GPT-4o / agent fact extraction ONLY.
    Numerical risk scores and valuation totals are computed deterministically in Python.
    """
    target_company: str
    domain: DomainType
    selected_evidence_ids: List[str]
    excluded_benign_doc_ids: List[str]
    quarantined_doc_ids: List[str]
    extracted_clause_facts: List[str]
    recommended_mitigation_covenants: List[str]


class DCFScenarioRow(StrictBaseModel):
    year: int = Field(..., ge=1, le=10)
    projected_revenue_musd: float = Field(..., gt=0.0)
    ebitda_musd: float
    taxes_musd: float
    capex_and_wc_musd: float
    fcff_musd: float
    discounted_fcff_musd: float


class DCFValuationOutput(StrictBaseModel):
    target_company: str
    policy_version: str = POLICY_VERSION
    currency_unit: str = Field(default="USD_MILLIONS", pattern="^USD_MILLIONS$")
    valuation_basis: str = "Equity Value Purchase Price Basis (Cash-Free Debt-Adjusted)"
    documented_assumptions: Dict[str, Any]
    asking_price_equity_musd: float = Field(..., gt=0.0)
    wacc_pct: float = Field(..., gt=1.0, lt=35.0)
    terminal_growth_pct: float = Field(..., ge=0.0, lt=8.0)
    pv_5yr_fcff_musd: float
    pv_terminal_value_musd: float
    base_enterprise_value_musd: float = Field(..., gt=0.0)
    less_total_debt_musd: float = Field(..., ge=0.0)
    plus_cash_musd: float = Field(..., ge=0.0)
    implied_equity_value_musd: float = Field(..., gt=0.0)
    direct_price_reduction_musd: float = Field(..., ge=0.0)
    risk_adjusted_offer_price_musd: float = Field(..., gt=0.0)
    indemnity_escrow_holdback_musd: float = Field(..., ge=0.0)
    net_cash_at_closing_to_seller_musd: float = Field(..., ge=0.0)
    valuation_gap_vs_ask_musd: float
    implied_ev_ebitda_multiple: float = Field(..., gt=0.0)
    wacc_tg_sensitivity_matrix: Dict[str, Dict[str, float]]
    yearly_schedule: List[DCFScenarioRow]


class MLForecastOutput(StrictBaseModel):
    model_name: str
    corpus_provenance: str = "Synthetic Historical M&A Calibration Corpus (N=250, In-Fold Standardized)"
    training_sample_size: int = Field(..., ge=100)
    in_fold_cv_accuracy: float = Field(..., ge=0.5, le=1.0)
    in_fold_cv_roc_auc: float = Field(..., ge=0.5, le=1.0)
    random_seed_used: int
    pmi_failure_probability_pct: float = Field(..., ge=0.0, le=100.0)
    expected_synergy_musd: float
    synergy_var_95_musd: float
    retention_attrition_risk_score: float = Field(..., ge=0.0, le=100.0)
    feature_contributions: Dict[str, float]
    key_risk_drivers: List[str]


class RiskDimensionBreakdown(StrictBaseModel):
    inherent_evidence_floor: float = Field(..., ge=0.0, le=100.0)
    financial_materiality_score: float = Field(..., ge=0.0, le=100.0)
    operational_sla_impact_score: float = Field(..., ge=0.0, le=100.0)
    regulatory_legal_score: float = Field(..., ge=0.0, le=100.0)
    cross_domain_cascade_score: float = Field(..., ge=0.0, le=100.0)
    residual_risk_score: float = Field(..., ge=0.0, le=100.0)


class DomainRiskAssessment(StrictBaseModel):
    agent_id: str
    framework: str = Field(..., pattern="^(Google_ADK|CrewAI)$")
    requested_execution_mode: str = Field(..., pattern="^(deterministic|live)$")
    actual_execution_mode: str = Field(..., pattern="^(deterministic|live|live_cache_replay|deterministic_fallback)$")
    actual_model_id: str = Field(..., min_length=3)
    fallback_used: bool = False
    fallback_reason: Optional[str] = None
    execution_status: str = Field(default="COMPLETED", pattern="^(COMPLETED|FAILED|HOLD)$")
    latency_ms: float = Field(..., ge=0.0)
    retry_count: int = Field(default=0, ge=0)
    cache_hit: bool = False
    error_info: Optional[str] = None
    domain: DomainType
    risk_score: float = Field(..., ge=0.0, le=100.0)
    heuristic_confidence_score: float = Field(..., ge=0.0, le=1.0)
    severity: SeverityLevel
    max_evidence_severity: SeverityLevel
    currency_unit: str = Field(default="USD_MILLIONS", pattern="^USD_MILLIONS$")
    deterministic_adjustment_musd: float = Field(..., ge=0.0)
    contingent_escrow_exposure_musd: float = Field(..., ge=0.0)
    quantified_exposure_musd: float = Field(..., ge=0.0)
    dimension_breakdown: RiskDimensionBreakdown
    key_findings: List[str]
    mitigation_covenants: List[str]
    evidence_refs: List[str]
    excluded_benign_doc_ids: List[str]
    quarantined_doc_ids: List[str]
    worker_verification_summary: str
    input_sha256: str = Field(..., min_length=64, max_length=64)


class ConsolidatedDueDiligenceReport(StrictBaseModel):
    report_id: str
    deal_id: str
    request_id: str
    timestamp_utc: str
    policy_version: str = POLICY_VERSION
    prompt_version: str = PROMPT_VERSION
    dataset_version: str = DATASET_VERSION
    requested_execution_mode: str
    actual_execution_mode: str
    target_company: str
    acquirer_company: str
    currency_unit: str = Field(default="USD_MILLIONS", pattern="^USD_MILLIONS$")
    asking_price_musd: float = Field(..., gt=0.0)
    base_enterprise_value_musd: float = Field(..., gt=0.0)
    implied_equity_value_musd: float = Field(..., gt=0.0)
    direct_price_reduction_musd: float = Field(..., ge=0.0)
    recommended_offer_price_musd: float = Field(..., gt=0.0)
    escrow_holdback_musd: float = Field(..., ge=0.0)
    composite_risk_score: float = Field(..., ge=0.0, le=100.0)
    unresolved_critical_domains: List[str]
    heuristic_overall_confidence: float = Field(..., ge=0.0, le=1.0)
    context_completeness_pct: float = Field(..., ge=0.0, le=100.0)
    incomplete_context_hold_applied: bool
    final_decision: GoNoGoDecision
    executive_rationale: str
    dcf_valuation: DCFValuationOutput
    ml_forecast: MLForecastOutput
    domain_assessments: List[DomainRiskAssessment]
    mandatory_closing_conditions: List[str]
    context_mechanism: str = Field(..., pattern="^(DURABLE_SQLITE_WAL_BLACKBOARD|BOUNDED_P2P_LOCAL_SNAPSHOT)$")
    context_snapshot_sha256: str = Field(..., min_length=64, max_length=64)


# ============================================================================
# DETERMINISTIC PYTHON SCORING & DECISION FUNCTIONS (REQUIREMENT 4)
# ============================================================================

SEVERITY_TO_RANK = {
    SeverityLevel.BENIGN: 0,
    SeverityLevel.LOW: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.HIGH: 3,
    SeverityLevel.CRITICAL: 4,
}
RANK_TO_SEVERITY = {v: k for k, v in SEVERITY_TO_RANK.items()}
INHERENT_FLOOR_MAP = {
    SeverityLevel.BENIGN: 5.0,
    SeverityLevel.LOW: 18.0,
    SeverityLevel.MEDIUM: 42.0,
    SeverityLevel.HIGH: 62.0,
    SeverityLevel.CRITICAL: 82.0,
}

DOMAIN_WEIGHTS = {
    DomainType.FINANCIAL: 0.24,
    DomainType.LEGAL: 0.22,
    DomainType.CYBER: 0.20,
    DomainType.TECH: 0.13,
    DomainType.HR: 0.12,
    DomainType.ESG: 0.09,
}


def compute_deterministic_domain_score(
    evidence_items: List[Dict[str, Any]],
    asking_price_musd: float,
    op_sla_score: float,
    reg_legal_score: float,
    cascade_score: float,
    persona_risk_delta: float = 0.0,
) -> Tuple[float, SeverityLevel, SeverityLevel, RiskDimensionBreakdown]:
    """
    Deterministic Python policy function computing domain risk score and enforcing
    hard escalation floors so CRITICAL evidence can never be downgraded to MEDIUM.
    """
    max_rank = max([SEVERITY_TO_RANK[SeverityLevel(e["severity"])] for e in evidence_items], default=1)
    max_ev_sev = RANK_TO_SEVERITY[max_rank]
    inherent_floor = INHERENT_FLOOR_MAP[max_ev_sev]
    tot_exp = sum(float(e["financial_impact_musd"]) for e in evidence_items)
    fin_materiality = min(95.0, (tot_exp / max(asking_price_musd, 1.0)) * 750.0)
    residual_risk = round(inherent_floor * 0.45, 2)

    weighted = (
        0.34 * inherent_floor
        + 0.20 * fin_materiality
        + 0.16 * op_sla_score
        + 0.14 * reg_legal_score
        + 0.10 * cascade_score
        + 0.06 * residual_risk
    )
    adjusted = weighted * (1.0 + persona_risk_delta)

    if max_ev_sev == SeverityLevel.CRITICAL:
        final_score = round(min(98.0, max(76.0, adjusted)), 2)
        final_sev = SeverityLevel.CRITICAL
    elif max_ev_sev == SeverityLevel.HIGH:
        final_score = round(min(95.0, max(56.0, adjusted)), 2)
        final_sev = SeverityLevel.CRITICAL if final_score >= 75.0 else SeverityLevel.HIGH
    elif max_ev_sev == SeverityLevel.MEDIUM:
        final_score = round(min(90.0, max(36.0, adjusted)), 2)
        final_sev = SeverityLevel.HIGH if final_score >= 56.0 else SeverityLevel.MEDIUM
    else:
        final_score = round(min(34.0, max(8.0, adjusted)), 2)
        final_sev = SeverityLevel.LOW

    breakdown = RiskDimensionBreakdown(
        inherent_evidence_floor=round(inherent_floor, 2),
        financial_materiality_score=round(fin_materiality, 2),
        operational_sla_impact_score=round(op_sla_score, 2),
        regulatory_legal_score=round(reg_legal_score, 2),
        cross_domain_cascade_score=round(cascade_score, 2),
        residual_risk_score=round(residual_risk, 2),
    )
    return final_score, final_sev, max_ev_sev, breakdown


def compute_deterministic_committee_decision(
    domain_assessments: List[DomainRiskAssessment],
    dcf_obj: DCFValuationOutput,
    ml_obj: MLForecastOutput,
    context_completeness_pct: float,
    required_contingent_escrow_musd: float,
) -> Tuple[GoNoGoDecision, float, List[str], bool]:
    """
    Deterministic Python decision gate:
      - Returns `INSUFFICIENT_EVIDENCE_HOLD` if context_completeness_pct < 100.0%
        or if any domain failed execution or lacks required evidence when risks exist.
      - Returns `NO_GO` if > 2 CRITICAL domains, or composite_risk >= 72.0,
        or CRITICAL domains lack >= 80% escrow coverage.
      - Returns `CONDITIONAL_GO` if >= 1 CRITICAL or HIGH domain or composite_risk >= 35.0.
      - Returns `GO` only when all 6 domains complete with 100% context completeness and LOW/MEDIUM risk.
    """
    composite_risk = round(
        sum(d.risk_score * DOMAIN_WEIGHTS.get(d.domain, 0.15) for d in domain_assessments),
        2,
    )
    unresolved_critical = [d.domain.value for d in domain_assessments if d.severity == SeverityLevel.CRITICAL]
    high_domains = [d.domain.value for d in domain_assessments if d.severity == SeverityLevel.HIGH]
    any_failed = any(d.execution_status != "COMPLETED" for d in domain_assessments)

    if context_completeness_pct < 100.0 or len(domain_assessments) < 6 or any_failed:
        return GoNoGoDecision.INSUFFICIENT_EVIDENCE_HOLD, composite_risk, unresolved_critical, True

    escrow_adequate = (dcf_obj.indemnity_escrow_holdback_musd >= 0.80 * required_contingent_escrow_musd)
    if len(unresolved_critical) > 2 or composite_risk >= 72.0 or (len(unresolved_critical) >= 1 and not escrow_adequate):
        return GoNoGoDecision.NO_GO, composite_risk, unresolved_critical, False
    elif len(unresolved_critical) >= 1 or len(high_domains) >= 1 or composite_risk >= 35.0 or ml_obj.pmi_failure_probability_pct >= 50.0:
        return GoNoGoDecision.CONDITIONAL_GO, composite_risk, unresolved_critical, False
    else:
        return GoNoGoDecision.GO, composite_risk, unresolved_critical, False
