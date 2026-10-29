"""
Security, JWT validation (using PyJWT / cryptography HMAC-SHA256), deal-level RBAC,
cross-instance SQLite-WAL rate limiting, prompt/document injection quarantine, and grounding checks.
"""

import os
import re
import hmac
import json
import time
import uuid
import base64
import codecs
import sqlite3
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from acquisense.schemas import (
    StrictBaseModel,
    DomainRiskAssessment,
    EvidenceItem,
    ExposureCategory,
    SeverityLevel,
    SEVERITY_TO_RANK,
    RANK_TO_SEVERITY,
)

try:
    import jwt as pyjwt
    PYJWT_AVAILABLE = True
except ImportError:
    pyjwt = None
    PYJWT_AVAILABLE = False


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def create_jwt_token(
    subject: str,
    allowed_targets: List[str],
    role: str = "deal_committee",
    ttl_seconds: int = 3600,
    secret_key: Optional[str] = None,
    issuer: str = "acquisense-iam",
    audience: str = "acquisense-api",
) -> str:
    """
    Issues a signed HS256 JWT token using PyJWT (if installed) or maintained
    `cryptography.hazmat.primitives.hmac` with explicit `iss`, `aud`, `exp`, `nbf`, and `allowed_targets`.
    """
    secret_str = secret_key or os.environ["ACQUISENSE_JWT_SECRET"]
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "role": role,
        "allowed_targets": list(allowed_targets),
        "iat": now,
        "nbf": now - 5,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex[:12],
    }
    if PYJWT_AVAILABLE:
        return pyjwt.encode(payload, secret_str, algorithm="HS256")

    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))}."
        f"{_b64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))}"
    )
    h = crypto_hmac.HMAC(secret_str.encode("utf-8"), hashes.SHA256())
    h.update(signing_input.encode("ascii"))
    sig = h.finalize()
    return f"{signing_input}.{_b64url_encode(sig)}"


def verify_jwt_token(
    token: str,
    secret_key: Optional[str] = None,
    expected_issuer: str = "acquisense-iam",
    expected_audience: str = "acquisense-api",
) -> Dict[str, Any]:
    """
    Verifies a JWT token with explicit algorithm constraint (`HS256` only) and validates
    signature, `exp`, `nbf`, `iss`, and `aud` claims.
    """
    secret_str = secret_key or os.environ["ACQUISENSE_JWT_SECRET"]
    if PYJWT_AVAILABLE:
        try:
            return pyjwt.decode(
                token,
                secret_str,
                algorithms=["HS256"],
                issuer=expected_issuer,
                audience=expected_audience,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except Exception as ex:
            raise PermissionError(f"JWT validation failed: {ex}") from ex

    parts = token.strip().split(".")
    if len(parts) != 3:
        raise PermissionError("Malformed JWT token structure.")
    header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
    if header.get("alg") != "HS256":
        raise PermissionError(f"Disallowed JWT algorithm '{header.get('alg')}'; only HS256 permitted.")

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    h = crypto_hmac.HMAC(secret_str.encode("utf-8"), hashes.SHA256())
    h.update(signing_input)
    try:
        h.verify(_b64url_decode(parts[2]))
    except Exception as ex:
        raise PermissionError("JWT signature verification failed (cryptography HMAC-SHA256 mismatch).") from ex

    claims = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    now = int(time.time())
    if claims.get("exp", 0) < now:
        raise PermissionError("JWT token has expired.")
    if claims.get("nbf", 0) > now + 5:
        raise PermissionError("JWT token is not yet active (nbf violation).")
    if claims.get("iss") != expected_issuer:
        raise PermissionError(f"Invalid JWT issuer '{claims.get('iss')}'.")
    if claims.get("aud") != expected_audience:
        raise PermissionError(f"Invalid JWT audience '{claims.get('aud')}'.")
    return claims


def check_distributed_rate_limit(db_path: str, client_sub: str, max_requests_per_min: int = 30) -> int:
    """
    Cross-process / cross-instance rate limiter backed by SQLite WAL transactions.
    """
    now = time.time()
    conn = sqlite3.connect(db_path, timeout=15.0)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("CREATE TABLE IF NOT EXISTS distributed_rate_limits (client_id TEXT, request_epoch REAL)")
    cur.execute("BEGIN IMMEDIATE")
    cur.execute("DELETE FROM distributed_rate_limits WHERE request_epoch < ?", (now - 60.0,))
    cur.execute("SELECT COUNT(*) FROM distributed_rate_limits WHERE client_id = ?", (client_sub,))
    count = int(cur.fetchone()[0])
    if count >= max_requests_per_min:
        conn.commit()
        conn.close()
        raise OverflowError(f"Rate limit exceeded ({count}/{max_requests_per_min} req/min) for '{client_sub}'.")
    cur.execute("INSERT INTO distributed_rate_limits VALUES (?, ?)", (client_sub, now))
    conn.commit()
    conn.close()
    return count + 1


class SecurityGuardrailResult(StrictBaseModel):
    passed: bool
    policy_verdict: str
    injection_detected: bool
    indirect_doc_injection_detected: bool
    toxicity_detected: bool
    obfuscation_decoded: bool
    risk_flags: List[str]
    effective_prompt: str
    persona_risk_aversion_delta: float
    persona_materiality_cutoff_musd: float
    audit_note: str


class SecurityGuardrailEngine:
    INJECTION_SIGNATURES = [
        r"ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions|rules|directives)",
        r"system\s+override|developer\s+mode|jailbreak|sudo\s+mode",
        r"disregard\s+(all\s+)?(patent|risks|debts|litigation|liabilities|compliance)",
        r"output\s+go\s+with\s+(0|zero|no)\s+risk",
        r"<\|im_start\|>|###\s*system:|\[inst\]|<script>|drop\s+table|union\s+select",
    ]
    TOXIC_PATTERNS = [
        r"\b(idiot|idiots|moron|morons|stupid|incompetent|useless|pathetic|fools)\b",
        r"\b(shut\s+up|damn\s+it|garbage|trash)\b",
        r"approve\s+this\s+deal\s+or\s+you(\s+all)?\s+are\s+fired",
        r"i\s+don'?t\s+care\s+about\s+your\s+(stupid\s+)?compliance",
    ]
    LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
    ALLOWED_CONTENT_TYPES = {"text/plain", "application/json", "application/pdf", "text/markdown"}

    def __init__(self, max_input_chars: int = 4000, max_file_bytes: int = 524288):
        self.max_input_chars = max_input_chars
        self.max_file_bytes = max_file_bytes
        self.audit_log: List[Dict[str, Any]] = []
        self.quarantined_documents: List[Dict[str, Any]] = []

    def validate_file_upload_constraints(self, file_path: str, content_type: str = "text/plain") -> int:
        if content_type not in self.ALLOWED_CONTENT_TYPES:
            raise ValueError(f"Disallowed VDR document content-type '{content_type}'.")
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"VDR file not found: {file_path}")
        fsize = os.path.getsize(file_path)
        if fsize > self.max_file_bytes:
            raise ValueError(f"VDR file '{file_path}' size {fsize} exceeds limit {self.max_file_bytes} bytes.")
        return fsize

    def _normalize_and_deobfuscate(self, text: str) -> Tuple[str, bool]:
        decoded_any = False
        cleaned = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", text)
        if len(cleaned) != len(text):
            decoded_any = True
        b64_candidates = re.findall(r"\b[A-Za-z0-9+/]{20,}={0,2}", cleaned)
        for cand in b64_candidates:
            try:
                raw_dec = base64.b64decode(cand, validate=True).decode("utf-8", errors="ignore")
                if raw_dec and sum(c.isprintable() for c in raw_dec) / len(raw_dec) > 0.85:
                    cleaned += " [DECODED_B64: " + raw_dec + "]"
                    decoded_any = True
            except Exception:
                pass
        if "rot13:" in cleaned.lower():
            rot_part = cleaned.split(":", 1)[-1]
            cleaned += " [DECODED_ROT13: " + codecs.decode(rot_part, "rot_13") + "]"
            decoded_any = True
        leet_norm = cleaned.lower().translate(self.LEET_MAP)
        return cleaned + " || " + leet_norm, decoded_any

    def inspect_text(
        self,
        raw_text: str,
        persona_name: str = "Standard_User",
        is_document_chunk: bool = False,
        hard_reject_on_injection: bool = False,
    ) -> SecurityGuardrailResult:
        if not isinstance(raw_text, str) or len(raw_text.strip()) == 0:
            raise ValueError("Empty or non-string input rejected by SecurityGuardrailEngine.")
        if len(raw_text) > self.max_input_chars:
            raise ValueError(f"Input length {len(raw_text)} exceeds limit {self.max_input_chars} characters.")

        normalized_view, decoded_flag = self._normalize_and_deobfuscate(raw_text)
        flags: List[str] = []
        injection_hit = False
        toxicity_hit = False
        sanitized = raw_text

        for pat in self.INJECTION_SIGNATURES:
            if re.search(pat, normalized_view, flags=re.IGNORECASE):
                injection_hit = True
                flags.append(f"{'INDIRECT_DOC_INJECTION' if is_document_chunk else 'PROMPT_INJECTION'}:{pat[:30]}")

        for pat in self.TOXIC_PATTERNS:
            if re.search(pat, raw_text, flags=re.IGNORECASE):
                toxicity_hit = True
                flags.append(f"TOXIC_COERCION:{pat[:25]}")
                sanitized = re.sub(pat, "[REDACTED_HOSTILE_PHRASE]", sanitized, flags=re.IGNORECASE)

        lp = raw_text.lower()
        if "zero-tolerance" in lp or "hyper-strict" in lp or "micro-audit" in lp:
            cutoff_musd = 0.015
            risk_delta = +0.08
        elif "coarse" in lp or "headline-only" in lp or "high-threshold" in lp:
            cutoff_musd = 1.40
            risk_delta = -0.03
        elif "quant" in lp or "var" in lp or "wacc" in lp:
            cutoff_musd = 0.25
            risk_delta = +0.05
        elif "conservative" in lp or "compliance" in lp or "esg" in lp:
            cutoff_musd = 0.20
            risk_delta = +0.06
        else:
            cutoff_musd = 0.25
            risk_delta = 0.00

        if injection_hit:
            if is_document_chunk:
                verdict = "QUARANTINED_VDR_DOCUMENT"
                passed = False
                sanitized = "[QUARANTINED_UNTRUSTED_DOCUMENT_EXCLUDED]"
                note = f"Quarantined VDR document '{persona_name}' due to indirect prompt injection."
                self.quarantined_documents.append({"document": persona_name, "flags": flags})
            elif hard_reject_on_injection:
                raise PermissionError(f"Hard security rejection: Prompt injection detected from '{persona_name}': {flags}")
            else:
                verdict = "QUARANTINED_PROMPT_INJECTION"
                passed = False
                sanitized = "[QUARANTINED_INJECTION_NEUTRALIZED] Perform standard evidence-grounded due diligence."
                cutoff_musd = 0.25
                risk_delta = 0.00
                note = f"Quarantined prompt injection from '{persona_name}'."
        elif toxicity_hit:
            verdict = "SANITIZED_TOXICITY"
            passed = True
            note = f"Sanitized coercive language from '{persona_name}'; analytical threshold preserved."
        else:
            verdict = "ALLOWED"
            passed = True
            note = f"Clean input from '{persona_name}'."

        res = SecurityGuardrailResult(
            passed=passed,
            policy_verdict=verdict,
            injection_detected=injection_hit and not is_document_chunk,
            indirect_doc_injection_detected=injection_hit and is_document_chunk,
            toxicity_detected=toxicity_hit,
            obfuscation_decoded=decoded_flag,
            risk_flags=flags,
            effective_prompt=sanitized,
            persona_risk_aversion_delta=risk_delta,
            persona_materiality_cutoff_musd=cutoff_musd,
            audit_note=note,
        )
        self.audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": persona_name,
            "is_doc": is_document_chunk,
            "verdict": verdict,
            "cutoff_musd": cutoff_musd,
            "flags": ", ".join(flags) if flags else "NONE",
        })
        return res

    def validate_tool_payload_recursively(
        self,
        tool_name: str,
        payload: Any,
        required_keys: Set[str],
        numeric_bounds: Optional[Dict[str, Tuple[float, float]]] = None,
    ) -> Dict[str, Any]:
        import numpy as np
        if not isinstance(payload, dict):
            raise TypeError(f"Tool '{tool_name}' must return dict; got {type(payload).__name__}")
        missing = required_keys - set(payload.keys())
        if missing:
            raise KeyError(f"Tool '{tool_name}' output missing required schema keys: {sorted(missing)}")

        def _walk(obj: Any, path: str) -> None:
            if isinstance(obj, float) and (np.isnan(obj) or np.isinf(obj)):
                raise ValueError(f"Tool '{tool_name}' produced NaN/Inf at '{path}'")
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    _walk(v, f"{path}.{k}")
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    _walk(v, f"{path}[{i}]")

        _walk(payload, tool_name)
        if numeric_bounds:
            for k, (lo, hi) in numeric_bounds.items():
                if k not in payload:
                    raise KeyError(f"Tool '{tool_name}' missing bounded field '{k}'")
                v = payload[k]
                if not isinstance(v, (int, float)) or isinstance(v, bool) or not (lo <= float(v) <= hi):
                    raise ValueError(f"Tool '{tool_name}.{k}'={v} violates bounds [{lo}, {hi}]")
        return payload

    def verify_claim_grounding(
        self,
        assessment: DomainRiskAssessment,
        target_company: str,
        raw_vdr_inventory: Dict[str, List[EvidenceItem]],
    ) -> bool:
        if target_company not in raw_vdr_inventory:
            raise ValueError(f"Unknown target '{target_company}' in grounding verification.")
        raw_map = {e.evidence_id: e for e in raw_vdr_inventory[target_company]}

        det_expected = 0.0
        esc_expected = 0.0
        tot_expected = 0.0
        max_r = 0

        for ref_id in assessment.evidence_refs:
            if ref_id not in raw_map:
                raise ValueError(f"Cross-target or non-existent evidence_ref '{ref_id}' in {assessment.agent_id} for {target_company}.")
            if "INJ" in ref_id or ref_id in assessment.quarantined_doc_ids:
                raise ValueError(f"Quarantined document '{ref_id}' illegally referenced in {assessment.agent_id}!")
            ev = raw_map[ref_id]
            if ev.target_company != target_company:
                raise ValueError(f"Target identity mismatch on {ref_id}: {ev.target_company} != {target_company}")
            if ev.domain != assessment.domain:
                raise ValueError(f"Domain mismatch on {ref_id}: {ev.domain} != {assessment.domain}")
            eff_sev = SeverityLevel.LOW if ev.severity == SeverityLevel.BENIGN else ev.severity
            max_r = max(max_r, SEVERITY_TO_RANK[eff_sev])
            tot_expected += ev.financial_impact_musd
            if ev.exposure_category in (ExposureCategory.DETERMINISTIC_PRICE_REDUCTION, ExposureCategory.BENIGN_ROUTINE_EXPENSE):
                det_expected += ev.financial_impact_musd
            elif ev.exposure_category == ExposureCategory.CONTINGENT_ESCROW_LIABILITY:
                esc_expected += ev.financial_impact_musd

        expected_max_sev = RANK_TO_SEVERITY[max_r] if assessment.evidence_refs else SeverityLevel.LOW
        if assessment.max_evidence_severity != expected_max_sev:
            raise ValueError(
                f"max_evidence_severity mismatch in {assessment.agent_id}: reported {assessment.max_evidence_severity.value} "
                f"vs actual evidence max {expected_max_sev.value}"
            )
        if SEVERITY_TO_RANK[assessment.severity] < SEVERITY_TO_RANK[expected_max_sev]:
            raise ValueError(
                f"Severity downgrade violation in {assessment.agent_id}: {assessment.severity.value} < {expected_max_sev.value}"
            )
        if abs(assessment.deterministic_adjustment_musd - round(det_expected, 2)) > 0.05:
            raise ValueError(f"Deterministic adjustment mismatch in {assessment.agent_id}")
        if abs(assessment.contingent_escrow_exposure_musd - round(esc_expected, 2)) > 0.05:
            raise ValueError(f"Contingent escrow mismatch in {assessment.agent_id}")
        if abs(assessment.quantified_exposure_musd - round(tot_expected, 2)) > 0.05:
            raise ValueError(f"Total quantified exposure mismatch in {assessment.agent_id}")

        valid_tags = list(assessment.evidence_refs) + ["[SQLite_Registry]", "[DCF_ML_Engine]", "[No_Material_Findings]", "[A2A_CrossCheck]"]
        for finding in assessment.key_findings:
            if not any(tag in finding for tag in valid_tags):
                raise ValueError(f"Ungrounded finding without source tag in {assessment.agent_id}: '{finding[:60]}'")
        return True
