#!/usr/bin/env python3
"""
Opt-in Cloud Deployment & Preflight Validation Script (`deploy.py`).
Defaults to local-only operation (`DEPLOY_TARGET=none`).
Never triggers cloud deployment unless BOTH `--target cloud_run` (or `DEPLOY_TARGET=cloud_run`)
AND `--confirm` (or `CONFIRM_CLOUD_DEPLOY=true`) are explicitly provided and all preflight checks pass.
"""

import os
import sys
import shutil
import argparse
from typing import Any, Dict, List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv(override=False)
except ImportError:
    pass

from acquisense.config import AcquiSenseConfig


def run_deployment_preflight(cfg: AcquiSenseConfig, cli_target: Optional[str] = None, cli_confirm: bool = False) -> Dict[str, Any]:
    target = (cli_target or cfg.deploy_target).strip().lower()
    confirmed = cli_confirm or cfg.confirm_cloud_deploy

    if target == "none":
        return {
            "status": "LOCAL_ONLY_NO_OP",
            "deploy_target": "none",
            "cloud_deployment_triggered": False,
            "message": "DEPLOY_TARGET=none (default). Local operation verified; no cloud deployment triggered.",
        }

    if target != "cloud_run":
        raise ValueError(f"Unsupported deploy target '{target}'. Allowed: 'none', 'cloud_run'.")

    if not confirmed:
        raise PermissionError(
            "Cloud deployment aborted: explicit confirmation required. "
            "Pass `--confirm` or set `CONFIRM_CLOUD_DEPLOY=true`."
        )

    missing_checks: List[str] = []
    if not cfg.gcp_project_id:
        missing_checks.append("GCP_PROJECT_ID is not set.")
    if not cfg.gcp_region:
        missing_checks.append("GCP_REGION is not set.")
    if not cfg.gcp_artifact_repository:
        missing_checks.append("GCP_ARTIFACT_REPOSITORY is not set.")
    if cfg.database_url.startswith("sqlite:"):
        missing_checks.append(
            "DATABASE_URL uses local ephemeral SQLite; multi-instance Cloud Run requires durable Cloud SQL PostgreSQL (postgresql://...)."
        )
    if shutil.which("gcloud") is None:
        missing_checks.append("gcloud CLI binary is not installed in PATH.")

    if missing_checks:
        raise RuntimeError(
            "Cloud Run preflight validation failed — aborting safely before deployment:\n  - "
            + "\n  - ".join(missing_checks)
        )

    return {
        "status": "PREFLIGHT_PASSED_READY_FOR_GCLOUD_SUBMIT",
        "deploy_target": "cloud_run",
        "gcp_project_id": cfg.gcp_project_id,
        "gcp_region": cfg.gcp_region,
        "gcp_artifact_repository": cfg.gcp_artifact_repository,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="AcquiSense Opt-In Deployment Manager")
    parser.add_argument("--target", choices=["none", "cloud_run"], default=None, help="Deployment target (default: none)")
    parser.add_argument("--confirm", action="store_true", help="Explicit confirmation for cloud deployment")
    args = parser.parse_args()

    cfg = AcquiSenseConfig.from_env()
    try:
        res = run_deployment_preflight(cfg, cli_target=args.target, cli_confirm=args.confirm)
        print(f"[Deploy Status] {res['status']}: {res.get('message', 'Ready')}")
        return 0
    except Exception as ex:
        print(f"[Deploy Aborted Safely] {ex}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
