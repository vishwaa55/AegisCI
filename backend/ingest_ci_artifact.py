"""
AegisCI Local Artifact Ingestion Tool.

Allows developers to ingest CI failure artifacts or Semgrep results locally
when the AegisCI backend is running on localhost and cannot be reached directly
by cloud GitHub Actions runners.

Usage:
    python -m backend.ingest_ci_artifact --file path/to/aegis-ci-run.json
    python -m backend.ingest_ci_artifact --zip path/to/aegis-incident-report.zip
    python -m backend.ingest_ci_artifact --file path/to/aegis-ci-run.json --direct
"""

import argparse
import json
import logging
import os
import sys
import zipfile
from typing import Any, Dict, Optional

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aegis.ingest")


def load_payload_from_file(file_path: str) -> Dict[str, Any]:
    """Load JSON payload from a file path."""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_payload_from_zip(zip_path: str) -> Dict[str, Any]:
    """Extract and load incident/results JSON from a downloaded GitHub artifact zip."""
    with zipfile.ZipFile(zip_path, "r") as z:
        # Search for aegis-ci-run.json or aegis-incident-*.json
        names = z.namelist()
        target = None
        for name in names:
            if name.endswith("aegis-ci-run.json") or (name.startswith("aegis-incident") and name.endswith(".json")):
                target = name
                break

        if not target:
            # Check for test-output.log
            if "test-output.log" in names:
                log_data = z.read("test-output.log").decode("utf-8", errors="replace")
                return {
                    "repo": "local/AegisCI",
                    "commit_sha": "manual-ingest",
                    "branch": "main",
                    "run_id": f"ingest-{os.path.basename(zip_path)}",
                    "logs": log_data,
                    "test_passed": False,
                }
            raise FileNotFoundError(f"Could not locate an Aegis incident JSON or log inside {zip_path}")

        raw = z.read(target).decode("utf-8")
        return json.loads(raw)


def post_to_backend(payload: Dict[str, Any], backend_url: str, secret: Optional[str] = None) -> Dict[str, Any]:
    """Send payload to the AegisCI FastAPI backend."""
    endpoint = f"{backend_url.rstrip('/')}/ci/results"
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-Aegis-Secret"] = secret

    logger.info(f"Posting CI results to {endpoint}...")
    res = requests.post(endpoint, json=payload, headers=headers, timeout=30)
    res.raise_for_status()
    return res.json()


def execute_direct(payload: Dict[str, Any]):
    """Execute the pipeline directly in-process without needing the HTTP server."""
    from backend.agents.graph import aegis_graph
    from backend.database import SessionLocal
    from backend.models import Incident
    from backend.security.parser import parse_semgrep_json
    from backend.utils.scrubber import scrub_secrets

    clean_logs = scrub_secrets(payload.get("logs") or "")
    repo = payload.get("repo", "local/AegisCI")
    commit_sha = payload.get("commit_sha", "manual")
    branch = payload.get("branch", "main")
    run_id = payload.get("run_id", "manual-run")

    logger.info(f"Executing in-process remediation for {repo}@{commit_sha}...")

    # Functional failure branch
    if clean_logs:
        incident_id = f"inc-direct-{run_id}"
        initial_state = {
            "incident_id": incident_id,
            "repo": repo,
            "commit_sha": commit_sha,
            "branch": branch,
            "run_id": run_id,
            "raw_logs": clean_logs,
            "cleaned_logs": "",
            "is_flaky_ignored": False,
            "flaky_reason": None,
            "diagnosis_category": None,
            "diagnosis_confidence": 0.0,
            "affected_files": [],
            "evidence": "",
            "current_patch": None,
            "guardrail_passed": True,
            "guardrail_error": None,
            "rejection_memory_context": "",
            "current_attempt": 0,
            "max_attempts": 3,
            "patch_history": [],
            "test_passed": False,
            "test_output": "",
            "security_findings": [],
            "active_finding_id": None,
            "attacker_assessment": None,
            "defender_a_proposal": None,
            "defender_b_proposal": None,
            "debate_history": [],
            "judge_decision": None,
            "security_remediation_round": 0,
            "max_security_rounds": 3,
            "final_outcome": "processing",
            "pr_link": None,
            "pr_branch": None,
            "summary_notes": "",
            "agent_execution_log": [],
        }

        db = SessionLocal()
        inc = Incident(
            id=incident_id,
            repo=repo,
            commit_sha=commit_sha,
            branch=branch,
            run_id=run_id,
            raw_logs=clean_logs,
            final_outcome="processing",
        )
        db.merge(inc)
        db.commit()
        db.close()

        final = aegis_graph.invoke(initial_state)
        logger.info(f"Functional remediation completed: outcome={final.get('final_outcome')}, PR={final.get('pr_link')}")

    # Security branch
    semgrep_data = payload.get("semgrep_json")
    if semgrep_data:
        from backend.agents.security_graph import security_graph
        findings = parse_semgrep_json(semgrep_data)
        if findings:
            sec_id = f"sec-direct-{run_id}"
            active = findings[0]
            sec_state = {
                "incident_id": sec_id,
                "repo": repo,
                "commit_sha": commit_sha,
                "branch": branch,
                "run_id": run_id,
                "raw_logs": "",
                "cleaned_logs": "",
                "is_flaky_ignored": False,
                "flaky_reason": None,
                "diagnosis_category": "security_finding",
                "diagnosis_confidence": 0.9,
                "affected_files": [active.file_path],
                "evidence": active.message,
                "current_patch": None,
                "guardrail_passed": True,
                "guardrail_error": None,
                "rejection_memory_context": "",
                "current_attempt": 0,
                "max_attempts": 3,
                "patch_history": [],
                "test_passed": False,
                "test_output": "",
                "security_findings": [f.model_dump() for f in findings],
                "active_finding_id": active.id,
                "attacker_assessment": None,
                "defender_a_proposal": None,
                "defender_b_proposal": None,
                "debate_history": [],
                "judge_decision": None,
                "security_remediation_round": 1,
                "max_security_rounds": 3,
                "final_outcome": "processing",
                "pr_link": None,
                "pr_branch": None,
                "summary_notes": "",
                "agent_execution_log": [],
            }
            sec_final = security_graph.invoke(sec_state)
            logger.info(f"Security debate completed: outcome={sec_final.get('final_outcome')}, PR={sec_final.get('pr_link')}")


def main():
    parser = argparse.ArgumentParser(description="Ingest CI artifacts into AegisCI")
    parser.add_argument("--file", "-f", help="Path to JSON result file (e.g. aegis-ci-run.json)")
    parser.add_argument("--zip", "-z", help="Path to downloaded GitHub Actions artifact zip file")
    parser.add_argument("--backend-url", default=os.getenv("AEGIS_BACKEND_URL", "http://localhost:8000"), help="Backend URL")
    parser.add_argument("--secret", default=os.getenv("AEGIS_WEBHOOK_SECRET"), help="Optional X-Aegis-Secret authentication")
    parser.add_argument("--direct", action="store_true", help="Execute pipeline directly in-process without HTTP call")

    args = parser.parse_args()

    if not args.file and not args.zip:
        parser.error("Specify either --file or --zip")

    if args.zip:
        payload = load_payload_from_zip(args.zip)
    else:
        payload = load_payload_from_file(args.file)

    if args.direct:
        execute_direct(payload)
    else:
        res = post_to_backend(payload, args.backend_url, args.secret)
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
