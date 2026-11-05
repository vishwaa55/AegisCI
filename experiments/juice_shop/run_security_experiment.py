"""
Automated Security Experiment Runner for AegisCI.
Runs the Attacker -> Defender A & B -> Judge debate workflow on the baseline findings.
"""

import json
import logging
import os
import time
from typing import Any, Dict

from backend.agents.security_graph import security_graph
from backend.agents.state import AegisAgentState
from backend.database import SessionLocal
from backend.models import Incident
from backend.security.parser import parse_semgrep_json

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("aegis.experiment.security")


def run_security_experiment(baseline_file: str = "experiments/juice_shop/baseline_scan.json") -> Dict[str, Any]:
    print("\n======================================================================")
    print("  AegisCI Phase 3 — Multi-Agent Security Debate Experiment")
    print("======================================================================")

    if not os.path.exists(baseline_file):
        raise FileNotFoundError(f"Baseline scan file not found: {baseline_file}")

    with open(baseline_file, "r", encoding="utf-8") as f:
        scan_data = json.load(f)

    findings = parse_semgrep_json(scan_data)
    if not findings:
        raise ValueError(f"No security findings parsed from {baseline_file}")

    print(f"\n[1] Loaded {len(findings)} security findings from baseline scan:")
    for idx, f in enumerate(findings):
        print(f"    - Finding #{idx+1}: {f.rule_id} ({f.severity}) in {f.file_path}:{f.start_line}")

    active = findings[0]
    incident_id = f"sec-exp-{int(time.time())}"
    run_id = f"run-sec-{int(time.time())}"
    repo = "vishwaa55/AegisCI"
    branch = "experiment/phase3-integration"

    initial_state: AegisAgentState = {
        "incident_id": incident_id,
        "repo": repo,
        "commit_sha": f"sha-{incident_id[:8]}",
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

    # Record incident in database
    db = SessionLocal()
    inc = Incident(
        id=incident_id,
        repo=repo,
        commit_sha=initial_state["commit_sha"],
        branch=branch,
        run_id=run_id,
        raw_logs=f"Security findings: {len(findings)} detected by Semgrep",
        final_outcome="processing",
    )
    db.merge(inc)
    db.commit()
    db.close()

    print(f"\n[2] Triggering security debate graph for finding '{active.rule_id}'...")
    final_state = security_graph.invoke(initial_state)

    print("\n======================================================================")
    print("  Experiment Results Summary")
    print("======================================================================")
    print(f"Incident ID        : {final_state.get('incident_id')}")
    print(f"Final Outcome      : {final_state.get('final_outcome')}")
    print(f"Debate Rounds Run  : {final_state.get('security_remediation_round')}")
    print(f"PR Link            : {final_state.get('pr_link')}")
    print(f"PR Branch          : {final_state.get('pr_branch')}")

    att = final_state.get("attacker_assessment") or {}
    print(f"\nAttacker Threat Model:")
    print(f"  Exploitability   : {att.get('exploitability')}")
    print(f"  Attack Vector    : {att.get('attack_vector')}")
    print(f"  Inputs Controlled: {att.get('attacker_controlled_inputs')}")

    judge = final_state.get("judge_decision") or {}
    print(f"\nJudge Decision:")
    print(f"  Status           : {judge.get('status')}")
    print(f"  Selected Defender: {judge.get('selected_defender')}")
    print(f"  Rationale        : {judge.get('rationale')}")

    return final_state


if __name__ == "__main__":
    run_security_experiment()
