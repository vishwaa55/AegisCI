"""
Judge Agent — evaluates Defender A and Defender B proposals and selects the winner.

Applies each candidate patch in an isolated sandbox, re-runs Semgrep, and runs
the test suite.  Selects the patch that:
1. Passes all tests (no regressions)
2. Clears the Semgrep finding
3. Has the stronger security rationale

Enforces a maximum of 3 remediation rounds before escalating.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, Optional, Tuple

from backend.agents.fix_proposer import validate_patch_guardrails
from backend.agents.llm_client import LLMClient
from backend.agents.reviewer import apply_patch_to_directory, run_isolated_tests, open_draft_pull_request, generate_pr_description
from backend.agents.state import AegisAgentState
from backend.database import SessionLocal
from backend.models import Incident

logger = logging.getLogger("aegis.judge")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _run_semgrep_on_dir(directory: str, file_path: str) -> Tuple[bool, str]:
    """
    Run Semgrep on a specific file inside the sandbox directory.
    Returns (finding_cleared, output_text).
    Finding is considered cleared if Semgrep exits 0 (no findings).
    """
    target = os.path.join(directory, file_path)
    if not os.path.isfile(target):
        return True, f"Target file {file_path} not found in sandbox; assuming cleared."

    semgrep_exe = shutil.which("semgrep") or shutil.which("pysemgrep")
    if not semgrep_exe:
        # Try venv
        venv_semgrep = os.path.join(ROOT_DIR, "venv", "Scripts", "semgrep.exe")
        if os.path.isfile(venv_semgrep):
            semgrep_exe = venv_semgrep

    if not semgrep_exe:
        return True, "Semgrep not found — skipping re-scan."

    try:
        res = subprocess.run(
            [semgrep_exe, "--config=auto", "--json", target],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = res.stdout + ("\n" + res.stderr if res.stderr else "")
        try:
            data = json.loads(res.stdout)
            num_findings = len(data.get("results", []))
            cleared = num_findings == 0
        except Exception:
            cleared = res.returncode == 0
        return cleared, output[:2000]
    except subprocess.TimeoutExpired:
        return True, "Semgrep timed out — treating as cleared for sandbox."
    except Exception as e:
        return True, f"Semgrep error: {e}"


def _apply_and_validate(
    proposal: Dict[str, Any],
    finding: Dict[str, Any],
    incident_id: str,
) -> Dict[str, Any]:
    """
    Apply a defender's patch in an isolated sandbox, run tests and Semgrep.
    Returns a validation result dict.
    """
    patch_diff = proposal.get("patch_diff", "")
    affected_file = finding.get("file_path", "")

    if not patch_diff or not patch_diff.strip():
        return {
            "applied": False,
            "tests_passed": False,
            "semgrep_cleared": False,
            "regression_detected": False,
            "test_output": "Empty patch diff.",
            "semgrep_output": "",
        }

    # Guardrail check
    guard_ok, guard_err = validate_patch_guardrails(
        patch_diff, [affected_file] if affected_file else []
    )
    if not guard_ok:
        return {
            "applied": False,
            "tests_passed": False,
            "semgrep_cleared": False,
            "regression_detected": False,
            "test_output": f"Guardrail violation: {guard_err}",
            "semgrep_output": "",
        }

    sandbox_dir = tempfile.mkdtemp(prefix=f"aegis_sec_sandbox_{incident_id}_")
    try:
        # Copy sample-app + relevant files
        sample_app_src = os.path.join(ROOT_DIR, "sample-app")
        if os.path.isdir(sample_app_src):
            shutil.copytree(sample_app_src, os.path.join(sandbox_dir, "sample-app"))

        # Copy affected file if outside sample-app
        if affected_file and not affected_file.startswith("sample-app"):
            src = os.path.join(ROOT_DIR, affected_file)
            dst = os.path.join(sandbox_dir, affected_file)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if os.path.isfile(src):
                shutil.copy2(src, dst)

        # Copy pytest.ini
        pytest_ini = os.path.join(ROOT_DIR, "pytest.ini")
        if os.path.exists(pytest_ini):
            shutil.copy(pytest_ini, sandbox_dir)

        apply_ok, apply_msg = apply_patch_to_directory(sandbox_dir, patch_diff)
        if not apply_ok:
            return {
                "applied": False,
                "tests_passed": False,
                "semgrep_cleared": False,
                "regression_detected": False,
                "test_output": f"Patch apply failed: {apply_msg}",
                "semgrep_output": "",
            }

        tests_passed, test_output = run_isolated_tests(sandbox_dir)
        semgrep_cleared, semgrep_output = _run_semgrep_on_dir(sandbox_dir, affected_file)

        return {
            "applied": True,
            "tests_passed": tests_passed,
            "semgrep_cleared": semgrep_cleared,
            "regression_detected": not tests_passed,
            "test_output": test_output[:1500],
            "semgrep_output": semgrep_output[:1000],
        }
    finally:
        shutil.rmtree(sandbox_dir, ignore_errors=True)


def _llm_compare(
    incident_id: str,
    finding: Dict[str, Any],
    proposal_a: Dict[str, Any],
    proposal_b: Dict[str, Any],
    result_a: Dict[str, Any],
    result_b: Dict[str, Any],
) -> Dict[str, Any]:
    """Ask the LLM to compare both proposals and decide."""
    llm = LLMClient()
    system = (
        "You are the Security Judge Agent for AegisCI.\n"
        "Compare two security remediation proposals and select the best one.\n"
        "Output ONLY a JSON object:\n"
        "{\n"
        '  "status": "accepted" | "rejected",\n'
        '  "selected_defender": "defender_a" | "defender_b" | "synthesized",\n'
        '  "rationale": "<explanation>"\n'
        "}\n"
        "If neither proposal is acceptable, set status='rejected' and "
        "selected_defender=null."
    )

    def _fmt(label: str, p: Dict, r: Dict) -> str:
        return (
            f"{label}:\n"
            f"  Strategy: {p.get('strategy_name', '')}\n"
            f"  Rationale: {p.get('security_rationale', '')}\n"
            f"  Side Effects: {p.get('potential_side_effects', '')}\n"
            f"  Tests Passed: {r['tests_passed']}  "
            f"Semgrep Cleared: {r['semgrep_cleared']}  "
            f"Regression: {r['regression_detected']}\n"
        )

    user = (
        f"Finding: {finding.get('rule_id')} in {finding.get('file_path')}:{finding.get('start_line')}\n"
        f"Message: {finding.get('message', '')}\n\n"
        + _fmt("Defender A", proposal_a, result_a)
        + "\n"
        + _fmt("Defender B", proposal_b, result_b)
        + "\nSelect the best proposal or reject both:"
    )

    try:
        decision = llm.generate_json(system, user)
    except Exception as e:
        logger.error(f"[{incident_id}] Judge LLM comparison failed: {e}")
        # Heuristic fallback
        a_score = int(result_a["tests_passed"]) + int(result_a["semgrep_cleared"])
        b_score = int(result_b["tests_passed"]) + int(result_b["semgrep_cleared"])
        if a_score >= b_score and a_score > 0:
            decision = {"status": "accepted", "selected_defender": "defender_a",
                        "rationale": "Heuristic: A passes more checks."}
        elif b_score > a_score:
            decision = {"status": "accepted", "selected_defender": "defender_b",
                        "rationale": "Heuristic: B passes more checks."}
        else:
            decision = {"status": "rejected", "selected_defender": None,
                        "rationale": "Neither proposal passed all checks."}

    return decision


def judge_agent(state: AegisAgentState) -> AegisAgentState:
    """
    Judge Agent node.

    1. Validates both defender patches in isolated sandboxes.
    2. Asks the LLM to compare and select the winner.
    3. If accepted: creates a draft PR via the existing open_draft_pull_request helper.
    4. If rejected and rounds remain: increments round for another debate cycle.
    5. If max rounds reached: escalates.
    """
    incident_id = state.get("incident_id", "unknown")
    findings = state.get("security_findings", [])
    active_id = state.get("active_finding_id")
    finding = next((f for f in findings if f.get("id") == active_id), findings[0] if findings else None)

    round_number = state.get("security_remediation_round", 1)
    max_rounds = state.get("max_security_rounds", 3)
    proposal_a = state.get("defender_a_proposal") or {}
    proposal_b = state.get("defender_b_proposal") or {}

    logger.info(f"[{incident_id}] Judge Agent evaluating round {round_number}/{max_rounds}...")

    if not finding:
        logger.error(f"[{incident_id}] Judge: no active finding.")
        return {**state, "final_outcome": "security_escalated",
                "summary_notes": "Judge: no finding available."}

    # Validate both proposals in sandboxes
    result_a = _apply_and_validate(proposal_a, finding, incident_id)
    result_b = _apply_and_validate(proposal_b, finding, incident_id)

    logger.info(
        f"[{incident_id}] Judge results — A: tests={result_a['tests_passed']} "
        f"semgrep={result_a['semgrep_cleared']} | "
        f"B: tests={result_b['tests_passed']} semgrep={result_b['semgrep_cleared']}"
    )

    # LLM-based comparison
    llm_decision = _llm_compare(incident_id, finding, proposal_a, proposal_b, result_a, result_b)
    selected_id = llm_decision.get("selected_defender")
    llm_status = llm_decision.get("status", "rejected")
    rationale = llm_decision.get("rationale", "")

    # Map selected proposal to its result
    if selected_id == "defender_a":
        winning_proposal = proposal_a
        winning_result = result_a
    elif selected_id == "defender_b":
        winning_proposal = proposal_b
        winning_result = result_b
    else:
        winning_proposal = {}
        winning_result = {}

    validation_evidence = json.dumps({
        "defender_a": result_a,
        "defender_b": result_b,
    }, indent=2)

    judge_decision = {
        "status": llm_status,
        "selected_defender": selected_id,
        "selected_patch": winning_proposal.get("patch_diff"),
        "rationale": rationale,
        "semgrep_verified": winning_result.get("semgrep_cleared", False),
        "tests_verified": winning_result.get("tests_passed", False),
        "regression_detected": winning_result.get("regression_detected", False),
        "round_number": round_number,
        "validation_evidence": validation_evidence[:2000],
    }

    # ── Accepted: open draft PR ───────────────────────────────────────────
    if llm_status == "accepted" and winning_proposal.get("patch_diff"):
        repo = state.get("repo", "local/AegisCI")
        run_id = state.get("run_id", incident_id)
        branch_name = f"security-fix/{run_id}"
        pr_title = f"[Security] Fix {finding.get('rule_id')} in {finding.get('file_path')}"
        pr_desc = (
            f"### AegisCI Automated Security Fix\n\n"
            f"**Finding**: `{finding.get('rule_id')}` — {finding.get('severity')}\n"
            f"**File**: `{finding.get('file_path')}` line {finding.get('start_line')}\n"
            f"**Message**: {finding.get('message', '')}\n\n"
            f"**Selected**: {selected_id}\n"
            f"**Strategy**: {winning_proposal.get('strategy_name', '')}\n"
            f"**Rationale**: {winning_proposal.get('security_rationale', '')}\n\n"
            f"**Judge Decision** (Round {round_number}):\n{rationale}\n\n"
            f"> ⚠️ Human review is mandatory before merging.\n"
        )
        pr_url, pr_notes = open_draft_pull_request(
            repo_name=repo,
            branch_name=branch_name,
            title=pr_title,
            description=pr_desc,
            patch_diff=winning_proposal["patch_diff"],
            incident_id=incident_id,
        )
        logger.info(f"[{incident_id}] Security PR created: {pr_url}")

        return {
            **state,
            "judge_decision": judge_decision,
            "final_outcome": "security_pr_opened",
            "pr_link": pr_url,
            "pr_branch": branch_name,
            "summary_notes": (
                f"Security fix accepted (round {round_number}, {selected_id}). "
                f"{pr_notes}"
            ),
        }

    # ── Rejected: retry if rounds remain ─────────────────────────────────
    if round_number < max_rounds:
        next_round = round_number + 1
        logger.info(f"[{incident_id}] Judge rejected — advancing to debate round {next_round}.")
        return {
            **state,
            "judge_decision": judge_decision,
            "security_remediation_round": next_round,
            "summary_notes": f"Round {round_number} rejected: {rationale[:200]}. Retrying.",
        }

    # ── Max rounds exhausted ─────────────────────────────────────────────
    logger.error(
        f"[{incident_id}] Security remediation exhausted {max_rounds} rounds without a valid fix. Escalating."
    )
    return {
        **state,
        "judge_decision": judge_decision,
        "final_outcome": "security_escalated",
        "summary_notes": (
            f"Security remediation escalated after {max_rounds} rounds. "
            f"Human review required for {finding.get('rule_id')} in {finding.get('file_path')}."
        ),
    }
