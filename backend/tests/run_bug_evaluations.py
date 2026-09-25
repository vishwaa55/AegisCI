"""
Comprehensive Live Bug Evaluation Suite for AegisCI.
Tests the 4 required scenarios:
1. Missing null check (AttributeError when user is None)
2. Wrong comparison operator (wrong discount calculation / operator)
3. Missing dependency (ImportError / ModuleNotFoundError)
4. Escalation (unfixable error reaching max attempts without opening PR)
"""

import os
import shutil
import subprocess
import time
from backend.agents.graph import aegis_graph
from backend.agents.state import AegisAgentState
from backend.database import SessionLocal
from backend.models import Incident


def run_local_pytest() -> str:
    """Run pytest on sample-app and return the combined stdout/stderr."""
    python_exe = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "venv", "Scripts", "python.exe"))
    if not os.path.exists(python_exe):
        python_exe = "python"

    res = subprocess.run([python_exe, "-m", "pytest", "sample-app/tests"], capture_output=True, text=True)
    return res.stdout + ("\n" + res.stderr if res.stderr else "")


def execute_pipeline(scenario_name: str, raw_logs: str, max_attempts: int = 3) -> dict:
    print(f"\n======================================================================")
    print(f"[RUN] Starting Evaluation Scenario: {scenario_name}")
    print(f"======================================================================")

    incident_id = f"inc-{scenario_name.lower().replace(' ', '-')}-{int(time.time())}"
    run_id = f"run-{int(time.time())}"

    initial_state: AegisAgentState = {
        "incident_id": incident_id,
        "repo": "vishwaa55/AegisCI",
        "commit_sha": f"sha-{incident_id[:10]}",
        "branch": "main",
        "run_id": run_id,
        "raw_logs": raw_logs,
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
        "current_attempt": 0,
        "max_attempts": max_attempts,
        "patch_history": [],
        "test_passed": False,
        "test_output": "",
        "final_outcome": "processing",
        "pr_link": None,
        "pr_branch": None,
        "summary_notes": "",
    }

    # Record initial incident in SQLite database
    db = SessionLocal()
    inc = Incident(
        id=incident_id,
        repo=initial_state["repo"],
        commit_sha=initial_state["commit_sha"],
        branch=initial_state["branch"],
        run_id=initial_state["run_id"],
        raw_logs=raw_logs,
        final_outcome="processing",
    )
    db.merge(inc)
    db.commit()
    db.close()

    # Invoke LangGraph agent chain
    final_state = aegis_graph.invoke(initial_state)

    print(f"--- Results for {scenario_name} ---")
    print(f"Diagnosis Category   : {final_state.get('diagnosis_category')}")
    print(f"Diagnosis Confidence : {final_state.get('diagnosis_confidence')}")
    print(f"Affected Files       : {final_state.get('affected_files')}")
    print(f"Evidence             : {final_state.get('evidence')[:100]}...")
    print(f"Attempts Made        : {final_state.get('current_attempt')}")
    print(f"Final Outcome        : {final_state.get('final_outcome')}")
    print(f"PR Link              : {final_state.get('pr_link')}")
    print(f"Summary Notes        : {final_state.get('summary_notes')}")

    return final_state


def evaluate_bug_1_missing_null_check():
    """
    Bug 1: Missing null check.
    Injects missing null check into process_user_data in sample-app/calculator.py,
    runs pytest to capture real failure, passes to AegisCI, and restores file.
    """
    calc_path = os.path.join("sample-app", "calculator.py")
    with open(calc_path, "r", encoding="utf-8") as f:
        original = f.read()

    try:
        # Inject bug: remove the null check
        buggy = original.replace(
            '    if user is None:\n        return "Guest"\n',
            '    # BUG: missing null check\n',
        )
        with open(calc_path, "w", encoding="utf-8") as f:
            f.write(buggy)

        # Run pytest to produce real CI failure log
        failure_log = run_local_pytest()
        assert "AttributeError" in failure_log or "FAILED" in failure_log

        # Run through AegisCI multi-agent chain
        res = execute_pipeline("Bug 1: Missing Null Check", failure_log)
        assert res.get("diagnosis_category") in ["test_assertion_failure", "dependency_error", "lint_error"]
        assert res.get("final_outcome") == "pr_opened"
        assert res.get("pr_link") is not None
        print(f"[PASSED] Bug 1 successfully diagnosed, patched in sandbox, and PR created.")
        return res
    finally:
        with open(calc_path, "w", encoding="utf-8") as f:
            f.write(original)


def evaluate_bug_2_wrong_operator():
    """
    Bug 2: Wrong comparison operator or arithmetic bug.
    Injects wrong operator into calculate_discount in sample-app/calculator.py,
    runs pytest to capture real failure, passes to AegisCI, and restores file.
    """
    calc_path = os.path.join("sample-app", "calculator.py")
    with open(calc_path, "r", encoding="utf-8") as f:
        original = f.read()

    try:
        # Inject bug: price + discount_amount instead of price - discount_amount
        buggy = original.replace(
            "return round(price - discount_amount, 2)",
            "return round(price + discount_amount, 2)",
        )
        with open(calc_path, "w", encoding="utf-8") as f:
            f.write(buggy)

        # Run pytest to produce real CI failure log
        failure_log = run_local_pytest()
        assert "AssertionError" in failure_log or "FAILED" in failure_log

        # Run through AegisCI multi-agent chain
        res = execute_pipeline("Bug 2: Wrong Comparison Operator", failure_log)
        assert res.get("diagnosis_category") == "test_assertion_failure"
        assert res.get("final_outcome") == "pr_opened"
        assert res.get("pr_link") is not None
        print(f"[PASSED] Bug 2 successfully diagnosed, patched in sandbox, and PR created.")
        return res
    finally:
        with open(calc_path, "w", encoding="utf-8") as f:
            f.write(original)


def evaluate_bug_3_missing_dependency():
    """
    Bug 3: Missing dependency / ModuleNotFoundError.
    Injects missing import into sample-app/calculator.py,
    runs pytest to capture real failure, passes to AegisCI, and restores file.
    """
    calc_path = os.path.join("sample-app", "calculator.py")
    with open(calc_path, "r", encoding="utf-8") as f:
        original = f.read()

    try:
        # Inject missing dependency import
        buggy = "import non_existent_telemetry_client\n" + original
        with open(calc_path, "w", encoding="utf-8") as f:
            f.write(buggy)

        failure_log = run_local_pytest()
        assert "ModuleNotFoundError" in failure_log or "ERROR" in failure_log

        res = execute_pipeline("Bug 3: Missing Dependency", failure_log)
        assert res.get("diagnosis_category") == "dependency_error"
        print(f"[PASSED] Bug 3 successfully diagnosed as dependency_error with evidence.")
        return res
    finally:
        with open(calc_path, "w", encoding="utf-8") as f:
            f.write(original)


def evaluate_bug_4_escalation():
    """
    Bug 4: Escalation scenario.
    We inject a bug where the LLM proposes a patch touching sample-app/calculator.py
    but the broken test references a non-existent function — so sandbox tests will always
    fail (NameError). The patch cannot pass review regardless of what the LLM proposes,
    ensuring the reviewer loops up to max_attempts and then escalates.
    """
    test_path = os.path.join("sample-app", "tests", "test_calculator.py")
    with open(test_path, "r", encoding="utf-8") as f:
        orig_test = f.read()

    try:
        # Inject a test that calls a function that doesn't exist in calculator.py
        impossible_test = (
            orig_test
            + "\n\ndef test_missing_function_always_fails():\n"
            + "    # This function does not exist and cannot be added (guardrail blocks test file changes)\n"
            + "    result = compute_advanced_metric(42, 7)\n"
            + "    assert result == 6\n"
        )
        with open(test_path, "w", encoding="utf-8") as f:
            f.write(impossible_test)

        failure_log = run_local_pytest()
        assert "NameError" in failure_log or "FAILED" in failure_log or "ERROR" in failure_log

        # Force affected_files to calculator.py only, so test-file patches are guardrail-blocked
        print(f"\n======================================================================")
        print(f"[RUN] Starting Evaluation Scenario: Bug 4: Escalation After Max Attempts")
        print(f"======================================================================")

        import uuid, time
        from backend.agents.state import AegisAgentState
        from backend.agents.graph import aegis_graph
        from backend.database import SessionLocal
        from backend.models import Incident

        incident_id = f"inc-bug-4-esc-{int(time.time())}"
        initial_state: AegisAgentState = {
            "incident_id": incident_id,
            "repo": "vishwaa55/AegisCI",
            "commit_sha": f"sha-{incident_id[:10]}",
            "branch": "main",
            "run_id": f"run-{int(time.time())}",
            "raw_logs": failure_log,
            "cleaned_logs": "",
            "is_flaky_ignored": False,
            "flaky_reason": None,
            "diagnosis_category": None,
            "diagnosis_confidence": 0.0,
            # Force affected_files to source only — any test-file patch will be guardrail-blocked
            "affected_files": ["sample-app/calculator.py"],
            "evidence": "NameError: compute_advanced_metric not defined — function missing from source",
            "current_patch": None,
            "guardrail_passed": True,
            "guardrail_error": None,
            "current_attempt": 0,
            "max_attempts": 2,
            "patch_history": [],
            "test_passed": False,
            "test_output": "",
            "final_outcome": "processing",
            "pr_link": None,
            "pr_branch": None,
            "summary_notes": "",
        }

        db = SessionLocal()
        inc = Incident(
            id=incident_id,
            repo=initial_state["repo"],
            commit_sha=initial_state["commit_sha"],
            branch=initial_state["branch"],
            run_id=initial_state["run_id"],
            raw_logs=failure_log,
            final_outcome="processing",
        )
        db.merge(inc)
        db.commit()
        db.close()

        res = aegis_graph.invoke(initial_state)

        print(f"--- Results for Bug 4: Escalation After Max Attempts ---")
        print(f"Diagnosis Category   : {res.get('diagnosis_category')}")
        print(f"Diagnosis Confidence : {res.get('diagnosis_confidence')}")
        print(f"Affected Files       : {res.get('affected_files')}")
        print(f"Attempts Made        : {res.get('current_attempt')}")
        print(f"Final Outcome        : {res.get('final_outcome')}")
        print(f"PR Link              : {res.get('pr_link')}")
        print(f"Summary Notes        : {res.get('summary_notes')}")

        assert res.get("final_outcome") == "escalated", f"Expected 'escalated', got '{res.get('final_outcome')}'"
        assert res.get("pr_link") is None
        print(f"[PASSED] Bug 4 successfully exhausted attempts and escalated without opening PR.")
        return res
    finally:
        with open(test_path, "w", encoding="utf-8") as f:
            f.write(orig_test)


if __name__ == "__main__":
    print("==================================================================")
    print("      AegisCI End-to-End Bug Scenarios Evaluation Suite          ")
    print("==================================================================")

    res1 = evaluate_bug_1_missing_null_check()
    res2 = evaluate_bug_2_wrong_operator()
    res3 = evaluate_bug_3_missing_dependency()
    res4 = evaluate_bug_4_escalation()

    print("\n[SUCCESS] ALL 4 BUG SCENARIOS EVALUATED AND PASSED END-TO-END!")
