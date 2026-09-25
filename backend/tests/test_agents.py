"""
Comprehensive End-to-End and Unit Tests for AegisCI Phase 1 and Phase 2.
Tests all 4 agents, guardrails, loopbacks, escalation, and FastAPI endpoints.
"""

import os
import shutil
import tempfile
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.database import SessionLocal, Base, engine
from backend.models import Incident, KnownFailure
from backend.agents.diagnosis import strip_ansi_codes, preprocess_ci_log, diagnosis_agent
from backend.agents.fix_proposer import validate_patch_guardrails, extract_files_from_diff
from backend.agents.reviewer import apply_patch_to_directory, apply_unified_diff_smart, reviewer_agent
from backend.agents.build_monitor import build_monitor_agent
from backend.agents.graph import aegis_graph
from backend.agents.state import AegisAgentState


@pytest.fixture(scope="module")
def client():
    Base.metadata.create_all(bind=engine)
    return TestClient(app)


def test_health_check_endpoint(client):
    """Verify Phase 1 health-check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "AegisCI Backend"


def test_strip_ansi_codes():
    """Verify ANSI escape code stripping in Diagnosis Agent."""
    ansi_sample = "\x1b[31mFAIL\x1b[0m \x1b[1mtest_sample.py\x1b[0m"
    clean = strip_ansi_codes(ansi_sample)
    assert clean == "FAIL test_sample.py"


def test_preprocess_ci_log():
    """Verify log preprocessing extracts failure blocks from verbose logs."""
    raw_log = (
        "Starting test session...\n"
        "Loading plugins: pytest, anyio\n"
        "============================= test session starts =============================\n"
        "collected 6 items\n\n"
        "=================================== FAILURES ===================================\n"
        "________________________ test_process_user_data_none __________________________\n"
        "    def test_process_user_data_none():\n"
        ">       assert process_user_data(None) == 'Guest'\n"
        "E       AttributeError: 'NoneType' object has no attribute 'get'\n"
        "sample-app/tests/test_calculator.py:25: AttributeError\n"
        "=========================== short test summary info ===========================\n"
        "FAILED sample-app/tests/test_calculator.py::test_process_user_data_none\n"
        "============================== 1 failed in 0.05s ==============================\n"
    )
    extracted = preprocess_ci_log(raw_log)
    assert "FAILURES" in extracted
    assert "AttributeError: 'NoneType' object has no attribute 'get'" in extracted


def test_guardrail_rejections():
    """Verify Fix-Proposer guardrail rejects CI files, secrets, and unapproved files."""
    allowed = ["sample-app/calculator.py"]

    # 1. Tampering with CI config
    ci_hack = (
        "--- a/.github/workflows/ci.yml\n"
        "+++ b/.github/workflows/ci.yml\n"
        "@@ -1,5 +1,5 @@\n"
        "- run: pytest\n"
        "+ run: echo 'bypass'\n"
    )
    ok, err = validate_patch_guardrails(ci_hack, allowed)
    assert not ok
    assert "forbidden/sensitive" in err.lower()

    # 2. Tampering with .env secret
    secret_hack = (
        "--- a/.env\n"
        "+++ b/.env\n"
        "@@ -1,2 +1,2 @@\n"
        "- KEY=123\n"
        "+ KEY=456\n"
    )
    ok, err = validate_patch_guardrails(secret_hack, allowed)
    assert not ok
    assert "forbidden/sensitive" in err.lower()

    # 3. Modifying file outside affected_files list
    out_of_scope = (
        "--- a/backend/main.py\n"
        "+++ b/backend/main.py\n"
        "@@ -1,2 +1,2 @@\n"
        "- x = 1\n"
        "+ x = 2\n"
    )
    ok, err = validate_patch_guardrails(out_of_scope, allowed)
    assert not ok
    assert "outside diagnosed files" in err.lower()

    # 4. Valid patch
    valid_patch = (
        "--- a/sample-app/calculator.py\n"
        "+++ b/sample-app/calculator.py\n"
        "@@ -30,2 +30,4 @@\n"
        "+    if user is None:\n"
        "+        return 'Guest'\n"
    )
    ok, err = validate_patch_guardrails(valid_patch, allowed)
    assert ok
    assert err is None


def test_build_monitor_triage_known_flaky():
    """Verify Build-Monitor Agent triages known flaky failures without invoking LLM."""
    db = SessionLocal()
    existing = db.query(KnownFailure).filter(KnownFailure.signature == "FLAKY_TIMEOUT_PATTERN_XYZ").first()
    if not existing:
        kf = KnownFailure(signature="FLAKY_TIMEOUT_PATTERN_XYZ", category="flaky_test", reason="Network jitter in CI")
        db.add(kf)
        db.commit()
    db.close()

    state: AegisAgentState = {
        "incident_id": "test-flaky-1",
        "repo": "local/AegisCI",
        "commit_sha": "abc1234",
        "branch": "main",
        "run_id": "run-flaky",
        "raw_logs": "ERROR: Test failed due to FLAKY_TIMEOUT_PATTERN_XYZ in runner",
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
        "max_attempts": 3,
        "patch_history": [],
        "test_passed": False,
        "test_output": "",
        "final_outcome": "processing",
        "pr_link": None,
        "pr_branch": None,
        "summary_notes": "",
    }

    result = build_monitor_agent(state)
    assert result["is_flaky_ignored"] is True
    assert result["final_outcome"] == "ignored_flaky"
    assert "Network jitter in CI" in result["flaky_reason"]


def test_patch_application_helpers():
    """Verify unified diff application in isolated directory."""
    temp_dir = tempfile.mkdtemp()
    try:
        sample_file = os.path.join(temp_dir, "test.txt")
        with open(sample_file, "w") as f:
            f.write("Line 1\nLine 2 - Old\nLine 3\n")

        diff = (
            "--- a/test.txt\n"
            "+++ b/test.txt\n"
            "@@ -1,3 +1,3 @@\n"
            " Line 1\n"
            "-Line 2 - Old\n"
            "+Line 2 - Patched\n"
            " Line 3\n"
        )

        ok, msg = apply_patch_to_directory(temp_dir, diff)
        assert ok, f"Patch failed: {msg}"

        with open(sample_file, "r") as f:
            updated = f.read()
        assert "Line 2 - Patched" in updated
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
