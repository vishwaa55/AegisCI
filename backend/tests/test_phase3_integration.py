"""
Phase 3 Integration and Webhook Tests for AegisCI.
Covers:
- Secret scrubbing from logs and strings
- Unified /ci/results endpoint
- Webhook secret authentication (X-Aegis-Secret header)
- Idempotency & duplicate-event suppression
- Ingest CI artifact tool helpers
- Experiment evaluation schema
"""

import json
import os
import tempfile
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.database import Base, engine, SessionLocal
from backend.models import Incident
from backend.utils.scrubber import scrub_secrets
from backend.ingest_ci_artifact import load_payload_from_file, load_payload_from_zip
from experiments.evaluation_schema import ExperimentRecord


@pytest.fixture(scope="module")
def client():
    Base.metadata.create_all(bind=engine)
    return TestClient(app)


# ---------------------------------------------------------------------------
# Secret Scrubber Tests
# ---------------------------------------------------------------------------

def test_scrub_secrets_github_token():
    log = "Error during push with token ghp_ABCdef1234567890ABCdef12345678901234 to repo"
    scrubbed = scrub_secrets(log)
    assert "ghp_" not in scrubbed
    assert "[REDACTED_SECRET]" in scrubbed


def test_scrub_secrets_openai_key():
    log = "OpenAI API request failed with key sk-proj-1234567890abcdef1234567890"
    scrubbed = scrub_secrets(log)
    assert "sk-proj-" not in scrubbed
    assert "[REDACTED_SECRET]" in scrubbed


def test_scrub_secrets_groq_key():
    log = "Groq authorization header: gsk_1234567890abcdef1234567890abcdef123456789012"
    scrubbed = scrub_secrets(log)
    assert "gsk_" not in scrubbed
    assert "[REDACTED_SECRET]" in scrubbed


def test_scrub_secrets_bearer_and_password():
    log = "Authorization: Bearer my_secret_bearer_token_xyz_12345 and password='super_secret_db_pass'"
    scrubbed = scrub_secrets(log)
    assert "super_secret_db_pass" not in scrubbed
    assert "[REDACTED_SECRET]" in scrubbed


# ---------------------------------------------------------------------------
# Unified /ci/results Endpoint Tests
# ---------------------------------------------------------------------------

def test_ci_results_succeeded_run_no_action(client):
    """When a CI run passes with 0 findings, returns no_action_required."""
    payload = {
        "repo": "vishwaa55/AegisCI",
        "commit_sha": f"sha-{uuid.uuid4().hex[:6]}",
        "branch": "main",
        "run_id": f"run-pass-{uuid.uuid4().hex[:6]}",
        "event_name": "push",
        "test_passed": True,
        "test_exit_code": 0,
        "logs": "6 passed in 0.1s",
        "semgrep_json": {"results": [], "errors": []},
    }
    response = client.post("/ci/results", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "no_action_required"
    assert data["duplicate"] is False


def test_ci_results_functional_failure_dispatch(client, monkeypatch):
    """When a CI run has test failures, triggers functional repair pipeline."""
    # Mock background runner to avoid waiting for live LLM in unit test
    monkeypatch.setattr("backend.main.run_agent_workflow_background", lambda state: None)

    sha = f"sha-{uuid.uuid4().hex[:6]}"
    run_id = f"run-fail-{uuid.uuid4().hex[:6]}"
    payload = {
        "repo": "vishwaa55/AegisCI",
        "commit_sha": sha,
        "branch": "main",
        "run_id": run_id,
        "event_name": "push",
        "test_passed": False,
        "test_exit_code": 1,
        "logs": "FAILED sample-app/tests/test_calculator.py - AssertionError: 42 != 43",
    }
    response = client.post("/ci/results", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "remediation_triggered"
    assert data["functional_incident_id"] is not None
    assert data["duplicate"] is False


def test_ci_results_duplicate_suppression(client, monkeypatch):
    """Submitting the exact same run_id and commit_sha returns already_processed."""
    monkeypatch.setattr("backend.main.run_agent_workflow_background", lambda state: None)

    sha = f"sha-{uuid.uuid4().hex[:6]}"
    run_id = f"run-dup-{uuid.uuid4().hex[:6]}"
    payload = {
        "repo": "vishwaa55/AegisCI",
        "commit_sha": sha,
        "branch": "main",
        "run_id": run_id,
        "event_name": "push",
        "test_passed": False,
        "test_exit_code": 1,
        "logs": "FAILED sample-app/tests/test_calculator.py - AssertionError: 42 != 43",
    }
    # First invocation
    r1 = client.post("/ci/results", json=payload)
    assert r1.status_code == 200
    assert r1.json()["status"] == "remediation_triggered"

    # Second invocation with same run_id and commit_sha
    r2 = client.post("/ci/results", json=payload)
    assert r2.status_code == 200
    data = r2.json()
    assert data["status"] == "already_processed"
    assert data["duplicate"] is True


def test_ci_results_webhook_secret_auth(client, monkeypatch):
    """When AEGIS_WEBHOOK_SECRET is set, requests without valid header are rejected with 401."""
    monkeypatch.setenv("AEGIS_WEBHOOK_SECRET", "super-secret-token-12345")

    payload = {
        "repo": "vishwaa55/AegisCI",
        "commit_sha": f"sha-{uuid.uuid4().hex[:6]}",
        "branch": "main",
        "run_id": f"run-auth-{uuid.uuid4().hex[:6]}",
        "test_passed": True,
    }

    # 1. Missing header -> 401
    res_no_header = client.post("/ci/results", json=payload)
    assert res_no_header.status_code == 401

    # 2. Invalid header -> 401
    res_wrong_header = client.post(
        "/ci/results",
        json=payload,
        headers={"X-Aegis-Secret": "wrong-token"},
    )
    assert res_wrong_header.status_code == 401

    # 3. Correct header -> 200
    res_valid = client.post(
        "/ci/results",
        json=payload,
        headers={"X-Aegis-Secret": "super-secret-token-12345"},
    )
    assert res_valid.status_code == 200
    res_no_header = client.post("/ci/results", json=payload)
    assert res_no_header.status_code == 401

    # 2. Invalid header -> 401
    res_wrong_header = client.post(
        "/ci/results",
        json=payload,
        headers={"X-Aegis-Secret": "wrong-token"},
    )
    assert res_wrong_header.status_code == 401

    # 3. Correct header -> 200
    res_valid = client.post(
        "/ci/results",
        json=payload,
        headers={"X-Aegis-Secret": "super-secret-token-12345"},
    )
    assert res_valid.status_code == 200


# ---------------------------------------------------------------------------
# Ingestion Tool & Evaluation Schema Tests
# ---------------------------------------------------------------------------

def test_load_payload_from_file():
    """Verify loading JSON results payload from file."""
    data = {"repo": "test/repo", "run_id": "run-10", "test_passed": False}
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as f:
        json.dump(data, f)
        temp_name = f.name

    try:
        loaded = load_payload_from_file(temp_name)
        assert loaded["run_id"] == "run-10"
        assert loaded["test_passed"] is False
    finally:
        os.remove(temp_name)


def test_experiment_record_schema():
    """Verify ExperimentRecord data model and scorecard calculation."""
    record = ExperimentRecord(
        experiment_id="exp-001",
        scenario_type="functional",
        scenario_name="Missing Null Check",
        duration_seconds=12.4,
        attempts_made=1,
        max_attempts=3,
        final_outcome="pr_opened",
        expected_category="test_assertion_failure",
        diagnosed_category="test_assertion_failure",
        diagnosis_accurate=True,
        tests_passed=True,
        pr_created=True,
    )
    scorecard = record.summary()
    assert scorecard["experiment"] == "Missing Null Check"
    assert scorecard["diagnosis_match"] is True
    assert scorecard["success"] is True
    assert scorecard["attempts"] == "1/3"
