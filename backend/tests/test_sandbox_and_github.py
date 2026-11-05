"""
Unit tests for Docker Sandbox (and fallback) and GitHub PR Manager.
"""

import os
import shutil
import tempfile
import pytest

from backend.sandbox.docker_runner import DockerSandbox, SandboxResult, is_docker_available
from backend.github.pr_manager import check_gh_cli_status, create_remediation_pull_request


def test_is_docker_available_boolean():
    """Verify is_docker_available returns boolean without raising exceptions."""
    avail = is_docker_available()
    assert isinstance(avail, bool)


def test_docker_sandbox_process_fallback():
    """Verify DockerSandbox falls back cleanly to process execution when Docker is unavailable."""
    sandbox = DockerSandbox(default_timeout=15)
    temp_dir = tempfile.mkdtemp(prefix="aegis_test_sandbox_")
    try:
        res = sandbox._run_in_process(["python", "-c", "print('hello from sandbox')"], workspace_dir=temp_dir, timeout=15)
        assert res.passed
        assert "hello from sandbox" in res.stdout
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_docker_sandbox_timeout():
    """Verify timeout is enforced in sandbox."""
    sandbox = DockerSandbox(default_timeout=2)
    temp_dir = tempfile.mkdtemp(prefix="aegis_test_timeout_")
    try:
        res = sandbox._run_in_process(
            ["python", "-c", "import time; time.sleep(10)"],
            workspace_dir=temp_dir,
            timeout=2,
        )
        assert res.timed_out
        assert not res.passed
        assert res.exit_code == 124
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_docker_sandbox_sensitive_path_mount_rejected():
    """Verify Docker sandbox rejects mounting .env or secrets directory directly."""
    sandbox = DockerSandbox()
    res = sandbox._run_in_docker(
        command=["ls"],
        workspace_dir=os.path.abspath(".env"),
        timeout=10,
    )
    assert not res.passed
    assert "sensitive" in res.stderr.lower()


def test_gh_cli_status_check():
    """Verify check_gh_cli_status returns boolean and descriptive string."""
    is_auth, status_msg = check_gh_cli_status()
    assert isinstance(is_auth, bool)
    assert isinstance(status_msg, str)
    assert len(status_msg) > 0


def test_create_remediation_pull_request_local_fallback():
    """Verify PR creation prepares local branch when remote is unconfigured."""
    branch = "test-pr-safety-branch"
    patch = (
        "--- a/sample-app/calculator.py\n"
        "+++ b/sample-app/calculator.py\n"
        "@@ -10,1 +10,1 @@\n"
        "-    return a + b\n"
        "+    return a + b  # test comment\n"
    )
    url, notes = create_remediation_pull_request(
        repo_name="local/AegisCI",
        branch_name=branch,
        title="Test Fix",
        description="Test description",
        patch_diff=patch,
        incident_id="inc-test-pr-01",
    )
    assert url is not None
    assert "branch" in notes.lower()

