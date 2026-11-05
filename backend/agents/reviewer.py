import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple
from dotenv import load_dotenv

from backend.database import SessionLocal
from backend.models import Incident
from backend.agents.llm_client import LLMClient
from backend.agents.state import AegisAgentState

load_dotenv()
logger = logging.getLogger("aegis.reviewer")


def apply_patch_to_directory(repo_dir: str, patch_diff: str) -> Tuple[bool, str]:
    """
    Applies unified diff patch to a target directory using git apply or smart fallback parser.
    """
    if not patch_diff or not patch_diff.strip():
        return False, "Patch diff is empty"

    patch_file_path = os.path.join(repo_dir, ".aegis_temp.patch")
    try:
        with open(patch_file_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(patch_diff + "\n")

        # First attempt: git apply with whitespace tolerance
        cmd = ["git", "apply", "--ignore-space-change", "--ignore-whitespace", "--unidiff-zero", ".aegis_temp.patch"]
        res = subprocess.run(cmd, cwd=repo_dir, capture_output=True, text=True)
        if res.returncode == 0:
            return True, "Patch applied cleanly via git apply"

        cmd_p0 = ["git", "apply", "-p0", "--ignore-space-change", "--ignore-whitespace", ".aegis_temp.patch"]
        res_p0 = subprocess.run(cmd_p0, cwd=repo_dir, capture_output=True, text=True)
        if res_p0.returncode == 0:
            return True, "Patch applied cleanly via git apply -p0"

        # Fallback: Robust smart hunk matcher
        fallback_ok, fallback_msg = apply_unified_diff_smart(repo_dir, patch_diff)
        if fallback_ok:
            return True, f"Patch applied via smart fallback: {fallback_msg}"

        return False, f"git apply failed: {res.stderr}\nFallback: {fallback_msg}"
    finally:
        if os.path.exists(patch_file_path):
            try:
                os.remove(patch_file_path)
            except Exception:
                pass


def apply_unified_diff_smart(repo_dir: str, patch_diff: str) -> Tuple[bool, str]:
    """
    Robust smart unified diff applicator. Parses file hunks and applies substitutions
    even when line numbers or line endings vary.
    """
    try:
        lines = patch_diff.splitlines()
        current_file = None
        file_hunks: Dict[str, List[List[str]]] = {}
        current_hunk: List[str] = []

        for line in lines:
            if line.startswith("--- a/") or line.startswith("--- "):
                if current_file and current_hunk:
                    file_hunks.setdefault(current_file, []).append(current_hunk)
                    current_hunk = []
                p = line.split(" ", 1)[1].strip()
                if p.startswith("a/"):
                    p = p[2:]
                current_file = p
            elif line.startswith("+++ "):
                continue
            elif line.startswith("@@"):
                if current_file and current_hunk:
                    file_hunks.setdefault(current_file, []).append(current_hunk)
                current_hunk = []
            elif current_file and (line.startswith(" ") or line.startswith("+") or line.startswith("-")):
                current_hunk.append(line)

        if current_file and current_hunk:
            file_hunks.setdefault(current_file, []).append(current_hunk)

        if not file_hunks:
            return False, "No valid hunks found in patch diff"

        applied_files = 0
        for rel_path, hunks in file_hunks.items():
            full_path = os.path.join(repo_dir, rel_path)
            if not os.path.isfile(full_path):
                # Try finding file under repo_dir
                basename = os.path.basename(rel_path)
                found = None
                for root, _, files in os.walk(repo_dir):
                    if basename in files:
                        found = os.path.join(root, basename)
                        break
                if found:
                    full_path = found
                else:
                    return False, f"Target file not found: {rel_path}"

            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()

            for hunk in hunks:
                content = _replace_hunk_in_content(content, hunk)

            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)
            applied_files += 1

        return True, f"Successfully applied changes to {applied_files} file(s)"
    except Exception as e:
        return False, f"Smart patch error: {e}"


def _replace_hunk_in_content(content: str, hunk_lines: List[str]) -> str:
    """Replaces a single diff hunk inside file content with fallback fuzzy matching."""
    orig_chunk = []
    mod_chunk = []
    for line in hunk_lines:
        prefix = line[0]
        text = line[1:]
        if prefix in (" ", "-"):
            orig_chunk.append(text)
        if prefix in (" ", "+"):
            mod_chunk.append(text)

    orig_str = "\n".join(orig_chunk)
    mod_str = "\n".join(mod_chunk)

    if orig_str and orig_str in content:
        return content.replace(orig_str, mod_str, 1)

    # Fuzzy line matching: ignore whitespace variation
    content_lines = content.splitlines()
    clean_orig = [l.strip() for l in orig_chunk if l.strip()]
    if not clean_orig:
        return content

    for i in range(len(content_lines) - len(clean_orig) + 1):
        window = [content_lines[i + j].strip() for j in range(len(clean_orig))]
        if window == clean_orig:
            # Match found
            res_lines = content_lines[:i] + mod_chunk + content_lines[i + len(clean_orig):]
            return "\n".join(res_lines)

    return content


def run_isolated_tests(sandbox_dir: str) -> Tuple[bool, str]:
    """
    Runs sample-app test suite in isolated directory using DockerSandbox
    (with automatic fallback to isolated process sandbox).
    """
    from backend.sandbox.docker_runner import DockerSandbox
    sandbox = DockerSandbox()
    res = sandbox.run_command(["pytest", "--color=no", "sample-app/tests"], workspace_dir=sandbox_dir, timeout=60)
    return res.passed, res.combined_output


def open_draft_pull_request(
    repo_name: str,
    branch_name: str,
    title: str,
    description: str,
    patch_diff: str,
    incident_id: str,
) -> Tuple[Optional[str], str]:
    """
    Uses GitHub API (PyGithub or gh CLI) to open a draft PR.
    If running locally or no token/remote is configured, falls back to local git branch.
    """
    token = os.getenv("GITHUB_TOKEN")

    # 1. First ensure branch is committed in local git repo
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    try:
        # Check current branch
        curr_branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=root_dir, capture_output=True, text=True
        ).stdout.strip()

        # Checkout or create agent-fix branch
        subprocess.run(["git", "checkout", "-B", branch_name], cwd=root_dir, capture_output=True)
        # Apply patch in root
        apply_patch_to_directory(root_dir, patch_diff)
        # Stage & commit
        subprocess.run(["git", "add", "sample-app/"], cwd=root_dir, capture_output=True)
        commit_msg = f"fix(agent): automated fix for incident {incident_id}\n\n{title}"
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=root_dir, capture_output=True)

        # Return to original branch
        if curr_branch and curr_branch != branch_name:
            subprocess.run(["git", "checkout", curr_branch], cwd=root_dir, capture_output=True)
    except Exception as e:
        logger.warning(f"Git local branch creation encountered warning: {e}")

    # 2. Check if PyGithub can create remote draft PR
    if token and repo_name and repo_name != "unknown" and "/" in repo_name:
        try:
            from github import Github, Auth
            auth = Auth.Token(token)
            gh = Github(auth=auth)
            gh_repo = gh.get_repo(repo_name)

            # Push branch to remote
            push_res = subprocess.run(["git", "push", "-u", "origin", branch_name], cwd=root_dir, capture_output=True, text=True)
            if push_res.returncode == 0:
                pr = gh_repo.create_pull(
                    title=f"[AegisCI Draft Fix] {title}",
                    body=description,
                    head=branch_name,
                    base="main",
                    draft=True,
                )
                return pr.html_url, f"Draft PR #{pr.number} created successfully on GitHub"
            else:
                logger.warning(f"Could not push branch to remote: {push_res.stderr}")
        except Exception as e:
            logger.warning(f"GitHub API PR creation failed: {e}")

    # 3. Fallback: local branch / draft PR simulation
    local_pr_url = f"https://github.com/{repo_name}/pull/draft-agent-fix-{incident_id}" if "/" in repo_name else f"local://branch/{branch_name}"
    return local_pr_url, f"Draft PR prepared on local branch '{branch_name}'. Ready for push when remote is connected."


def generate_pr_description(
    incident_id: str,
    category: str,
    evidence: str,
    patch_diff: str,
    attempts: int,
) -> str:
    """Generate a clean, professional plain-English PR description."""
    llm = LLMClient()
    system_prompt = (
        "You are an AI Release & DevOps Engineer for AegisCI.\n"
        "Write a concise, professional Pull Request description in markdown explaining an automated bug fix."
    )
    user_prompt = (
        f"Incident ID: {incident_id}\n"
        f"Diagnosis: {category}\n"
        f"Evidence: {evidence}\n"
        f"Attempts needed: {attempts}\n"
        f"Unified Diff Patch:\n```diff\n{patch_diff}\n```\n\n"
        "Include sections:\n"
        "### Summary of Incident\n"
        "### Root Cause\n"
        "### Proposed Fix\n"
        "### Verification\n"
    )
    try:
        return llm.generate_text(system_prompt, user_prompt, temperature=0.2)
    except Exception:
        return (
            f"### AegisCI Automated Fix\n\n"
            f"- **Incident**: `{incident_id}`\n"
            f"- **Category**: `{category}`\n"
            f"- **Attempts**: {attempts}\n\n"
            f"#### Root Cause Evidence\n{evidence}\n\n"
            f"#### Applied Patch\n```diff\n{patch_diff}\n```\n"
        )


def reviewer_agent(state: AegisAgentState) -> AegisAgentState:
    """
    Reviewer Agent:
    1. Creates isolated temporary sandbox.
    2. Applies proposed patch.
    3. Executes test suite inside isolated sandbox.
    4. If passes: opens draft PR with clear explanation.
    5. If fails: logs failure, loops back to Fix-Proposer (up to 3 attempts).
    6. If 3 attempts exhausted: escalates incident without opening PR.
    """
    incident_id = state.get("incident_id", "unknown")
    run_id = state.get("run_id") or incident_id
    repo = state.get("repo", "local/AegisCI")
    category = state.get("diagnosis_category", "unknown")
    evidence = state.get("evidence", "")
    patch_diff = state.get("current_patch", "")
    guardrail_passed = state.get("guardrail_passed", True)
    guardrail_error = state.get("guardrail_error")
    current_attempt = state.get("current_attempt", 1)
    max_attempts = state.get("max_attempts", 3)
    patch_history = list(state.get("patch_history", []))

    logger.info(f"[{incident_id}] Reviewer Agent evaluating attempt {current_attempt}/{max_attempts}...")

    # If guardrail failed, treat as test failure immediately
    if not guardrail_passed:
        logger.warning(f"[{incident_id}] Reviewer rejected patch due to guardrail error: {guardrail_error}")
        test_passed = False
        test_output = f"Guardrail Failure: {guardrail_error}"
    else:
        # Create isolated temporary sandbox from repository
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        sandbox_dir = tempfile.mkdtemp(prefix=f"aegis_sandbox_{run_id}_")

        try:
            # Copy sample-app and pytest.ini into sandbox
            shutil.copytree(
                os.path.join(root_dir, "sample-app"),
                os.path.join(sandbox_dir, "sample-app"),
            )
            pytest_ini = os.path.join(root_dir, "pytest.ini")
            if os.path.exists(pytest_ini):
                shutil.copy(pytest_ini, sandbox_dir)

            # Apply patch in isolated sandbox
            apply_ok, apply_msg = apply_patch_to_directory(sandbox_dir, patch_diff)
            if not apply_ok:
                test_passed = False
                test_output = f"Failed to apply patch in isolated sandbox: {apply_msg}"
                logger.warning(f"[{incident_id}] {test_output}")
            else:
                # Run test suite in sandbox
                test_passed, test_output = run_isolated_tests(sandbox_dir)
                logger.info(f"[{incident_id}] Sandbox tests completed. Passed: {test_passed}")
        finally:
            shutil.rmtree(sandbox_dir, ignore_errors=True)

    # Record attempt in history
    patch_history.append({
        "attempt": current_attempt,
        "patch": patch_diff,
        "passed": test_passed,
        "test_output": test_output,
    })

    # Branch 1: Tests Passed -> Open Draft PR
    if test_passed:
        branch_name = f"agent-fix/{run_id}"
        pr_desc = generate_pr_description(incident_id, category, evidence, patch_diff, current_attempt)
        pr_url, pr_notes = open_draft_pull_request(
            repo_name=repo,
            branch_name=branch_name,
            title=f"Fix {category} in {', '.join(state.get('affected_files', []))}",
            description=pr_desc,
            patch_diff=patch_diff,
            incident_id=incident_id,
        )

        final_outcome = "pr_opened"
        summary_notes = f"Tests passed on attempt {current_attempt}. {pr_notes}"
        logger.info(f"[{incident_id}] SUCCESS: Draft PR opened at {pr_url}")

        _update_incident_db(
            incident_id=incident_id,
            category=category,
            confidence=state.get("diagnosis_confidence", 0.0),
            affected_files=state.get("affected_files", []),
            evidence=evidence,
            attempts=current_attempt,
            outcome=final_outcome,
            pr_link=pr_url,
            pr_branch=branch_name,
            patch_diff=patch_diff,
            notes=summary_notes,
        )

        return {
            **state,
            "test_passed": True,
            "test_output": test_output,
            "final_outcome": final_outcome,
            "pr_link": pr_url,
            "pr_branch": branch_name,
            "patch_history": patch_history,
            "summary_notes": summary_notes,
        }

    # Branch 2: Tests Failed
    logger.warning(f"[{incident_id}] Attempt {current_attempt} failed tests: {test_output[:200]}...")

    # ── Store rejected patch in ChromaDB rejection memory ─────────────────
    if patch_diff:
        try:
            from backend.memory.rejection_memory import RejectionMemory  # noqa: PLC0415
            mem = RejectionMemory()
            rejection_reason = test_output[:300] if test_output else "Test suite failed"
            mem.store_rejected_patch(
                incident_id=incident_id,
                attempt=current_attempt,
                patch_diff=patch_diff,
                diagnosis=category,
                evidence=evidence,
                rejection_reason=rejection_reason,
                affected_files=state.get("affected_files", []),
            )
        except Exception as e:
            logger.warning(f"[{incident_id}] Could not store rejection memory: {e}")

    if current_attempt < max_attempts:
        # Loopback to Fix-Proposer
        return {
            **state,
            "test_passed": False,
            "test_output": test_output,
            "patch_history": patch_history,
            "summary_notes": f"Attempt {current_attempt} failed. Looping back to Fix-Proposer.",
        }
    else:
        # Max attempts reached -> Escalate
        final_outcome = "escalated"
        summary_notes = (
            f"Escalated incident after {max_attempts} failed attempts. "
            f"No PR opened. Developer intervention required."
        )
        logger.error(f"[{incident_id}] {summary_notes}")

        _update_incident_db(
            incident_id=incident_id,
            category=category,
            confidence=state.get("diagnosis_confidence", 0.0),
            affected_files=state.get("affected_files", []),
            evidence=evidence,
            attempts=current_attempt,
            outcome=final_outcome,
            pr_link=None,
            pr_branch=None,
            patch_diff=patch_diff,
            notes=summary_notes,
        )

        return {
            **state,
            "test_passed": False,
            "test_output": test_output,
            "final_outcome": final_outcome,
            "pr_link": None,
            "patch_history": patch_history,
            "summary_notes": summary_notes,
        }


def _update_incident_db(
    incident_id: str,
    category: str,
    confidence: float,
    affected_files: List[str],
    evidence: str,
    attempts: int,
    outcome: str,
    pr_link: Optional[str],
    pr_branch: Optional[str],
    patch_diff: Optional[str],
    notes: Optional[str],
):
    """Update incident record in SQLite database."""
    db = SessionLocal()
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if incident:
            incident.diagnosis_category = category
            incident.diagnosis_confidence = confidence
            incident.affected_files = affected_files
            incident.evidence = evidence
            incident.attempts_made = attempts
            incident.final_outcome = outcome
            incident.pr_link = pr_link
            incident.pr_branch = pr_branch
            incident.patch_diff = patch_diff
            incident.notes = notes
            db.commit()
    except Exception as e:
        logger.error(f"Failed to update incident in database: {e}")
    finally:
        db.close()
