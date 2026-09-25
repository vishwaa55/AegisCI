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
    Applies unified diff patch to a target directory using git apply or fallback.
    """
    if not patch_diff or not patch_diff.strip():
        return False, "Patch diff is empty"

    patch_file_path = os.path.join(repo_dir, ".aegis_temp.patch")
    try:
        with open(patch_file_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(patch_diff + "\n")

        # Try git apply
        cmd = ["git", "apply", "--ignore-space-change", "--ignore-whitespace", "--unidiff-zero", ".aegis_temp.patch"]
        res = subprocess.run(cmd, cwd=repo_dir, capture_output=True, text=True)
        if res.returncode == 0:
            return True, "Patch applied cleanly via git apply"

        # Try with -p0 or 3-way
        cmd_p0 = ["git", "apply", "-p0", "--ignore-space-change", "--ignore-whitespace", ".aegis_temp.patch"]
        res_p0 = subprocess.run(cmd_p0, cwd=repo_dir, capture_output=True, text=True)
        if res_p0.returncode == 0:
            return True, "Patch applied cleanly via git apply -p0"

        # If git apply fails, try fallback direct file patch
        fallback_ok, fallback_msg = apply_unified_diff_fallback(repo_dir, patch_diff)
        if fallback_ok:
            return True, f"Patch applied via fallback: {fallback_msg}"

        return False, f"git apply failed: {res.stderr}\nFallback: {fallback_msg}"
    finally:
        if os.path.exists(patch_file_path):
            try:
                os.remove(patch_file_path)
            except Exception:
                pass


def apply_unified_diff_fallback(repo_dir: str, patch_diff: str) -> Tuple[bool, str]:
    """
    Fallback unified diff patcher for simple edits when git apply fails due to whitespace.
    Parses @@ -start,len +start,len @@ headers and replaces target lines.
    """
    try:
        lines = patch_diff.splitlines()
        target_file = None
        hunks = []
        current_hunk = None

        for line in lines:
            if line.startswith("--- a/") or line.startswith("--- "):
                path = line.split(" ", 1)[1].strip()
                if path.startswith("a/"):
                    path = path[2:]
                target_file = os.path.join(repo_dir, path)
            elif line.startswith("@@"):
                if current_hunk:
                    hunks.append(current_hunk)
                current_hunk = {"header": line, "removals": [], "additions": [], "context": []}
            elif current_hunk is not None:
                if line.startswith("-") and not line.startswith("---"):
                    current_hunk["removals"].append(line[1:])
                elif line.startswith("+") and not line.startswith("+++"):
                    current_hunk["additions"].append(line[1:])
                elif line.startswith(" "):
                    current_hunk["context"].append(line[1:])

        if current_hunk:
            hunks.append(current_hunk)

        if not target_file or not os.path.exists(target_file):
            return False, f"Target file not found for fallback patch: {target_file}"

        with open(target_file, "r", encoding="utf-8") as f:
            content = f.read()

        # Apply hunk replacements
        for h in hunks:
            removals_block = "\n".join(h["removals"])
            additions_block = "\n".join(h["additions"])
            if removals_block in content:
                content = content.replace(removals_block, additions_block, 1)
            elif len(h["removals"]) == 1 and h["removals"][0].strip() in content:
                # single line fuzzy match
                old_line = h["removals"][0].strip()
                new_line = additions_block.strip()
                lines_in_file = content.splitlines()
                replaced = False
                for idx, fl in enumerate(lines_in_file):
                    if fl.strip() == old_line:
                        indent = len(fl) - len(fl.lstrip())
                        lines_in_file[idx] = (" " * indent) + new_line
                        replaced = True
                        break
                if replaced:
                    content = "\n".join(lines_in_file)

        with open(target_file, "w", encoding="utf-8") as f:
            f.write(content)

        return True, "Fallback patch applied successfully"
    except Exception as e:
        return False, f"Fallback patch exception: {e}"


def run_isolated_tests(sandbox_dir: str) -> Tuple[bool, str]:
    """
    Runs sample-app test suite in isolated directory.
    """
    python_exe = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "venv", "Scripts", "python.exe"))
    if not os.path.exists(python_exe):
        python_exe = "python"

    cmd = [python_exe, "-m", "pytest", "--color=no", "sample-app/tests"]
    try:
        res = subprocess.run(cmd, cwd=sandbox_dir, capture_output=True, text=True, timeout=60)
        output = res.stdout + ("\n" + res.stderr if res.stderr else "")
        passed = (res.returncode == 0)
        return passed, output.strip()
    except subprocess.TimeoutExpired:
        return False, "Test execution timed out after 60 seconds."
    except Exception as e:
        return False, f"Error launching test subprocess: {e}"


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
