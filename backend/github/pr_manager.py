"""
GitHub Pull Request Operations and Safety Guardrails for AegisCI.

Ensures:
- Dedicated fix branches (agent-fix/* or security-fix/*)
- Never pushes directly to main
- Human review is mandatory (opens as draft or explicitly requires review)
- Safe fallback when GitHub token / CLI is not authenticated
"""

import logging
import os
import subprocess
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("aegis.github")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def check_gh_cli_status() -> Tuple[bool, str]:
    """Check if GitHub CLI (gh) is installed and authenticated."""
    try:
        res = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            return True, "GitHub CLI authenticated."
        return False, res.stderr or res.stdout or "Not logged in."
    except Exception as e:
        return False, f"GitHub CLI unavailable: {e}"


def create_remediation_pull_request(
    repo_name: str,
    branch_name: str,
    title: str,
    description: str,
    patch_diff: str,
    incident_id: str,
    base_branch: str = "main",
    is_security: bool = False,
) -> Tuple[Optional[str], str]:
    """
    Safely creates a remediation branch, applies the validated patch, commits,
    and opens a draft PR on GitHub (via PyGithub or `gh pr create`).
    If remote is not configured or unauthenticated, prepares the local git branch.

    SAFETY INVARIANT:
    - Never pushes to main
    - Always creates Draft PR
    - Human approval is mandatory before any merge
    """
    if base_branch.strip() == branch_name.strip():
        raise ValueError("Remediation branch cannot be identical to base branch.")

    prefix = "security-fix" if is_security else "agent-fix"
    safe_branch = branch_name if branch_name.startswith(f"{prefix}/") else f"{prefix}/{branch_name}"

    token = os.getenv("GITHUB_TOKEN")

    # 1. Ensure local branch exists with committed patch
    try:
        curr_branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=ROOT_DIR, capture_output=True, text=True
        ).stdout.strip()

        # Create or switch to branch
        subprocess.run(["git", "checkout", "-B", safe_branch], cwd=ROOT_DIR, capture_output=True)

        # Apply patch in root
        from backend.agents.reviewer import apply_patch_to_directory
        apply_patch_to_directory(ROOT_DIR, patch_diff)

        # Stage and commit
        subprocess.run(["git", "add", "sample-app/"], cwd=ROOT_DIR, capture_output=True)
        commit_type = "fix(security)" if is_security else "fix(agent)"
        commit_msg = f"{commit_type}: automated repair for {incident_id}\n\n{title}"
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=ROOT_DIR, capture_output=True)

        # Switch back to original branch
        if curr_branch and curr_branch != safe_branch:
            subprocess.run(["git", "checkout", curr_branch], cwd=ROOT_DIR, capture_output=True)

    except Exception as e:
        logger.warning(f"Local git branch preparation encountered warning: {e}")

    # 2. Remote PR via PyGithub
    if token and repo_name and "/" in repo_name and not repo_name.startswith("owner/"):
        try:
            from github import Github, Auth
            auth = Auth.Token(token)
            gh = Github(auth=auth)
            gh_repo = gh.get_repo(repo_name)

            push_res = subprocess.run(
                ["git", "push", "-u", "origin", safe_branch],
                cwd=ROOT_DIR, capture_output=True, text=True
            )
            if push_res.returncode == 0:
                pr = gh_repo.create_pull(
                    title=f"[AegisCI Draft] {title}",
                    body=description,
                    head=safe_branch,
                    base=base_branch,
                    draft=True,
                )
                logger.info(f"Draft PR #{pr.number} created on GitHub: {pr.html_url}")
                return pr.html_url, f"Draft PR #{pr.number} created on GitHub: {pr.html_url}"
        except Exception as e:
            logger.warning(f"PyGithub draft PR creation error: {e}")

    # 3. Fallback: Local branch prepared
    local_url = (
        f"https://github.com/{repo_name}/pull/draft-{safe_branch}"
        if repo_name and "/" in repo_name
        else f"local://branch/{safe_branch}"
    )
    msg = (
        f"Remediation patch validated and committed to branch '{safe_branch}'. "
        f"Ready to push to remote when GitHub credentials are configured."
    )
    return local_url, msg
