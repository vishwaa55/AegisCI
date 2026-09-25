from typing import Any, Dict, List, Optional
from typing_extensions import TypedDict


class AegisAgentState(TypedDict):
    """
    LangGraph State representation passed across AegisCI agents.
    """
    # Incident Identification
    incident_id: str
    repo: str
    commit_sha: str
    branch: str
    run_id: str
    
    # Input logs
    raw_logs: str
    cleaned_logs: str
    
    # Agent 1: Build-Monitor Triage
    is_flaky_ignored: bool
    flaky_reason: Optional[str]
    
    # Agent 2: Diagnosis
    diagnosis_category: Optional[str]  # dependency_error, test_assertion_failure, flaky_test, lint_error
    diagnosis_confidence: float
    affected_files: List[str]
    evidence: str
    
    # Agent 3: Fix-Proposer
    current_patch: Optional[str]
    guardrail_passed: bool
    guardrail_error: Optional[str]
    
    # Agent 4: Reviewer & Execution Sandbox
    current_attempt: int
    max_attempts: int
    patch_history: List[Dict[str, Any]]
    test_passed: bool
    test_output: str
    
    # Final Result
    final_outcome: str  # pending, pr_opened, escalated, ignored_flaky
    pr_link: Optional[str]
    pr_branch: Optional[str]
    summary_notes: str
