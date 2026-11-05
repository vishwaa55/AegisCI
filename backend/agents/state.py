from typing import Any, Dict, List, Optional
from typing_extensions import TypedDict


class AegisAgentState(TypedDict):
    """
    LangGraph State representation passed across AegisCI agents.
    Covers both the functional CI-repair workflow and the security-debate workflow.
    """
    # ── Incident Identification ──────────────────────────────────────────────
    incident_id: str
    repo: str
    commit_sha: str
    branch: str
    run_id: str

    # ── Input logs (functional CI failure) ───────────────────────────────────
    raw_logs: str
    cleaned_logs: str

    # ── Agent 1: Build-Monitor Triage ────────────────────────────────────────
    is_flaky_ignored: bool
    flaky_reason: Optional[str]

    # ── Agent 2: Diagnosis ───────────────────────────────────────────────────
    diagnosis_category: Optional[str]   # dependency_error | test_assertion_failure | flaky_test | lint_error
    diagnosis_confidence: float
    affected_files: List[str]
    evidence: str

    # ── Agent 3: Fix-Proposer (functional) ───────────────────────────────────
    current_patch: Optional[str]
    guardrail_passed: bool
    guardrail_error: Optional[str]
    rejection_memory_context: str       # Retrieved ChromaDB entries injected into prompt

    # ── Agent 4: Reviewer & Execution Sandbox ────────────────────────────────
    current_attempt: int
    max_attempts: int
    patch_history: List[Dict[str, Any]]
    test_passed: bool
    test_output: str

    # ── Security Workflow ─────────────────────────────────────────────────────
    # Findings list: each is a dict representation of SecurityFinding
    security_findings: List[Dict[str, Any]]
    active_finding_id: Optional[str]      # The finding currently being remediated

    # Attacker Agent output
    attacker_assessment: Optional[Dict[str, Any]]   # dict of AttackerAssessment

    # Defender A and Defender B proposals (dict of DefenderProposal)
    defender_a_proposal: Optional[Dict[str, Any]]
    defender_b_proposal: Optional[Dict[str, Any]]
    debate_history: List[Dict[str, Any]]  # list of {round, defender_a, defender_b}

    # Judge Agent output
    judge_decision: Optional[Dict[str, Any]]        # dict of JudgeDecision
    security_remediation_round: int                 # 1-3
    max_security_rounds: int

    # ── Final Result ─────────────────────────────────────────────────────────
    final_outcome: str    # pending | pr_opened | escalated | ignored_flaky | security_pr_opened | security_escalated
    pr_link: Optional[str]
    pr_branch: Optional[str]
    summary_notes: str

    # ── Audit trail ──────────────────────────────────────────────────────────
    agent_execution_log: List[Dict[str, Any]]  # timestamped agent events
