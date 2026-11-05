"""
Structured Evaluation Record Schema for AegisCI Experiments.

Tracks:
- Diagnosis accuracy
- Patch success & regression rate
- Security vulnerability removal
- Rejection memory influence & retrieval
- Retry count & convergence
- Human escalation & processing duration
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ExperimentRecord(BaseModel):
    """Structured record for an AegisCI evaluation run."""

    experiment_id: str
    scenario_type: str = Field(..., description="'functional' or 'security'")
    scenario_name: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Execution metrics
    duration_seconds: float = 0.0
    attempts_made: int = 1
    max_attempts: int = 3
    final_outcome: str  # pr_opened, escalated, ignored_flaky, security_pr_opened, security_escalated

    # Diagnosis accuracy
    expected_category: str
    diagnosed_category: Optional[str] = None
    diagnosis_accurate: bool = False
    affected_files_expected: List[str] = Field(default_factory=list)
    affected_files_identified: List[str] = Field(default_factory=list)

    # Patch validation
    patch_applied_cleanly: bool = False
    tests_passed: bool = False
    regression_detected: bool = False
    guardrails_passed: bool = True

    # Security metrics (for security scenarios)
    vulnerability_rule_id: Optional[str] = None
    vulnerability_cleared: Optional[bool] = None
    attacker_exploitability: Optional[str] = None
    winning_defender: Optional[str] = None

    # Memory influence
    rejection_memory_retrieved: int = 0
    rejection_memory_influenced_fix: bool = False

    # Pull Request details
    pr_created: bool = False
    pr_branch: Optional[str] = None
    pr_link: Optional[str] = None
    human_approval_required: bool = True

    def summary(self) -> Dict[str, Any]:
        """Return high-level scorecard summary."""
        return {
            "experiment": self.scenario_name,
            "type": self.scenario_type,
            "outcome": self.final_outcome,
            "diagnosis_match": self.diagnosis_accurate,
            "success": self.tests_passed or (self.vulnerability_cleared is True),
            "attempts": f"{self.attempts_made}/{self.max_attempts}",
            "pr_created": self.pr_created,
            "duration_s": round(self.duration_seconds, 2),
        }
