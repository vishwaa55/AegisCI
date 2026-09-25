import json
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import Column, String, Integer, Float, Text, DateTime
from backend.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True, index=True)
    repo = Column(String(255), nullable=False)
    commit_sha = Column(String(64), nullable=False)
    branch = Column(String(128), default="main")
    run_id = Column(String(64), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Diagnosis fields
    diagnosis_category = Column(String(64), nullable=True)  # dependency_error, test_assertion_failure, flaky_test, lint_error
    diagnosis_confidence = Column(Float, default=0.0)
    affected_files_json = Column(Text, default="[]")
    evidence = Column(Text, nullable=True)
    
    # Execution & review fields
    attempts_made = Column(Integer, default=0)
    final_outcome = Column(String(64), default="pending")  # pr_opened, escalated, ignored_flaky
    pr_link = Column(String(512), nullable=True)
    pr_branch = Column(String(128), nullable=True)
    
    # Logs and diffs
    raw_logs = Column(Text, nullable=True)
    patch_diff = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)

    @property
    def affected_files(self) -> List[str]:
        if not self.affected_files_json:
            return []
        try:
            return json.loads(self.affected_files_json)
        except Exception:
            return []

    @affected_files.setter
    def affected_files(self, files: List[str]):
        self.affected_files_json = json.dumps(files)


class KnownFailure(Base):
    __tablename__ = "known_failures"

    id = Column(Integer, primary_key=True, autoincrement=True)
    signature = Column(String(255), unique=True, index=True)  # e.g., error pattern or hash
    category = Column(String(64), default="flaky_test")
    reason = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
