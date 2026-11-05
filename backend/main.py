import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.database import Base, engine, get_db, SessionLocal
from backend.models import Incident, KnownFailure
from backend.agents.graph import aegis_graph
from backend.agents.state import AegisAgentState
from backend.security.parser import parse_semgrep_json
from backend.utils.scrubber import scrub_secrets

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aegis.main")

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AegisCI — Multi-Agent Automated CI/CD Repair Pipeline",
    description="Backend engine driving autonomous failure diagnosis, patch generation, and review.",
    version="0.1.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Pydantic Schemas
class IncidentCreate(BaseModel):
    repo: str = Field(default="local/AegisCI", description="Repository name e.g. owner/repo")
    commit_sha: str = Field(default="head", description="Commit SHA that failed CI")
    branch: str = Field(default="main", description="Branch name")
    run_id: Optional[str] = Field(default=None, description="CI workflow run ID")
    logs: str = Field(..., description="Raw CI test/build failure logs")


class IncidentResponse(BaseModel):
    incident_id: str
    status: str
    message: str
    repo: str
    commit_sha: str
    branch: str


class KnownFailureCreate(BaseModel):
    signature: str = Field(..., description="Signature text or substring in logs")
    category: str = Field(default="flaky_test")
    reason: str = Field(..., description="Explanation of why this is ignored")


def run_agent_workflow_background(initial_state: AegisAgentState):
    """
    Background worker that runs the LangGraph multi-agent repair chain.
    """
    incident_id = initial_state["incident_id"]
    logger.info(f"[{incident_id}] Starting LangGraph multi-agent repair pipeline...")
    try:
        final_state = aegis_graph.invoke(initial_state)
        outcome = final_state.get("final_outcome", "unknown")
        logger.info(f"[{incident_id}] Agent pipeline finished with outcome: {outcome}")
    except Exception as e:
        logger.error(f"[{incident_id}] Agent pipeline execution failed: {e}", exc_info=True)
        # Update DB on unhandled crash
        db = SessionLocal()
        try:
            inc = db.query(Incident).filter(Incident.id == incident_id).first()
            if inc:
                inc.final_outcome = "error"
                inc.notes = f"Pipeline execution error: {str(e)}"
                db.commit()
        finally:
            db.close()


@app.get("/health")
def health_check():
    """Health check endpoint for AegisCI backend."""
    return {
        "status": "healthy",
        "service": "AegisCI Backend",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/incident", response_model=IncidentResponse)
def report_incident(
    payload: IncidentCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Receives failure event from CI pipeline hook, records incident in SQLite,
    and kicks off the LangGraph agent chain asynchronously.
    """
    incident_id = f"inc-{uuid.uuid4().hex[:8]}"
    run_id = payload.run_id or f"run-{uuid.uuid4().hex[:6]}"

    # Check for duplicate incident to avoid redundant processing
    existing = db.query(Incident).filter(
        Incident.run_id == run_id,
        Incident.commit_sha == payload.commit_sha,
        Incident.final_outcome != "error",
    ).first()
    if existing:
        logger.info(f"Duplicate incident intake detected for run {run_id}@{payload.commit_sha}. Returning existing record.")
        return IncidentResponse(
            incident_id=existing.id,
            status=existing.final_outcome or "processing",
            message=f"Incident for run {run_id} already registered.",
            repo=existing.repo,
            commit_sha=existing.commit_sha,
            branch=existing.branch,
        )

    # Sanitize logs of secrets before storage
    clean_logs = scrub_secrets(payload.logs)

    # Record initial incident state in DB
    incident_record = Incident(
        id=incident_id,
        repo=payload.repo,
        commit_sha=payload.commit_sha,
        branch=payload.branch,
        run_id=run_id,
        raw_logs=clean_logs,
        final_outcome="processing",
    )
    db.add(incident_record)
    db.commit()

    initial_state: AegisAgentState = {
        "incident_id": incident_id,
        "repo": payload.repo,
        "commit_sha": payload.commit_sha,
        "branch": payload.branch,
        "run_id": run_id,
        "raw_logs": clean_logs,
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
        "rejection_memory_context": "",
        "current_attempt": 0,
        "max_attempts": 3,
        "patch_history": [],
        "test_passed": False,
        "test_output": "",
        # Security workflow fields (unused for CI-failure pipeline)
        "security_findings": [],
        "active_finding_id": None,
        "attacker_assessment": None,
        "defender_a_proposal": None,
        "defender_b_proposal": None,
        "debate_history": [],
        "judge_decision": None,
        "security_remediation_round": 0,
        "max_security_rounds": 3,
        "final_outcome": "processing",
        "pr_link": None,
        "pr_branch": None,
        "summary_notes": "",
        "agent_execution_log": [],
    }

    # Launch LangGraph agent workflow asynchronously
    background_tasks.add_task(run_agent_workflow_background, initial_state)

    logger.info(f"[{incident_id}] Incident registered for repo {payload.repo}@{payload.commit_sha}")

    return IncidentResponse(
        incident_id=incident_id,
        status="processing",
        message="AegisCI multi-agent repair chain triggered asynchronously.",
        repo=payload.repo,
        commit_sha=payload.commit_sha,
        branch=payload.branch,
    )


@app.get("/incidents")
def list_incidents(db: Session = Depends(get_db)):
    """Retrieve list of all logged incidents."""
    incidents = db.query(Incident).order_by(Incident.timestamp.desc()).limit(50).all()
    return [
        {
            "id": inc.id,
            "repo": inc.repo,
            "commit_sha": inc.commit_sha,
            "branch": inc.branch,
            "run_id": inc.run_id,
            "timestamp": inc.timestamp.isoformat() if inc.timestamp else None,
            "diagnosis_category": inc.diagnosis_category,
            "diagnosis_confidence": inc.diagnosis_confidence,
            "affected_files": inc.affected_files,
            "attempts_made": inc.attempts_made,
            "final_outcome": inc.final_outcome,
            "pr_link": inc.pr_link,
            "pr_branch": inc.pr_branch,
            "notes": inc.notes,
        }
        for inc in incidents
    ]


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    """Retrieve full details of a specific incident including patch diff."""
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {
        "id": inc.id,
        "repo": inc.repo,
        "commit_sha": inc.commit_sha,
        "branch": inc.branch,
        "run_id": inc.run_id,
        "timestamp": inc.timestamp.isoformat() if inc.timestamp else None,
        "diagnosis_category": inc.diagnosis_category,
        "diagnosis_confidence": inc.diagnosis_confidence,
        "affected_files": inc.affected_files,
        "evidence": inc.evidence,
        "attempts_made": inc.attempts_made,
        "final_outcome": inc.final_outcome,
        "pr_link": inc.pr_link,
        "pr_branch": inc.pr_branch,
        "patch_diff": inc.patch_diff,
        "notes": inc.notes,
    }


@app.post("/known-failures")
def add_known_failure(payload: KnownFailureCreate, db: Session = Depends(get_db)):
    """Add a known flaky test signature for Build-Monitor triage."""
    kf = KnownFailure(
        signature=payload.signature,
        category=payload.category,
        reason=payload.reason,
    )
    db.add(kf)
    db.commit()
    db.refresh(kf)
    return {"id": kf.id, "signature": kf.signature, "reason": kf.reason}


# ---------------------------------------------------------------------------
# Security / Semgrep Intake Endpoint
# ---------------------------------------------------------------------------

class SecurityIncidentCreate(BaseModel):
    repo: str = Field(default="local/AegisCI")
    commit_sha: str = Field(default="head")
    branch: str = Field(default="main")
    run_id: Optional[str] = Field(default=None)
    semgrep_json: Dict[str, Any] = Field(..., description="Raw Semgrep JSON output dict")


def run_security_workflow_background(initial_state: AegisAgentState):
    """Background worker that runs the security debate LangGraph."""
    from backend.agents.security_graph import security_graph  # noqa: PLC0415
    incident_id = initial_state["incident_id"]
    logger.info(f"[{incident_id}] Starting security debate pipeline...")
    try:
        final_state = security_graph.invoke(initial_state)
        outcome = final_state.get("final_outcome", "unknown")
        logger.info(f"[{incident_id}] Security pipeline finished: {outcome}")
    except Exception as e:
        logger.error(f"[{incident_id}] Security pipeline error: {e}", exc_info=True)
        db = SessionLocal()
        try:
            inc = db.query(Incident).filter(Incident.id == incident_id).first()
            if inc:
                inc.final_outcome = "error"
                inc.notes = f"Security pipeline error: {str(e)}"
                db.commit()
        finally:
            db.close()


@app.post("/security-incident", response_model=IncidentResponse)
def report_security_incident(
    payload: SecurityIncidentCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Receives Semgrep JSON output, parses findings, records an incident, and
    launches the security debate workflow asynchronously.
    """
    findings = parse_semgrep_json(payload.semgrep_json)
    if not findings:
        raise HTTPException(status_code=422, detail="No actionable security findings in Semgrep output.")

    incident_id = f"sec-{uuid.uuid4().hex[:8]}"
    run_id = payload.run_id or f"run-{uuid.uuid4().hex[:6]}"

    incident_record = Incident(
        id=incident_id,
        repo=payload.repo,
        commit_sha=payload.commit_sha,
        branch=payload.branch,
        run_id=run_id,
        raw_logs=f"Security findings: {len(findings)} from Semgrep",
        final_outcome="processing",
    )
    db.add(incident_record)
    db.commit()

    # Use first finding as the active one (each finding should ideally be a separate incident)
    active = findings[0]
    findings_dicts = [f.model_dump() for f in findings]

    initial_state: AegisAgentState = {
        "incident_id": incident_id,
        "repo": payload.repo,
        "commit_sha": payload.commit_sha,
        "branch": payload.branch,
        "run_id": run_id,
        "raw_logs": "",
        "cleaned_logs": "",
        "is_flaky_ignored": False,
        "flaky_reason": None,
        "diagnosis_category": "security_finding",
        "diagnosis_confidence": 0.9,
        "affected_files": [active.file_path],
        "evidence": active.message,
        "current_patch": None,
        "guardrail_passed": True,
        "guardrail_error": None,
        "rejection_memory_context": "",
        "current_attempt": 0,
        "max_attempts": 3,
        "patch_history": [],
        "test_passed": False,
        "test_output": "",
        "security_findings": findings_dicts,
        "active_finding_id": active.id,
        "attacker_assessment": None,
        "defender_a_proposal": None,
        "defender_b_proposal": None,
        "debate_history": [],
        "judge_decision": None,
        "security_remediation_round": 1,
        "max_security_rounds": 3,
        "final_outcome": "processing",
        "pr_link": None,
        "pr_branch": None,
        "summary_notes": "",
        "agent_execution_log": [],
    }

    background_tasks.add_task(run_security_workflow_background, initial_state)
    logger.info(f"[{incident_id}] Security incident registered: {len(findings)} findings.")

    return IncidentResponse(
        incident_id=incident_id,
        status="processing",
        message=f"AegisCI security debate pipeline triggered for {len(findings)} finding(s).",
        repo=payload.repo,
        commit_sha=payload.commit_sha,
        branch=payload.branch,
    )


# ---------------------------------------------------------------------------
# Phase 3 Unified CI Run Results Intake Endpoint
# ---------------------------------------------------------------------------

class CIRunResultPayload(BaseModel):
    repo: str = Field(default="local/AegisCI", description="Repository name owner/repo")
    commit_sha: str = Field(default="head", description="Commit SHA that triggered CI")
    branch: str = Field(default="main", description="Branch name")
    run_id: str = Field(..., description="Unique CI run or job ID")
    event_name: Optional[str] = Field(default="push", description="Trigger event (push, pull_request, workflow_dispatch)")
    test_passed: Optional[bool] = Field(default=None, description="Whether tests passed")
    build_exit_code: Optional[int] = Field(default=0, description="Build step exit code")
    test_exit_code: Optional[int] = Field(default=0, description="Test step exit code")
    logs: Optional[str] = Field(default="", description="Captured test or build logs")
    semgrep_json: Optional[Dict[str, Any]] = Field(default=None, description="Parsed Semgrep JSON output")
    artifacts: Optional[List[str]] = Field(default=None, description="List of generated artifact names")


class CIResultResponse(BaseModel):
    status: str
    message: str
    repo: str
    commit_sha: str
    run_id: str
    functional_incident_id: Optional[str] = None
    security_incident_id: Optional[str] = None
    duplicate: bool = False


def verify_webhook_secret(x_aegis_secret: Optional[str] = Header(None, alias="X-Aegis-Secret")):
    """
    Validates optional webhook secret header.
    If AEGIS_WEBHOOK_SECRET is set in environment, rejects unauthenticated requests.
    If not set, allows the request (convenient for local offline development).
    """
    expected_secret = os.getenv("AEGIS_WEBHOOK_SECRET")
    if expected_secret:
        if not x_aegis_secret or x_aegis_secret.strip() != expected_secret.strip():
            logger.warning("Rejected unauthorized CI webhook request: invalid or missing X-Aegis-Secret.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing X-Aegis-Secret header."
            )


@app.post("/ci/results", response_model=CIResultResponse)
def receive_ci_results(
    payload: CIRunResultPayload,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _auth: None = Depends(verify_webhook_secret),
):
    """
    Phase 3 Unified CI Result Receiver:
    - Authenticates via X-Aegis-Secret header when AEGIS_WEBHOOK_SECRET is configured.
    - Sanitizes logs of secrets.
    - Performs idempotency checks to avoid duplicate workflow executions.
    - Routes build/test failures to the Functional Repair graph.
    - Routes Semgrep security findings to the Multi-Agent Security Debate graph.
    """
    repo = payload.repo
    commit_sha = payload.commit_sha
    branch = payload.branch
    run_id = payload.run_id
    clean_logs = scrub_secrets(payload.logs or "")

    logger.info(f"Received CI results for {repo}@{commit_sha} (Run ID: {run_id}, Event: {payload.event_name})")

    # Check for existing processed run (idempotency)
    existing = db.query(Incident).filter(
        Incident.run_id == run_id,
        Incident.commit_sha == commit_sha,
        Incident.final_outcome != "error",
    ).first()
    if existing:
        logger.info(f"CI run {run_id}@{commit_sha} was already registered (Incident {existing.id}). Skipping re-dispatch.")
        return CIResultResponse(
            status="already_processed",
            message=f"CI run {run_id} already registered with incident {existing.id}",
            repo=repo,
            commit_sha=commit_sha,
            run_id=run_id,
            functional_incident_id=existing.id if not existing.id.startswith("sec-") else None,
            security_incident_id=existing.id if existing.id.startswith("sec-") else None,
            duplicate=True,
        )

    functional_id = None
    security_id = None

    # 1. Determine if functional remediation is needed
    tests_failed = (
        payload.test_passed is False
        or (payload.test_exit_code is not None and payload.test_exit_code != 0)
        or (payload.build_exit_code is not None and payload.build_exit_code != 0)
        or ("FAILURES" in clean_logs)
        or ("FAILED" in clean_logs)
        or ("Error" in clean_logs and "test" in clean_logs.lower())
    )

    if tests_failed and clean_logs:
        functional_id = f"inc-{uuid.uuid4().hex[:8]}"
        inc_record = Incident(
            id=functional_id,
            repo=repo,
            commit_sha=commit_sha,
            branch=branch,
            run_id=run_id,
            raw_logs=clean_logs,
            final_outcome="processing",
        )
        db.add(inc_record)
        db.commit()

        initial_func_state: AegisAgentState = {
            "incident_id": functional_id,
            "repo": repo,
            "commit_sha": commit_sha,
            "branch": branch,
            "run_id": run_id,
            "raw_logs": clean_logs,
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
            "rejection_memory_context": "",
            "current_attempt": 0,
            "max_attempts": 3,
            "patch_history": [],
            "test_passed": False,
            "test_output": "",
            "security_findings": [],
            "active_finding_id": None,
            "attacker_assessment": None,
            "defender_a_proposal": None,
            "defender_b_proposal": None,
            "debate_history": [],
            "judge_decision": None,
            "security_remediation_round": 0,
            "max_security_rounds": 3,
            "final_outcome": "processing",
            "pr_link": None,
            "pr_branch": None,
            "summary_notes": "",
            "agent_execution_log": [],
        }
        background_tasks.add_task(run_agent_workflow_background, initial_func_state)
        logger.info(f"[{functional_id}] Dispatched functional repair pipeline for CI failure.")

    # 2. Determine if security remediation is needed
    if payload.semgrep_json:
        findings = parse_semgrep_json(payload.semgrep_json)
        if findings:
            security_id = f"sec-{uuid.uuid4().hex[:8]}"
            sec_record = Incident(
                id=security_id,
                repo=repo,
                commit_sha=commit_sha,
                branch=branch,
                run_id=run_id,
                raw_logs=f"Security findings: {len(findings)} detected by Semgrep",
                final_outcome="processing",
            )
            db.add(sec_record)
            db.commit()

            active = findings[0]
            findings_dicts = [f.model_dump() for f in findings]

            initial_sec_state: AegisAgentState = {
                "incident_id": security_id,
                "repo": repo,
                "commit_sha": commit_sha,
                "branch": branch,
                "run_id": run_id,
                "raw_logs": "",
                "cleaned_logs": "",
                "is_flaky_ignored": False,
                "flaky_reason": None,
                "diagnosis_category": "security_finding",
                "diagnosis_confidence": 0.9,
                "affected_files": [active.file_path],
                "evidence": active.message,
                "current_patch": None,
                "guardrail_passed": True,
                "guardrail_error": None,
                "rejection_memory_context": "",
                "current_attempt": 0,
                "max_attempts": 3,
                "patch_history": [],
                "test_passed": False,
                "test_output": "",
                "security_findings": findings_dicts,
                "active_finding_id": active.id,
                "attacker_assessment": None,
                "defender_a_proposal": None,
                "defender_b_proposal": None,
                "debate_history": [],
                "judge_decision": None,
                "security_remediation_round": 1,
                "max_security_rounds": 3,
                "final_outcome": "processing",
                "pr_link": None,
                "pr_branch": None,
                "summary_notes": "",
                "agent_execution_log": [],
            }
            background_tasks.add_task(run_security_workflow_background, initial_sec_state)
            logger.info(f"[{security_id}] Dispatched security debate pipeline for {len(findings)} findings.")

    if not functional_id and not security_id:
        return CIResultResponse(
            status="no_action_required",
            message="CI run succeeded with no test failures or security findings.",
            repo=repo,
            commit_sha=commit_sha,
            run_id=run_id,
            duplicate=False,
        )

    dispatches = []
    if functional_id:
        dispatches.append(f"functional repair ({functional_id})")
    if security_id:
        dispatches.append(f"security debate ({security_id})")

    return CIResultResponse(
        status="remediation_triggered",
        message=f"Dispatched {', '.join(dispatches)}.",
        repo=repo,
        commit_sha=commit_sha,
        run_id=run_id,
        functional_incident_id=functional_id,
        security_incident_id=security_id,
        duplicate=False,
    )
