import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.database import Base, engine, get_db, SessionLocal
from backend.models import Incident, KnownFailure
from backend.agents.graph import aegis_graph
from backend.agents.state import AegisAgentState

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

    # Record initial incident state in DB
    incident_record = Incident(
        id=incident_id,
        repo=payload.repo,
        commit_sha=payload.commit_sha,
        branch=payload.branch,
        run_id=run_id,
        raw_logs=payload.logs,
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
        "raw_logs": payload.logs,
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
        "current_attempt": 0,
        "max_attempts": 3,
        "patch_history": [],
        "test_passed": False,
        "test_output": "",
        "final_outcome": "processing",
        "pr_link": None,
        "pr_branch": None,
        "summary_notes": "",
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
