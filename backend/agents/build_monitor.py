import logging
from backend.database import SessionLocal
from backend.models import KnownFailure
from backend.agents.state import AegisAgentState

logger = logging.getLogger("aegis.build_monitor")


def build_monitor_agent(state: AegisAgentState) -> AegisAgentState:
    """
    Build-Monitor Agent:
    Performs triage on the failure event. Checks local SQLite history for known
    flaky or deliberately ignored failures.
    """
    incident_id = state.get("incident_id", "unknown")
    raw_logs = state.get("raw_logs", "")
    logger.info(f"[{incident_id}] Build-Monitor Agent analyzing failure...")

    db = SessionLocal()
    is_flaky = False
    flaky_reason = None

    try:
        known_flaky = db.query(KnownFailure).all()
        for kf in known_flaky:
            if kf.signature and kf.signature.lower() in raw_logs.lower():
                is_flaky = True
                flaky_reason = f"Matched known signature: '{kf.signature}' ({kf.reason})"
                break
    except Exception as e:
        logger.warning(f"[{incident_id}] Database check in Build-Monitor encountered error: {e}")
    finally:
        db.close()

    if is_flaky:
        logger.info(f"[{incident_id}] Failure identified as known flaky test. Triaged as ignored: {flaky_reason}")
        return {
            **state,
            "is_flaky_ignored": True,
            "flaky_reason": flaky_reason,
            "final_outcome": "ignored_flaky",
            "summary_notes": f"Triaged as known flaky test: {flaky_reason}",
        }

    logger.info(f"[{incident_id}] Failure is novel. Passing to Diagnosis Agent.")
    return {
        **state,
        "is_flaky_ignored": False,
        "flaky_reason": None,
    }
