import logging
from langgraph.graph import StateGraph, START, END

from backend.agents.state import AegisAgentState
from backend.agents.build_monitor import build_monitor_agent
from backend.agents.diagnosis import diagnosis_agent
from backend.agents.fix_proposer import fix_proposer_agent
from backend.agents.reviewer import reviewer_agent

logger = logging.getLogger("aegis.graph")


def check_build_monitor_triage(state: AegisAgentState) -> str:
    """Routing after Build-Monitor Agent: stop if flaky/ignored, else diagnose."""
    if state.get("is_flaky_ignored", False):
        return END
    return "diagnosis"


def check_review_outcome(state: AegisAgentState) -> str:
    """
    Routing after Reviewer Agent:
    - If tests passed: END (PR opened)
    - If tests failed and attempts remaining: loop back to fix_proposer
    - If attempts exhausted: END (escalated)
    """
    if state.get("test_passed", False):
        return END

    current_attempt = state.get("current_attempt", 1)
    max_attempts = state.get("max_attempts", 3)

    if current_attempt < max_attempts:
        logger.info(f"Looping back to fix_proposer (Attempt {current_attempt + 1}/{max_attempts})")
        return "fix_proposer"

    logger.warning("Max attempts reached. Ending workflow with escalation.")
    return END


def create_aegis_graph():
    """
    Constructs and compiles the AegisCI 4-agent LangGraph state machine.
    """
    workflow = StateGraph(AegisAgentState)

    # Add agent nodes
    workflow.add_node("build_monitor", build_monitor_agent)
    workflow.add_node("diagnosis", diagnosis_agent)
    workflow.add_node("fix_proposer", fix_proposer_agent)
    workflow.add_node("reviewer", reviewer_agent)

    # Wire nodes with edges
    workflow.add_edge(START, "build_monitor")

    workflow.add_conditional_edges(
        "build_monitor",
        check_build_monitor_triage,
        {
            END: END,
            "diagnosis": "diagnosis",
        },
    )

    workflow.add_edge("diagnosis", "fix_proposer")
    workflow.add_edge("fix_proposer", "reviewer")

    workflow.add_conditional_edges(
        "reviewer",
        check_review_outcome,
        {
            END: END,
            "fix_proposer": "fix_proposer",
        },
    )

    return workflow.compile()


# Compiled singleton instance
aegis_graph = create_aegis_graph()
