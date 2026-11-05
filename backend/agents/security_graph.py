"""
Security Debate LangGraph — the multi-agent security remediation workflow.

Flow:
  attacker → defender_a → defender_b → judge
      ↑ (if rejected and rounds < max)         ↓
      └────────────────── loop ─────────────────┘
                                               │ (accepted or max rounds)
                                              END
"""

import logging
from langgraph.graph import StateGraph, START, END

from backend.agents.state import AegisAgentState
from backend.agents.attacker import attacker_agent
from backend.agents.defenders import defender_a_agent, defender_b_agent
from backend.agents.judge import judge_agent

logger = logging.getLogger("aegis.security_graph")


def _route_after_judge(state: AegisAgentState) -> str:
    """
    After Judge:
    - 'security_pr_opened' or 'security_escalated' → END
    - otherwise (rejected, rounds remain) → back to defender_a for another round
    """
    outcome = state.get("final_outcome", "")
    if outcome in ("security_pr_opened", "security_escalated"):
        return END

    round_num = state.get("security_remediation_round", 1)
    max_rounds = state.get("max_security_rounds", 3)
    if round_num > max_rounds:
        return END

    logger.info(f"Routing back to defender_a for debate round {round_num}.")
    return "defender_a"


def create_security_graph():
    """Build and compile the security debate LangGraph."""
    workflow = StateGraph(AegisAgentState)

    workflow.add_node("attacker", attacker_agent)
    workflow.add_node("defender_a", defender_a_agent)
    workflow.add_node("defender_b", defender_b_agent)
    workflow.add_node("judge", judge_agent)

    workflow.add_edge(START, "attacker")
    workflow.add_edge("attacker", "defender_a")
    workflow.add_edge("defender_a", "defender_b")
    workflow.add_edge("defender_b", "judge")

    workflow.add_conditional_edges(
        "judge",
        _route_after_judge,
        {
            END: END,
            "defender_a": "defender_a",
        },
    )

    return workflow.compile()


security_graph = create_security_graph()

