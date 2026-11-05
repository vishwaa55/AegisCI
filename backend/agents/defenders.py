"""
Defender A and Defender B agents — independent security remediation proposals.

Each defender receives the same finding + attacker assessment and must
independently generate a candidate patch with security rationale.
They do NOT share intermediate drafts; independence is enforced by calling
each in separate graph nodes with separate LLM calls.

A second debate round allows each to critique the other's proposal and optionally
revise, before the Judge makes a final determination.
"""

import logging
import os
from typing import Any, Dict, Optional

from backend.agents.fix_proposer import clean_diff_markdown, validate_patch_guardrails
from backend.agents.llm_client import LLMClient
from backend.agents.state import AegisAgentState

logger = logging.getLogger("aegis.defenders")

# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

DEFENDER_SYSTEM_PROMPT = (
    "You are {defender_name}, an expert defensive security engineer for AegisCI.\n"
    "Your task: generate an independent, minimal fix for the security vulnerability described below.\n\n"
    "Output format — produce TWO sections separated by '---PATCH---':\n"
    "Section 1 (plain text):\n"
    "  strategy_name: <one-line name>\n"
    "  security_rationale: <why this fix neutralises the attack vector>\n"
    "  potential_side_effects: <trade-offs, performance, backward-compat notes>\n"
    "{critique_section}"
    "Section 2 (after ---PATCH---):\n"
    "  A unified diff patch inside a ```diff code block.\n\n"
    "RULES:\n"
    "1. Produce a minimal, surgical unified diff — do NOT rewrite the whole file.\n"
    "2. Do NOT modify CI/CD files, Dockerfiles, or secrets.\n"
    "3. Only change the file(s) flagged in the finding.\n"
    "4. Your proposal must differ in approach from the opposing defender."
)


def _read_file_safe(path: str) -> str:
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return ""
    return ""


def _build_defender_prompt(
    defender_name: str,
    finding: Dict[str, Any],
    attacker_assessment: Optional[Dict[str, Any]],
    file_content: str,
    counterpart_proposal: Optional[Dict[str, Any]],
    round_number: int,
) -> tuple[str, str]:
    """Return (system_prompt, user_prompt) for a defender."""
    critique_instruction = ""
    if round_number >= 2 and counterpart_proposal:
        counterpart_name = "Defender A" if "defender_b" in defender_name.lower() else "Defender B"
        critique_instruction = (
            f"  critique_of_counterpart: <constructive critique of {counterpart_name}'s proposal below>\n"
        )

    system = DEFENDER_SYSTEM_PROMPT.format(
        defender_name=defender_name,
        critique_section=critique_instruction,
    )

    attacker_text = ""
    if attacker_assessment:
        attacker_text = (
            f"\nAttacker Assessment:\n"
            f"  Exploitability: {attacker_assessment.get('exploitability')}\n"
            f"  Attack Vector: {attacker_assessment.get('attack_vector')}\n"
            f"  Exploit Scenario: {attacker_assessment.get('exploit_scenario')}\n"
            f"  Evidence vs Assumptions: {attacker_assessment.get('evidence_vs_assumptions')}\n"
        )

    counterpart_text = ""
    if counterpart_proposal and round_number >= 2:
        other_name = "Defender A" if "b" in defender_name.lower() else "Defender B"
        counterpart_text = (
            f"\n{other_name}'s Proposal (for critique):\n"
            f"  Strategy: {counterpart_proposal.get('strategy_name', '')}\n"
            f"  Rationale: {counterpart_proposal.get('security_rationale', '')}\n"
            f"  Side Effects: {counterpart_proposal.get('potential_side_effects', '')}\n"
        )

    file_path = finding.get("file_path", "")
    user = (
        f"Security Finding (Round {round_number}):\n"
        f"  Rule: {finding.get('rule_id', '')}\n"
        f"  Severity: {finding.get('severity', '')}\n"
        f"  File: {file_path}, Line: {finding.get('start_line', '?')}\n"
        f"  Message: {finding.get('message', '')}\n"
        f"  Code Snippet:\n```\n{finding.get('code_snippet', '')}\n```\n"
        f"{attacker_text}"
        f"{counterpart_text}"
        f"\nAffected File Contents:\n--- File: {file_path} ---\n{file_content}\n\n"
        "Produce your independent remediation proposal:"
    )

    return system, user


def _parse_defender_response(
    raw: str, defender_id: str, finding_file: str
) -> Dict[str, Any]:
    """Parse the two-section response into a DefenderProposal-like dict."""
    parts = raw.split("---PATCH---", 1)
    text_section = parts[0].strip()
    patch_section = clean_diff_markdown(parts[1].strip()) if len(parts) > 1 else ""

    def extract(key: str, text: str) -> str:
        for line in text.splitlines():
            if line.lower().startswith(key + ":"):
                return line.split(":", 1)[1].strip()
        return ""

    strategy = extract("strategy_name", text_section) or f"{defender_id} fix"
    rationale = extract("security_rationale", text_section) or text_section[:300]
    side_effects = extract("potential_side_effects", text_section) or "None identified."
    critique = extract("critique_of_counterpart", text_section) or None

    return {
        "defender_id": defender_id,
        "strategy_name": strategy,
        "patch_diff": patch_section,
        "security_rationale": rationale,
        "potential_side_effects": side_effects,
        "critique_of_counterpart": critique,
    }


# ---------------------------------------------------------------------------
# Agent nodes
# ---------------------------------------------------------------------------

def defender_a_agent(state: AegisAgentState) -> AegisAgentState:
    """Defender A generates an independent security remediation proposal."""
    incident_id = state.get("incident_id", "unknown")
    findings = state.get("security_findings", [])
    active_id = state.get("active_finding_id")
    finding = next((f for f in findings if f.get("id") == active_id), findings[0] if findings else None)

    if not finding:
        logger.warning(f"[{incident_id}] Defender A: no finding, skipping.")
        return {**state, "defender_a_proposal": None}

    round_number = state.get("security_remediation_round", 1)
    attacker_assessment = state.get("attacker_assessment")
    # On round 2+, Defender A may critique Defender B's round-1 output
    counterpart = state.get("defender_b_proposal") if round_number >= 2 else None

    file_path = finding.get("file_path", "")
    file_content = _read_file_safe(file_path)

    system, user = _build_defender_prompt(
        defender_name="Defender A",
        finding=finding,
        attacker_assessment=attacker_assessment,
        file_content=file_content,
        counterpart_proposal=counterpart,
        round_number=round_number,
    )

    logger.info(f"[{incident_id}] Defender A generating proposal (round {round_number})...")
    llm = LLMClient()
    try:
        raw = llm.generate_text(system, user, temperature=0.3)
    except Exception as e:
        logger.error(f"[{incident_id}] Defender A LLM call failed: {e}")
        raw = f"strategy_name: Fallback — sanitize input\nsecurity_rationale: LLM unavailable.\npotential_side_effects: Unknown.\n---PATCH---\n"

    proposal = _parse_defender_response(raw, "defender_a", file_path)
    logger.info(f"[{incident_id}] Defender A strategy: {proposal['strategy_name']}")

    return {**state, "defender_a_proposal": proposal}


def defender_b_agent(state: AegisAgentState) -> AegisAgentState:
    """Defender B generates an independent security remediation proposal."""
    incident_id = state.get("incident_id", "unknown")
    findings = state.get("security_findings", [])
    active_id = state.get("active_finding_id")
    finding = next((f for f in findings if f.get("id") == active_id), findings[0] if findings else None)

    if not finding:
        logger.warning(f"[{incident_id}] Defender B: no finding, skipping.")
        return {**state, "defender_b_proposal": None}

    round_number = state.get("security_remediation_round", 1)
    attacker_assessment = state.get("attacker_assessment")
    # On round 2+, Defender B may critique Defender A's round-1 output
    counterpart = state.get("defender_a_proposal") if round_number >= 2 else None

    file_path = finding.get("file_path", "")
    file_content = _read_file_safe(file_path)

    system, user = _build_defender_prompt(
        defender_name="Defender B",
        finding=finding,
        attacker_assessment=attacker_assessment,
        file_content=file_content,
        counterpart_proposal=counterpart,
        round_number=round_number,
    )

    logger.info(f"[{incident_id}] Defender B generating proposal (round {round_number})...")
    llm = LLMClient()
    try:
        raw = llm.generate_text(system, user, temperature=0.4)
    except Exception as e:
        logger.error(f"[{incident_id}] Defender B LLM call failed: {e}")
        raw = f"strategy_name: Fallback — use safe API\nsecurity_rationale: LLM unavailable.\npotential_side_effects: Unknown.\n---PATCH---\n"

    proposal = _parse_defender_response(raw, "defender_b", file_path)
    logger.info(f"[{incident_id}] Defender B strategy: {proposal['strategy_name']}")

    # Record debate round
    debate_history = list(state.get("debate_history", []))
    # Update or append this round entry
    round_entry = {
        "round": round_number,
        "defender_a": state.get("defender_a_proposal"),
        "defender_b": proposal,
    }
    if debate_history and debate_history[-1].get("round") == round_number:
        debate_history[-1] = round_entry
    else:
        debate_history.append(round_entry)

    return {
        **state,
        "defender_b_proposal": proposal,
        "debate_history": debate_history,
    }

