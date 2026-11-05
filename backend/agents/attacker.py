"""
Attacker Agent — assesses exploitability of a security finding.

Given a Semgrep finding and the affected source code, the agent reasons about
attack vectors, trust boundaries, and constructs a hypothetical exploit
scenario.  It never claims confirmed exploitability without code evidence.
"""

import json
import logging
from typing import Any, Dict

from backend.agents.llm_client import LLMClient
from backend.agents.state import AegisAgentState

logger = logging.getLogger("aegis.attacker")


def attacker_agent(state: AegisAgentState) -> AegisAgentState:
    """
    Attacker Agent node.

    Reads the active security finding from state, reads the affected file,
    and asks the LLM to produce a structured threat assessment.
    """
    incident_id = state.get("incident_id", "unknown")
    findings = state.get("security_findings", [])
    active_id = state.get("active_finding_id")

    finding = next(
        (f for f in findings if f.get("id") == active_id),
        findings[0] if findings else None,
    )

    if not finding:
        logger.warning(f"[{incident_id}] Attacker Agent: no active finding, skipping.")
        return {**state, "attacker_assessment": None}

    rule_id = finding.get("rule_id", "unknown-rule")
    severity = finding.get("severity", "WARNING")
    file_path = finding.get("file_path", "")
    start_line = finding.get("start_line", 1)
    message = finding.get("message", "")
    code_snippet = finding.get("code_snippet", "")
    cwe = finding.get("cwe", "")
    owasp = finding.get("owasp", "")

    logger.info(
        f"[{incident_id}] Attacker Agent assessing finding '{rule_id}' "
        f"in {file_path}:{start_line}"
    )

    system_prompt = (
        "You are an expert offensive security researcher working for AegisCI.\n"
        "Given a static analysis finding and the affected source code, produce a "
        "structured threat assessment in JSON.\n\n"
        "Output ONLY a JSON object with this exact schema:\n"
        "{\n"
        '  "exploitability": "unlikely" | "plausible" | "confirmed",\n'
        '  "attack_vector": "<single sentence>",\n'
        '  "attacker_controlled_inputs": ["<input1>", "..."],\n'
        '  "trust_boundaries": "<which boundary is crossed>",\n'
        '  "exploit_scenario": "<numbered step-by-step scenario>",\n'
        '  "evidence_vs_assumptions": "<what is confirmed by code vs what is assumed>",\n'
        '  "confidence": 0.0\n'
        "}\n\n"
        "RULES:\n"
        "1. Only mark exploitability 'confirmed' if the code clearly contains the "
        "vulnerability with no missing components.\n"
        "2. Distinguish confirmed evidence from assumptions explicitly.\n"
        "3. Keep each field concise."
    )

    user_prompt = (
        f"Security Finding:\n"
        f"  Rule: {rule_id}\n"
        f"  Severity: {severity}\n"
        f"  File: {file_path}, Line: {start_line}\n"
        f"  Message: {message}\n"
        f"  CWE: {cwe or 'N/A'}   OWASP: {owasp or 'N/A'}\n\n"
        f"Flagged Code Snippet:\n```\n{code_snippet or '(not available)'}\n```\n\n"
        "Assess the exploitability and describe the threat model:"
    )

    llm = LLMClient()
    try:
        assessment_data = llm.generate_json(system_prompt, user_prompt)
    except Exception as e:
        logger.error(f"[{incident_id}] Attacker LLM call failed: {e}")
        assessment_data = {
            "exploitability": "plausible",
            "attack_vector": f"LLM unavailable — manual review required for {rule_id}",
            "attacker_controlled_inputs": [],
            "trust_boundaries": "unknown",
            "exploit_scenario": f"Could not auto-generate — {str(e)[:200]}",
            "evidence_vs_assumptions": "LLM failure — treat as unconfirmed.",
            "confidence": 0.4,
        }

    assessment_data["finding_id"] = active_id or (findings[0].get("id") if findings else "")
    logger.info(
        f"[{incident_id}] Attacker assessment: exploitability="
        f"{assessment_data.get('exploitability')}, confidence={assessment_data.get('confidence')}"
    )

    return {
        **state,
        "attacker_assessment": assessment_data,
    }

