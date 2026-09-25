import json
import logging
import os
import re
from typing import Any, Dict, List
from backend.agents.llm_client import LLMClient
from backend.agents.state import AegisAgentState

logger = logging.getLogger("aegis.diagnosis")


def strip_ansi_codes(text: str) -> str:
    """Strip ANSI escape sequences from terminal and CI output."""
    ansi_regex = re.compile(
        r'''
        \x1b     # ESC
        (?:      # 7-bit C1 Fe
            [@-Z\\-_]
        |        # or [ for CSI, followed by parameter bytes and final byte
            \[
            [0-?]*  # Parameter bytes
            [ -/]*  # Intermediate bytes
            [@-~]   # Final byte
        )
        ''',
        re.VERBOSE
    )
    return ansi_regex.sub('', text)


def preprocess_ci_log(raw_logs: str, max_lines: int = 250) -> str:
    """
    Extracts the relevant error/failure block from raw CI logs.
    Avoids sending massive raw logs to LLM.
    """
    clean_text = strip_ansi_codes(raw_logs or "")
    lines = clean_text.splitlines()

    # Look for common test failure section markers
    error_markers = [
        "=== FAILURES ===",
        "=== ERRORS ===",
        "FAILURES",
        "Traceback (most recent call last):",
        "FAILED ",
        "AssertionError",
        "ModuleNotFoundError",
        "ImportError",
        "SyntaxError",
        "TypeError",
        "ValueError",
        "NameError",
        "short test summary info",
        "eslint",
        "flake8",
        "ruff",
    ]

    start_idx = -1
    for i, line in enumerate(lines):
        if any(marker in line for marker in error_markers):
            start_idx = max(0, i - 10)  # include 10 lines of context before
            break

    if start_idx != -1:
        extracted = lines[start_idx:start_idx + max_lines]
        return "\n".join(extracted).strip()

    # If no specific marker found, take the trailing lines where failures usually appear
    return "\n".join(lines[-max_lines:]).strip()


def diagnosis_agent(state: AegisAgentState) -> AegisAgentState:
    """
    Diagnosis Agent:
    Preprocesses logs and uses structured LLM output to classify failure,
    estimate confidence, extract evidence, and identify affected files.
    """
    incident_id = state.get("incident_id", "unknown")
    raw_logs = state.get("raw_logs", "")

    cleaned_logs = preprocess_ci_log(raw_logs)
    logger.info(f"[{incident_id}] Preprocessed CI logs ({len(raw_logs)} chars -> {len(cleaned_logs)} chars).")

    system_prompt = (
        "You are an expert CI/CD Root Cause Diagnosis Agent for AegisCI.\n"
        "Analyze the provided CI/CD error log and output a JSON object with EXACTLY the following structure:\n"
        "{\n"
        '  "category": "dependency_error" | "test_assertion_failure" | "flaky_test" | "lint_error",\n'
        '  "confidence": 0.0 to 1.0,\n'
        '  "affected_files": ["relative/path/to/file.py"],\n'
        '  "evidence": "concise explanation and quote of the failing line or error message"\n'
        "}\n\n"
        "RULES:\n"
        "1. 'category' MUST be one of: 'dependency_error', 'test_assertion_failure', 'flaky_test', 'lint_error'.\n"
        "2. 'affected_files' must be a list of relative file paths in the repository that need fixing (e.g. 'sample-app/calculator.py' or 'sample-app/requirements.txt'). Avoid test files if the bug is in the source code.\n"
        "3. Keep evidence concise and factual."
    )

    user_prompt = f"CI Failure Error Logs:\n```\n{cleaned_logs}\n```"

    llm = LLMClient()
    try:
        diagnosis_data = llm.generate_json(system_prompt, user_prompt)
    except Exception as e:
        logger.error(f"[{incident_id}] LLM diagnosis failed: {e}")
        diagnosis_data = {
            "category": "test_assertion_failure",
            "confidence": 0.5,
            "affected_files": ["sample-app/calculator.py"],
            "evidence": f"LLM error fallback: {str(e)}",
        }

    # Normalize category
    category = diagnosis_data.get("category", "test_assertion_failure")
    valid_categories = ["dependency_error", "test_assertion_failure", "flaky_test", "lint_error"]
    if category not in valid_categories:
        category = "test_assertion_failure"

    confidence = float(diagnosis_data.get("confidence", 0.8))
    affected_files = diagnosis_data.get("affected_files", [])
    if isinstance(affected_files, str):
        affected_files = [affected_files]
    evidence = diagnosis_data.get("evidence", "")

    # Clean file paths (remove leading ./, normalize slashes)
    cleaned_affected_files: List[str] = []
    for f in affected_files:
        f_norm = os.path.normpath(f).replace("\\", "/")
        if f_norm.startswith("./"):
            f_norm = f_norm[2:]
        cleaned_affected_files.append(f_norm)

    # If affected_files is empty, attempt to infer from logs
    if not cleaned_affected_files:
        match = re.search(r'sample-app/[a-zA-Z0-9_\-\./]+\.py', cleaned_logs)
        if match:
            cleaned_affected_files.append(match.group(0))
        else:
            cleaned_affected_files.append("sample-app/calculator.py")

    logger.info(
        f"[{incident_id}] Diagnosis completed: category={category}, "
        f"confidence={confidence}, affected_files={cleaned_affected_files}"
    )

    return {
        **state,
        "cleaned_logs": cleaned_logs,
        "diagnosis_category": category,
        "diagnosis_confidence": confidence,
        "affected_files": cleaned_affected_files,
        "evidence": evidence,
    }
