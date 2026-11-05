import logging
import os
import re
from typing import Dict, List, Optional, Tuple
from backend.agents.llm_client import LLMClient
from backend.agents.state import AegisAgentState

logger = logging.getLogger("aegis.fix_proposer")

FORBIDDEN_PATTERNS = [
    r"^\.github/",
    r"\.github/workflows/",
    r"\.env",
    r"secrets?",
    r"\.key$",
    r"\.pem$",
    r"id_rsa",
    r"credentials",
]


def extract_files_from_diff(patch_diff: str) -> List[str]:
    """Extract touched file paths from a unified diff."""
    files = set()
    for line in patch_diff.splitlines():
        if line.startswith("--- a/"):
            files.add(line[6:].strip())
        elif line.startswith("+++ b/"):
            files.add(line[6:].strip())
        elif line.startswith("--- "):
            p = line[4:].strip()
            if p.startswith("a/"):
                p = p[2:]
            if p != "/dev/null":
                files.add(p)
        elif line.startswith("+++ "):
            p = line[4:].strip()
            if p.startswith("b/"):
                p = p[2:]
            if p != "/dev/null":
                files.add(p)
    return list(files)


def validate_patch_guardrails(patch_diff: str, allowed_files: List[str]) -> Tuple[bool, Optional[str]]:
    """
    Guardrail Verification:
    1. Reject patches touching CI configuration (.github/, ci.yml).
    2. Reject patches touching secret/credential files (.env, keys).
    3. Reject patches modifying files outside diagnosed affected_files list.
    """
    if not patch_diff or not patch_diff.strip():
        return False, "Patch diff is empty"

    touched_files = extract_files_from_diff(patch_diff)
    if not touched_files:
        # Fallback: check if diff mentions affected file anywhere in header
        for f in allowed_files:
            if f in patch_diff:
                touched_files.append(f)
        if not touched_files:
            return False, "Could not determine touched files from unified diff headers"

    norm_allowed = [os.path.normpath(f).replace("\\", "/").lower() for f in allowed_files]

    for touched in touched_files:
        norm_touched = os.path.normpath(touched).replace("\\", "/").lower()

        # Check forbidden patterns (CI & secrets)
        for pattern in FORBIDDEN_PATTERNS:
            if re.search(pattern, norm_touched, re.IGNORECASE):
                return False, f"Guardrail violation: Patch attempts to modify forbidden/sensitive path '{touched}'"

        # Check if outside diagnosed affected files
        if not any(norm_touched == af or norm_touched.endswith(af) or af.endswith(norm_touched) for af in norm_allowed):
            return False, f"Guardrail violation: Patch modifies '{touched}' which is outside diagnosed files ({allowed_files})"

    return True, None


def clean_diff_markdown(raw_diff: str) -> str:
    """Extract clean unified diff content removing markdown fences."""
    diff = raw_diff.strip()
    if diff.startswith("```diff"):
        diff = diff[7:]
    elif diff.startswith("```patch"):
        diff = diff[8:]
    elif diff.startswith("```"):
        diff = diff[3:]
    if diff.endswith("```"):
        diff = diff[:-3]
    return diff.strip()


def fix_proposer_agent(state: AegisAgentState) -> AegisAgentState:
    """
    Fix-Proposer Agent:
    Reads current file contents, retrieves rejection-memory context from ChromaDB,
    invokes LLM to generate a minimal unified diff patch, and applies strict
    guardrail verification against CI tampering and unauthorized edits.
    """
    incident_id = state.get("incident_id", "unknown")
    category = state.get("diagnosis_category", "unknown")
    evidence = state.get("evidence", "")
    affected_files = state.get("affected_files", [])
    current_attempt = state.get("current_attempt", 0) + 1
    previous_test_output = state.get("test_output", "")

    logger.info(f"[{incident_id}] Fix-Proposer Agent generating fix (Attempt {current_attempt})...")

    # ── Rejection-Memory RAG: retrieve past failures ──────────────────────
    rejection_memory_context = ""
    try:
        from backend.memory.rejection_memory import RejectionMemory  # noqa: PLC0415
        mem = RejectionMemory()
        if mem.count() > 0:
            similar = mem.retrieve_similar(
                query_diagnosis=category or "",
                query_evidence=evidence or "",
                top_k=3,
            )
            if similar:
                mem_lines = []
                for entry in similar:
                    meta = entry.get("metadata", {})
                    mem_lines.append(
                        f"- Attempt {meta.get('attempt', '?')} for incident "
                        f"'{meta.get('incident_id', '?')}': "
                        f"Rejected because: {meta.get('rejection_reason', '?')} "
                        f"[distance={entry.get('distance', 0):.3f}]"
                    )
                rejection_memory_context = (
                    "REJECTION MEMORY — the following similar approaches were tried and FAILED.\n"
                    "Do NOT repeat these strategies:\n" + "\n".join(mem_lines)
                )
                logger.info(
                    f"[{incident_id}] Retrieved {len(similar)} rejection-memory entries."
                )
    except Exception as e:
        logger.warning(f"[{incident_id}] Rejection memory retrieval skipped: {e}")

    # Read affected files content from disk
    files_content_map: Dict[str, str] = {}
    for rel_path in affected_files:
        norm_path = os.path.normpath(rel_path)
        if os.path.isfile(norm_path):
            try:
                with open(norm_path, "r", encoding="utf-8") as f:
                    files_content_map[rel_path] = f.read()
            except Exception as e:
                logger.error(f"[{incident_id}] Could not read {rel_path}: {e}")

    # Build prompt context
    files_context = ""
    for path, content in files_content_map.items():
        files_context += f"\n--- File: {path} ---\n{content}\n"

    attempt_feedback = ""
    if current_attempt > 1 and previous_test_output:
        attempt_feedback = (
            f"\nATTENTION: A previous fix attempt failed with the following test output:\n"
            f"```\n{previous_test_output}\n```\n"
            "Please analyze why the previous patch failed and propose an improved solution.\n"
        )

    system_prompt = (
        "You are an expert Autonomous Software Repair Agent for AegisCI.\n"
        "Your task is to fix the software bug diagnosed in the CI/CD pipeline.\n"
        "You MUST generate the fix strictly as a UNIFIED DIFF patch (standard diff format with --- a/file and +++ b/file).\n"
        "CRITICAL RULES:\n"
        "1. Do NOT rewrite the whole file; produce a minimal, surgical unified diff patch.\n"
        "2. Do NOT touch any CI workflow files, Dockerfiles, or secrets.\n"
        "3. Only modify the diagnosed affected files.\n"
        "4. Output ONLY the raw unified diff inside a ```diff code block.\n"
        "5. Ensure line numbers, context lines, and indentation are precise."
    )

    cleaned_logs = state.get("cleaned_logs", "")

    rejection_section = f"\n{rejection_memory_context}\n" if rejection_memory_context else ""

    user_prompt = (
        f"Incident ID: {incident_id}\n"
        f"Diagnosis Category: {category}\n"
        f"Diagnosis Evidence:\n{evidence}\n\n"
        f"CI Failure Logs & Traceback:\n```\n{cleaned_logs}\n```\n\n"
        f"Affected File(s) Contents:\n{files_context}\n"
        f"{rejection_section}"
        f"{attempt_feedback}\n"
        "Generate the unified diff patch to resolve the failure:"
    )

    llm = LLMClient()
    raw_response = llm.generate_text(system_prompt, user_prompt, temperature=0.2)
    patch_diff = clean_diff_markdown(raw_response)

    # Validate patch with guardrails
    guardrail_passed, guardrail_error = validate_patch_guardrails(patch_diff, affected_files)
    if not guardrail_passed:
        logger.warning(f"[{incident_id}] Fix patch failed guardrail validation: {guardrail_error}")
    else:
        logger.info(f"[{incident_id}] Fix patch successfully passed all safety guardrails.")

    return {
        **state,
        "current_patch": patch_diff,
        "guardrail_passed": guardrail_passed,
        "guardrail_error": guardrail_error,
        "current_attempt": current_attempt,
        "rejection_memory_context": rejection_memory_context,
    }
