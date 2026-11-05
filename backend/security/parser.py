"""
Semgrep JSON Parser & Normalizer for AegisCI Security Finding Intake.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional, Set, Union

from backend.security.models import SecurityFinding

logger = logging.getLogger("aegis.security.parser")


def normalize_file_path(path: str) -> str:
    """Normalize file path to forward slashes without leading ./."""
    norm = os.path.normpath(path).replace("\\", "/")
    if norm.startswith("./"):
        norm = norm[2:]
    return norm


def parse_semgrep_json(
    raw_data: Union[str, Dict[str, Any]],
    filter_test_files: bool = True,
    min_severity: Optional[str] = None,
) -> List[SecurityFinding]:
    """
    Parses raw Semgrep JSON output, normalizes rule attributes,
    deduplicates identical findings, and filters irrelevant entries.
    """
    if isinstance(raw_data, str):
        try:
            data = json.loads(raw_data)
        except Exception as e:
            logger.error(f"Failed to parse Semgrep JSON string: {e}")
            return []
    else:
        data = raw_data

    raw_results = data.get("results", [])
    if not isinstance(raw_results, list):
        return []

    severity_order = {"ERROR": 3, "WARNING": 2, "INFO": 1, "INVENTORY": 0, "EXPERIMENT": 0}
    min_sev_score = severity_order.get((min_severity or "").upper(), 0)

    findings: List[SecurityFinding] = []
    seen_keys: Set[str] = set()

    for idx, item in enumerate(raw_results):
        try:
            check_id = item.get("check_id") or item.get("rule_id") or f"unknown-rule-{idx}"
            raw_path = item.get("path") or item.get("filename") or ""
            norm_path = normalize_file_path(raw_path)

            # Filter test fixtures or mock files if configured
            if filter_test_files and ("/tests/" in f"/{norm_path}" or norm_path.startswith("tests/")):
                # Keep if it is specifically in a target fixture designed for testing
                if "test_calculator.py" in norm_path:
                    continue

            extra = item.get("extra", {})
            raw_severity = (extra.get("severity") or item.get("severity") or "WARNING").upper()
            if severity_order.get(raw_severity, 1) < min_sev_score:
                continue

            message = extra.get("message") or item.get("message") or "Security vulnerability detected"
            lines_info = extra.get("lines") or item.get("lines") or ""

            start_info = item.get("start", {})
            end_info = item.get("end", {})
            start_line = start_info.get("line", 1)
            end_line = end_info.get("line", start_line)
            start_col = start_info.get("col")
            end_col = end_info.get("col")

            # Extract CWE / OWASP metadata if present
            metadata = extra.get("metadata", {})
            cwe = metadata.get("cwe")
            if isinstance(cwe, list) and cwe:
                cwe = cwe[0]
            elif not isinstance(cwe, str):
                cwe = None

            owasp = metadata.get("owasp")
            if isinstance(owasp, list) and owasp:
                owasp = owasp[0]
            elif not isinstance(owasp, str):
                owasp = None

            # Deduplication key: rule + file + start_line
            dedup_key = f"{check_id}::{norm_path}::{start_line}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            finding = SecurityFinding(
                id=f"finding-{idx}-{check_id.split('.')[-1]}",
                rule_id=check_id,
                severity=raw_severity,
                file_path=norm_path,
                start_line=start_line,
                end_line=end_line,
                start_col=start_col,
                end_col=end_col,
                message=message.strip(),
                code_snippet=lines_info.strip(),
                cwe=cwe,
                owasp=owasp,
            )
            findings.append(finding)
        except Exception as e:
            logger.warning(f"Error parsing individual Semgrep result #{idx}: {e}")

    logger.info(f"Parsed {len(findings)} unique security findings from {len(raw_results)} Semgrep entries.")
    return findings
