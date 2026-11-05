"""
Reset and Failure Injection Harness for Functional Experiments.

Provides automated commands to:
1. Inject a failing unit test (missing null check)
2. Inject a logic bug (wrong discount calculation)
3. Inject a syntax failure (invalid syntax)
4. Inject a missing dependency failure (unresolvable module import)
5. Reset all fixtures back to clean passing baseline
6. Run tests and report output
"""

import argparse
import os
import subprocess
import sys

BASE_SERVICES_CONTENT = '''"""
Controlled Functional Fixture Application for AegisCI Experiments.
Provides isolated services that can be intentionally mutated to produce reproducible failure modes.
"""

from typing import Any, Dict, List, Optional


def get_user_greeting(user: Optional[Dict[str, Any]]) -> str:
    """
    Format user greeting safely.
    Expected behavior: Return 'Guest' if user is None or empty.
    """
    if user is None:
        return "Guest"
    name = user.get("name")
    if not name:
        return "Guest"
    role = user.get("role", "member")
    return f"Welcome {name.strip().title()} ({role})"


def compute_cart_total(price: float, discount_percent: float) -> float:
    """
    Calculate final cart total after discount.
    Discount must be between 0 and 100 inclusive.
    """
    if discount_percent < 0 or discount_percent > 100:
        raise ValueError("Discount must be between 0 and 100")
    discount_amount = price * (discount_percent / 100.0)
    return round(price - discount_amount, 2)


def parse_numeric_identifier(raw_id: str) -> int:
    """
    Parse a numeric identifier from input string.
    Expected behavior: Returns positive integer.
    """
    cleaned = raw_id.strip()
    val = int(cleaned)
    if val < 0:
        raise ValueError("Identifier must be non-negative")
    return val
'''

SERVICES_FILE = os.path.join(os.path.dirname(__file__), "app", "services.py")


def reset_to_clean():
    """Restore services.py to its original, fully passing baseline state."""
    with open(SERVICES_FILE, "w", encoding="utf-8") as f:
        f.write(BASE_SERVICES_CONTENT)
    print("[RESET] services.py restored to clean, passing baseline.")


def inject_null_check_bug():
    """Failure Mode 1: Missing null check leading to AttributeError."""
    buggy = BASE_SERVICES_CONTENT.replace(
        '    if user is None:\n        return "Guest"\n',
        '    # BUG: missing null check\n',
    )
    with open(SERVICES_FILE, "w", encoding="utf-8") as f:
        f.write(buggy)
    print("[INJECTED] Scenario 1: Missing null check in get_user_greeting.")


def inject_logic_bug():
    """Failure Mode 2: Arithmetic/operator bug in discount calculation."""
    buggy = BASE_SERVICES_CONTENT.replace(
        "return round(price - discount_amount, 2)",
        "return round(price + discount_amount, 2)  # BUG: adds discount instead of subtracting",
    )
    with open(SERVICES_FILE, "w", encoding="utf-8") as f:
        f.write(buggy)
    print("[INJECTED] Scenario 2: Inverted operator in compute_cart_total.")


def inject_syntax_error():
    """Failure Mode 3: Python syntax error in module."""
    buggy = BASE_SERVICES_CONTENT.replace(
        "def parse_numeric_identifier(raw_id: str) -> int:",
        "def parse_numeric_identifier(raw_id: str -> int:  # BUG: missing closing parenthesis",
    )
    with open(SERVICES_FILE, "w", encoding="utf-8") as f:
        f.write(buggy)
    print("[INJECTED] Scenario 3: Syntax error in parse_numeric_identifier.")


def inject_missing_dependency():
    """Failure Mode 4: Unresolvable module import."""
    buggy = "import non_existent_jwt_telemetry_sdk  # BUG: missing dependency\n" + BASE_SERVICES_CONTENT
    with open(SERVICES_FILE, "w", encoding="utf-8") as f:
        f.write(buggy)
    print("[INJECTED] Scenario 4: Missing dependency import at top of module.")


def run_tests() -> int:
    """Run pytest on the fixture test suite and print results."""
    tests_dir = os.path.join(os.path.dirname(__file__), "tests")
    print(f"\n--- Running pytest on {tests_dir} ---")
    res = subprocess.run([sys.executable, "-m", "pytest", "-v", tests_dir], capture_output=False)
    print(f"--- Test Exit Code: {res.returncode} ---")
    return res.returncode


def main():
    parser = argparse.ArgumentParser(description="Functional Fixtures Failure Injection & Reset Harness")
    parser.add_argument(
        "--scenario",
        choices=["null_check", "logic_bug", "syntax_error", "missing_dep"],
        help="Failure scenario to inject",
    )
    parser.add_argument("--reset", action="store_true", help="Reset all files to passing state")
    parser.add_argument("--test", action="store_true", help="Run fixture tests immediately")

    args = parser.parse_args()

    if args.reset or not args.scenario:
        reset_to_clean()

    if args.scenario == "null_check":
        inject_null_check_bug()
    elif args.scenario == "logic_bug":
        inject_logic_bug()
    elif args.scenario == "syntax_error":
        inject_syntax_error()
    elif args.scenario == "missing_dep":
        inject_missing_dependency()

    if args.test:
        run_tests()


if __name__ == "__main__":
    main()
