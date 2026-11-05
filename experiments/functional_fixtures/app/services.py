"""
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
