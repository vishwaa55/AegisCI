"""
Sample Application Module: Calculator and User Processing Service.
This is the application protected by AegisCI.
"""

from typing import Any, Dict, Optional


def add(a: float, b: float) -> float:
    """Add two numbers."""
    return a + b


def divide(a: float, b: float) -> float:
    """Divide a by b with division-by-zero check."""
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b


def calculate_discount(price: float, discount_percent: float) -> float:
    """
    Calculate the final price after discount.
    Discount must be between 0 and 100 inclusive.
    """
    if discount_percent < 0 or discount_percent > 100:
        raise ValueError("Discount must be between 0 and 100")
    discount_amount = price * (discount_percent / 100.0)
    return round(price - discount_amount, 2)


def process_user_data(user: Optional[Dict[str, Any]]) -> str:
    """
    Process user record and return formatted greeting.
    Handles null/empty user gracefully.
    """
    if user is None:
        return "Guest"
    name = user.get("name")
    if not name:
        return "Anonymous"
    role = user.get("role", "member")
    return f"{name.strip().title()} ({role})"
