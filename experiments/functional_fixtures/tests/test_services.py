"""
Unit tests for Functional Fixture Application defining expected correct behavior.
"""

import pytest
from experiments.functional_fixtures.app.services import (
    get_user_greeting,
    compute_cart_total,
    parse_numeric_identifier,
)


def test_user_greeting_none():
    """Verify greeting handles None user gracefully."""
    assert get_user_greeting(None) == "Guest"


def test_user_greeting_valid():
    """Verify greeting formats valid user data."""
    user = {"name": "alice", "role": "admin"}
    assert get_user_greeting(user) == "Welcome Alice (admin)"


def test_compute_cart_total_valid_discount():
    """Verify discount computation matches expected math (100 - 10% = 90)."""
    assert compute_cart_total(100.0, 10.0) == 90.0
    assert compute_cart_total(200.0, 25.0) == 150.0
    assert compute_cart_total(50.0, 0.0) == 50.0


def test_compute_cart_total_invalid_discount():
    """Verify discount validation rejects negative numbers or over 100."""
    with pytest.raises(ValueError):
        compute_cart_total(100.0, -5.0)
    with pytest.raises(ValueError):
        compute_cart_total(100.0, 105.0)


def test_parse_numeric_identifier():
    """Verify numeric ID parsing."""
    assert parse_numeric_identifier(" 1234 ") == 1234
    with pytest.raises(ValueError):
        parse_numeric_identifier("-10")
