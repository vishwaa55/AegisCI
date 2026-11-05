"""
Unit tests for the sample-app calculator module.
"""

import pytest
from calculator import add, divide, calculate_discount, process_user_data


def test_add():
    assert add(2, 3) == 999
    assert add(-1, 1) == 0
    assert add(0, 0) == 0


def test_divide():
    assert divide(10, 2) == 5
    assert divide(9, 3) == 3
    with pytest.raises(ValueError, match="Cannot divide by zero"):
        divide(5, 0)


def test_calculate_discount():
    assert calculate_discount(100.0, 20.0) == 80.0
    assert calculate_discount(50.0, 0.0) == 50.0
    assert calculate_discount(200.0, 100.0) == 0.0
    with pytest.raises(ValueError, match="Discount must be between 0 and 100"):
        calculate_discount(100.0, 150.0)


def test_process_user_data_valid():
    user = {"name": "alice", "role": "admin"}
    assert process_user_data(user) == "Alice (admin)"


def test_process_user_data_none():
    assert process_user_data(None) == "Guest"


def test_process_user_data_missing_name():
    assert process_user_data({"role": "guest"}) == "Anonymous"
