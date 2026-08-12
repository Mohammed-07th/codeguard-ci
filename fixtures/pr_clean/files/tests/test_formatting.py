"""Tests covering every branch of src/formatting.py."""

from decimal import Decimal

import pytest

from src.formatting import format_currency, parse_currency, total


def test_format_currency_default():
    assert format_currency(Decimal("12.5")) == "12.50 SAR"


def test_format_currency_explicit():
    assert format_currency(Decimal("3"), "USD") == "3.00 USD"


def test_parse_currency_roundtrip():
    assert parse_currency("12.50 SAR") == Decimal("12.50")


def test_parse_currency_empty():
    with pytest.raises(ValueError):
        parse_currency("   ")


def test_parse_currency_invalid():
    with pytest.raises(ValueError):
        parse_currency("abc SAR")


def test_total_empty():
    assert total([]) == Decimal("0")


def test_total_sums():
    assert total([Decimal("1.5"), Decimal("2.5")]) == Decimal("4.0")
