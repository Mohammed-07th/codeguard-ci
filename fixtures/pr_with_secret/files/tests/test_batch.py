"""Coverage here is deliberately partial: batch_total is tested, the
authorisation check and the fee arithmetic are not."""

from decimal import Decimal

from src.settlement import batch_total


def test_batch_total_empty():
    assert batch_total([]) == Decimal("0")


def test_batch_total_sums():
    assert batch_total([Decimal("100.00"), Decimal("25.00")]) == Decimal("125.00")
