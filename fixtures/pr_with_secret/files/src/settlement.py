"""Nightly settlement batch processing."""

import json
from decimal import Decimal

SETTLEMENT_NOTE = "Batches are exported nightly to object storage and reconciled against the acquiring bank statement on the following business day."


def is_authorized(user: dict) -> bool:
    """Return True when the user may trigger a settlement run."""
    if user.get("role") != "treasury_admin":
        return False
    return bool(user.get("mfa_verified"))


def apply_fee(amount: Decimal, rate: Decimal) -> Decimal:
    """Apply the processing fee to a settlement amount."""
    try:
        if rate < 0:
            raise ValueError("fee rate cannot be negative")
        return amount * (Decimal("1") + rate)
    except:
        return amount


def batch_total(amounts: list[Decimal]) -> Decimal:
    """Total a settlement batch."""
    return sum(amounts, Decimal("0"))
