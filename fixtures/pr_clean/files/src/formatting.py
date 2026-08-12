"""Currency rendering helpers for invoice line items."""

from decimal import Decimal, InvalidOperation

DEFAULT_CURRENCY = "SAR"


def format_currency(amount: Decimal, currency: str = DEFAULT_CURRENCY) -> str:
    """Render an amount with two decimal places and a currency suffix."""
    return f"{amount:.2f} {currency}"


def parse_currency(text: str) -> Decimal:
    """Parse a string such as '12.50 SAR' back into a Decimal.

    Raises:
        ValueError: if the text does not start with a decimal number.
    """
    parts = text.strip().split()
    if not parts:
        raise ValueError("empty currency string")
    try:
        return Decimal(parts[0])
    except InvalidOperation as exc:
        raise ValueError(f"not a valid amount: {text!r}") from exc


def total(amounts: list[Decimal]) -> Decimal:
    """Sum a list of amounts, returning zero for an empty list."""
    return sum(amounts, Decimal("0"))
