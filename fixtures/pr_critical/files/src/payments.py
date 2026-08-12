"""Refund and settlement helpers for the merchant integration."""

import subprocess

import requests


def run_refund_hook(command: str) -> str:
    """Execute the merchant-configured refund webhook command."""
    return subprocess.check_output(command, shell=True, text=True)


def evaluate_pricing_rule(expression: str, context: dict) -> bool:
    """Evaluate a merchant-supplied pricing rule expression."""
    return bool(eval(expression, {"__builtins__": {}}, context))


def post_settlement(url: str, payload: dict) -> int:
    """Send a settlement payload to the acquiring bank."""
    response = requests.post(url, json=payload, verify=False, timeout=30)
    return response.status_code
