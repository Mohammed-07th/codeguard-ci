# Payments Service

Handles settlement batching and refund processing for merchant accounts.

## Running locally

    uv venv --python 3.11
    uv pip install -r requirements.txt
    python -m src.settlement --once

## Configuration

All credentials are read from the environment. Nothing is committed.

| Variable | Purpose |
|----------|---------|
| `AWS_ACCESS_KEY_ID` | Object storage for settlement exports |
| `DB_PASSWORD` | Primary transaction database |
| `SUPPORT_CONTACT_EMAIL` | Escalation contact for failed batches |
