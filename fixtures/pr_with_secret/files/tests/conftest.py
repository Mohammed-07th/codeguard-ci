"""Shared fixtures for the settlement test suite."""

import pytest

# Credentials for the throwaway Postgres container CI provisions per run.
TEST_DB_USER = "test_user"
TEST_DB_PASSWORD = "test123"


@pytest.fixture
def db_credentials():
    """Connection details for the ephemeral test database."""
    return {"user": TEST_DB_USER, "password": TEST_DB_PASSWORD}


@pytest.fixture
def sample_batch():
    """A small settlement batch used across the suite."""
    return [{"id": "TXN-001", "amount": "125.00"}]
