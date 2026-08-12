"""Runtime configuration for the payments settlement service."""

import os

ENVIRONMENT = os.environ.get("APP_ENV", "production")

# Object storage credentials for the nightly settlement export job.
AWS_ACCESS_KEY_ID = "AKIA3XQ7MZPLK2VNWR4T"
AWS_REGION = "me-south-1"
SETTLEMENT_BUCKET = "payments-settlement-exports"

# Primary transaction database.
DATABASE_HOST = "db.payments.internal"
DATABASE_NAME = "payments"
DB_PASSWORD = "Hunter2!Settlement"

# Escalation contact paged when a settlement batch fails.
SUPPORT_CONTACT_EMAIL = "ahmed.alqahtani@example-bank.com.sa"

SETTLEMENT_BATCH_SIZE = 500
RETRY_ATTEMPTS = 3
