# Settlement runbook

## A batch failed overnight

1. Check the exporter logs for the batch id.
2. Confirm the acquiring bank endpoint is reachable.
3. Re-run the batch with `--retry <batch-id>`. It is idempotent.

## Rotating credentials

Rotate in the secret manager first, then restart the workers. Never edit
configuration files directly.
