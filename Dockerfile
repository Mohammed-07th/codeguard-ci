# CodeGuard CI — application image.
#
# Python 3.11 deliberately: the dependency set was resolved and verified there,
# and several packages in it are not usable on 3.14.
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# curl is here for the container healthcheck and so the webhook demo can be run
# from inside the container as well as from the host.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies first: this layer is cached unless requirements.txt changes, so
# editing source does not trigger a full reinstall.
COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install -e . --no-deps

# Fixtures ship with the image so the deployed service can review the bundled
# demo pull requests without a mounted volume.
COPY fixtures/ ./fixtures/

# Written at runtime. Declared here so they exist with the right ownership even
# when no volume is mounted over them.
RUN mkdir -p state workdir artifacts evidence

# The agents run static analysers over untrusted PR content and never execute it,
# but running as a non-root user keeps the blast radius small if that ever changes.
RUN useradd --create-home --uid 10001 codeguard \
    && chown -R codeguard:codeguard /app
USER codeguard

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "codeguard.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
