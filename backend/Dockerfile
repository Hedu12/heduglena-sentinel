FROM python:3.11-slim AS builder

WORKDIR /build
COPY pyproject.toml .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir build && \
    pip install --no-cache-dir -e ".[dev]" --dry-run 2>/dev/null || true

# Install runtime deps only
COPY . .
RUN pip install --no-cache-dir -e "."

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Non-root user (SR-05: Least Privilege)
RUN groupadd --gid 1001 sentinel && \
    useradd --uid 1001 --gid sentinel --shell /bin/bash --create-home sentinel

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --chown=sentinel:sentinel . .

# Data directory for SQLite volume mount
RUN mkdir -p /data && chown sentinel:sentinel /data

USER sentinel

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
