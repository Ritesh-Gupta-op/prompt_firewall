FROM python:3.11.2-slim-bullseye AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements-dev.lock ./
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements-dev.lock
COPY backend ./backend
RUN python -m build --wheel --no-isolation --outdir /wheels backend

FROM python:3.11.2-slim-bullseye AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PROMPTFIREWALL_DATABASE_URL=sqlite+aiosqlite:////data/promptfirewall.db
WORKDIR /app
COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements.lock \
    && groupadd --gid 10001 firewall \
    && useradd --uid 10001 --gid firewall --no-create-home firewall \
    && mkdir /data && chown firewall:firewall /data /app
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir --no-deps /wheels/*.whl
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"
CMD ["python", "-m", "uvicorn", "promptfirewall.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
