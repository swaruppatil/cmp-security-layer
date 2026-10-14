# Test runner for test-phase environments: the gateway's scripts (scenario suite, coverage traffic,
# try_message) with the datasets they read, reachable through ECS Exec. Build context: repository root.
#   aws ecs execute-command --cluster <cluster> --task <task> --container test-runner --interactive \
#       --command "python -m scripts.run_scenarios"
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY gateway/pyproject.toml gateway/uv.lock ./
RUN uv sync --frozen --no-install-project
COPY gateway/app ./app
COPY gateway/scripts ./scripts
COPY datasets /datasets
ENV PATH="/app/.venv/bin:$PATH" PYTHONPATH=/app
CMD ["sleep", "infinity"]
