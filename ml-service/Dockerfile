# Build context: the repository root (the image needs ../datasets to train the model).
#   docker compose build ml-service
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY ml-service/pyproject.toml ml-service/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY ml-service/app ./app
COPY ml-service/training ./training
COPY ml-service/evaluation ./evaluation
COPY datasets /datasets
ENV PATH="/app/.venv/bin:$PATH"
# Train at build time: every image carries known, reproducible models (version, thresholds and
# held-out evaluation in /v1/model). This also downloads the embedding model (~230 MB ONNX) into
# /app/.cache, so the running container never needs network access.
#  * chat model (customer messages), --strict: the build fails when the model misses its
#    false-positive budget on realistic held-out customer text;
#  * tool-content model (tool output the AI reads), trained on the chat data plus /datasets/tool and
#    calibrated on tool content, budget checked on the tool held-out set.
RUN python -m training.train --data /datasets --out /app/models --cache-dir /app/.cache --no-report --strict \
 && python -m training.train --data /datasets --data /datasets/tool --out /app/models/tool \
      --cache-dir /app/.cache --no-report --name tool --budget-set toolcontent --budget-set handwritten
RUN useradd --create-home appuser && chown -R appuser /app
USER appuser
ENV ML_MODEL_DIR=/app/models ML_EMBED_CACHE_DIR=/app/.cache HF_HUB_OFFLINE=1
# Latency: ONNX Runtime gets 2 threads per call; numpy/BLAS gets 1. Letting BLAS spawn a thread per
# core makes it fight ONNX for the CPU and doubles scoring time (measured 14 ms → 6 ms p50).
ENV ML_EMBED_THREADS=2 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
