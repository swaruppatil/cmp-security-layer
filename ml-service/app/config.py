"""ML service settings, read from the environment (prefix ``ML_``)."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ML_", extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"
    # Directory holding trained model bundles and current.json.
    model_dir: str = "models"
    # Where the embedding model's ONNX files are cached (baked into the image at build time).
    embed_cache_dir: str | None = None
    # ONNX Runtime threads per scoring call (2: ~6 ms p50 for a short message; more threads help a
    # single call but compete under concurrency). Pin BLAS to 1 thread too — see the Dockerfile.
    embed_threads: int = 2
    # Serve the bundles' transformer view under another registry name, e.g. "horizon-small-int8" for the
    # int8 build of the same model (smaller image, same decisions within noise). Only applies to bundles
    # trained with a transformer view; None serves the name recorded in the bundle.
    transformer_name: str | None = None
    # Keep the model warm: score a dummy text after this many idle seconds (0 = off). See keep_warm.
    keep_warm_seconds: float = 1.0


settings = Settings()
