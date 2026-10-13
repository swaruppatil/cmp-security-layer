"""Write the gateway's OpenAPI document to docs/openapi.json (no running services needed).

    cd gateway && uv run python -m scripts.export_openapi

The live, browsable version is at http://localhost:18080/docs (Swagger UI) and /redoc.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.main import create_app
from tests.fakes import make_settings

OUT = Path(__file__).resolve().parents[2] / "docs" / "openapi.json"


def main() -> None:
    spec = create_app(settings=make_settings()).openapi()
    OUT.write_text(json.dumps(spec, indent=2) + "\n")
    print(f"wrote {OUT.relative_to(OUT.parents[1])}: {len(spec['paths'])} paths")


if __name__ == "__main__":
    main()
