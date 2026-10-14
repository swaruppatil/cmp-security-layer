"""Prepare the inputs of ``Dockerfile.prebuilt`` on a workstation.

    cd ml-service && uv run python prepare_prebuilt.py [--transformer horizon-small-int8]

* checks that ``models/current.json`` and ``models/tool/current.json`` name bundles that exist;
* downloads the transformer view's files into ``.cache/transformers/<name>/`` if they are missing;
* exports the locked runtime dependencies to ``requirements-prebuilt.txt`` and downloads their
  linux/arm64 wheels into ``.wheels/`` so the image installs them without network access (package
  downloads from inside Docker Desktop go through its proxy and are too slow or fail on this network).

Everything it writes is ignored by git; the image build copies it from the repository root context.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLATFORMS = ["manylinux_2_17_aarch64", "manylinux2014_aarch64", "manylinux_2_28_aarch64", "linux_aarch64"]


def check_bundles() -> None:
    for d in (HERE / "models", HERE / "models" / "tool"):
        pointer = d / "current.json"
        if not pointer.exists():
            sys.exit(f"{pointer} is missing: train first (python -m training.train ...)")
        bundle = d / json.loads(pointer.read_text())["file"]
        if not bundle.exists():
            sys.exit(f"{bundle} named by {pointer} is missing")
        print("bundle", bundle.relative_to(HERE))


def fetch_transformer(name: str) -> None:
    sys.path.insert(0, str(HERE))
    from app.transformer import ensure_files

    folder = ensure_files(name, HERE / ".cache")
    for f in ("model.onnx", "tokenizer.json", "config.json"):
        size = (folder / f).stat().st_size
        print(f"transformer {name}/{f}: {size / 1e6:.1f} MB")


def download_wheels() -> None:
    req = HERE / "requirements-prebuilt.txt"
    subprocess.run(
        ["uv", "export", "--frozen", "--no-dev", "--no-hashes", "--no-emit-project", "-o", str(req)],
        cwd=HERE,
        check=True,
    )
    wheels = HERE / ".wheels"
    wheels.mkdir(exist_ok=True)
    # pip evaluates the requirement markers (python_full_version < '3.12' ...) with the interpreter
    # that runs it, so run it with a 3.11 interpreter: uv provides one, with pip, without touching
    # the project venv.
    cmd = [
        "uv",
        "run",
        "--no-project",
        "--python",
        "3.11",
        "--with",
        "pip",
        "python",
        "-m",
        "pip",
        "download",
        "-q",
        "-r",
        str(req),
        "-d",
        str(wheels),
        "--python-version",
        "3.11",
        "--implementation",
        "cp",
        "--only-binary=:all:",
    ]
    for p in PLATFORMS:
        cmd += ["--platform", p]
    for abi in ("cp311", "abi3", "none"):
        cmd += ["--abi", abi]
    subprocess.run(cmd, cwd=HERE, check=True)
    files = sorted(wheels.glob("*.whl"))
    total = sum(f.stat().st_size for f in files)
    print(f"{len(files)} wheels, {total / 1e6:.0f} MB in {wheels.relative_to(HERE)}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--transformer", default="horizon-small-int8")
    ap.add_argument("--no-wheels", action="store_true", help="skip the wheel download")
    args = ap.parse_args()
    check_bundles()
    fetch_transformer(args.transformer)
    if not args.no_wheels:
        download_wheels()


if __name__ == "__main__":
    main()
