from __future__ import annotations

import importlib.util
import os
import platform
import site
import sys
from pathlib import Path


def check_module(name: str) -> str:
    spec = importlib.util.find_spec(name)
    return "OK" if spec is not None else "MISSING"


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]

    print("=== LeakLens environment check ===")
    print(f"Project root: {project_root}")
    print(f"Current working directory: {Path.cwd()}")
    print()

    print("=== Python ===")
    print(f"Executable: {sys.executable}")
    print(f"Version: {sys.version}")
    print(f"Platform: {platform.platform()}")
    print(f"Architecture: {platform.architecture()[0]}")
    print()

    print("=== Virtual environment ===")
    print(f"VIRTUAL_ENV: {os.environ.get('VIRTUAL_ENV')}")
    print(f"sys.prefix: {sys.prefix}")
    print(f"sys.base_prefix: {sys.base_prefix}")
    print(f"Inside venv: {sys.prefix != sys.base_prefix}")
    print()

    print("=== pip / site-packages ===")
    try:
        import pip

        print(f"pip: OK ({pip.__version__})")
    except Exception as exc:
        print(f"pip: ERROR ({exc})")

    try:
        print("site-packages:")
        for path in site.getsitepackages():
            print(f"  - {path}")
    except Exception as exc:
        print(f"site-packages: ERROR ({exc})")
    print()

    print("=== Important packages ===")
    for package in [
        "fastapi",
        "uvicorn",
        "pydantic",
        "torch",
        "transformers",
        "huggingface_hub",
        "gliner",
    ]:
        print(f"{package}: {check_module(package)}")

    print()

    print("=== Project imports ===")
    sys.path.insert(0, str(project_root))

    imports_to_check = [
        "backend.api.main",
        "backend.scanner.detector",
    ]

    for module_name in imports_to_check:
        try:
            __import__(module_name)
            print(f"{module_name}: OK")
        except Exception as exc:
            print(f"{module_name}: ERROR")
            print(f"  {type(exc).__name__}: {exc}")

    print()
    print("Done.")


if __name__ == "__main__":
    main()