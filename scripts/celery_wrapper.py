#!/usr/bin/env python
import sys
from pathlib import Path


def _run() -> int:
    backend_path = Path(__file__).parent.parent / "backend"
    if str(backend_path) not in sys.path:
        sys.path.insert(0, str(backend_path))

    from celery.__main__ import main as celery_main

    return celery_main()


if __name__ == "__main__":
    sys.exit(_run())
