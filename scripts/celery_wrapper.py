#!/usr/bin/env python
import sys
import os
from pathlib import Path

# Add backend to path to make 'app' module discoverable
backend_path = Path(__file__).parent.parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

# Now import and run celery
from celery.__main__ import main as celery_main

if __name__ == "__main__":
    sys.exit(celery_main())
