import os
import sys
from pathlib import Path

# Ensure backend/src is on the Python path
_backend_src = Path(__file__).resolve().parent / "backend" / "src"
if str(_backend_src) not in sys.path:
    sys.path.insert(0, str(_backend_src))

# On serverless platforms like Vercel, the filesystem is read-only except for /tmp
if os.environ.get("VERCEL") and not os.environ.get("PROMPTFIREWALL_DATABASE_URL"):
    os.environ["PROMPTFIREWALL_DATABASE_URL"] = "sqlite+aiosqlite:////tmp/promptfirewall.db"

from promptfirewall.main import app, create_app

__all__ = ["app", "create_app"]
