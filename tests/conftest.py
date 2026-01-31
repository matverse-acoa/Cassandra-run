import os
from pathlib import Path

DB_PATH = Path("/tmp/cassandra_run_test.db")

if DB_PATH.exists():
    DB_PATH.unlink()

os.environ.setdefault("CAS_RUN_DATABASE_URL", f"sqlite:///{DB_PATH}")
os.environ.setdefault("CAS_RUN_TOKEN", "test-token")
os.environ.setdefault("CAS_RUN_PBSE_DISABLED", "true")
