import os

DATABASE_URL = os.getenv(
    "CAS_RUN_DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/cassandra_run",
)

STATIC_TOKEN = os.getenv("CAS_RUN_TOKEN", "")

PBSE_ENDPOINT = os.getenv("CAS_RUN_PBSE_ENDPOINT", "http://localhost:8001")
PBSE_TIMEOUT = float(os.getenv("CAS_RUN_PBSE_TIMEOUT", "5"))
PBSE_RETRIES = int(os.getenv("CAS_RUN_PBSE_RETRIES", "3"))
PBSE_DISABLED = os.getenv("CAS_RUN_PBSE_DISABLED", "").lower() in {"1", "true", "yes"}

API_HOST = os.getenv("CAS_RUN_API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("CAS_RUN_API_PORT", "8080"))
