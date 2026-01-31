from fastapi.testclient import TestClient

from cassandra_run.api import app
from cassandra_run.db import init_db


client = TestClient(app)


def test_submit_requires_token() -> None:
    response = client.post("/submit", json={"test": "data"})
    assert response.status_code in {401, 403}


def test_ledger_requires_token() -> None:
    response = client.get("/ledger")
    assert response.status_code in {401, 403}


def test_submit_and_ledger_with_token() -> None:
    init_db()
    headers = {"Authorization": "Bearer test-token"}
    response = client.post("/submit", json={"test": "data"}, headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["pbse_decision"] == "PASS"

    ledger_response = client.get("/ledger", headers=headers)
    assert ledger_response.status_code == 200
    assert isinstance(ledger_response.json(), list)
