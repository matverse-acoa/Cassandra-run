from cassandra_run.db import init_db
from cassandra_run.persistence import add_event
from cassandra_run.replay import replay_all


def test_replay_returns_hashes() -> None:
    init_db()
    add_event("", "hash-2", "root-2", {"n": 1}, "PASS", "VERIFIED")
    add_event("hash-2", "hash-3", "root-3", {"n": 2}, "PASS", "VERIFIED")

    hashes = replay_all()
    assert "hash-2" in hashes
    assert "hash-3" in hashes
