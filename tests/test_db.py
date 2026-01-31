from cassandra_run.db import init_db
from cassandra_run.persistence import add_event, get_all_events


def test_add_event_persists() -> None:
    init_db()
    event = add_event("", "hash-1", "root-1", {"key": "value"}, "PASS", "VERIFIED")
    assert event.id is not None

    events = get_all_events()
    assert any(stored.data_hash == "hash-1" for stored in events)
