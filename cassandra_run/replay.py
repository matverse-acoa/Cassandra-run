from cassandra_run.persistence import get_all_events


def replay_all() -> list[str]:
    events = get_all_events()
    return [event.data_hash for event in events]
