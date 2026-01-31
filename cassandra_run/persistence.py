from cassandra_run.db import SessionLocal
from cassandra_run.models import Event, Proof


def add_event(
    prev_hash: str,
    data_hash: str,
    merkle_root: str,
    payload: dict,
    pbse_decision: str,
    status: str,
) -> Event:
    db = SessionLocal()
    try:
        event = Event(
            prev_hash=prev_hash,
            data_hash=data_hash,
            merkle_root=merkle_root,
            payload=payload,
            pbse_decision=pbse_decision,
            status=status,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event
    finally:
        db.close()


def get_event_by_id(event_id: int) -> Event | None:
    db = SessionLocal()
    try:
        return db.query(Event).filter(Event.id == event_id).first()
    finally:
        db.close()


def get_all_events() -> list[Event]:
    db = SessionLocal()
    try:
        return db.query(Event).order_by(Event.id).all()
    finally:
        db.close()


def add_proof(event_id: int, signer: str, signature: str) -> Proof:
    db = SessionLocal()
    try:
        proof = Proof(event_id=event_id, signer=signer, signature=signature)
        db.add(proof)
        db.commit()
        db.refresh(proof)
        return proof
    finally:
        db.close()
