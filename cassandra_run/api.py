import json

import blake3
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from cassandra_run.auth import verify_token
from cassandra_run.db import init_db
from cassandra_run.persistence import (
    add_event,
    add_proof,
    get_all_events,
    get_event_by_id,
)
from cassandra_run.replay import replay_all
from cassandra_run.pbse import PBSEClient

app = FastAPI(title="Cassandra-run Hardened API")
security = HTTPBearer()
pbse_client = PBSEClient()


def require_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> None:
    verify_token(credentials.credentials)


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.post("/submit", dependencies=[Depends(require_token)])
def submit(payload: dict) -> dict:
    payload_str = json.dumps(payload, sort_keys=True)
    data_hash = blake3.blake3(payload_str.encode()).hexdigest()

    events = get_all_events()
    prev_hash = events[-1].data_hash if events else ""

    merkle_root = data_hash

    pbse_response = pbse_client.evaluate(payload)
    decision = pbse_response.decision
    status_map = {
        "PASS": "VERIFIED",
        "SILENCE": "SILENCED",
        "ESCALATE": "ESCALATED",
    }
    status = status_map.get(decision, "BLOCKED")
    if decision not in status_map:
        raise HTTPException(status_code=403, detail="Event blocked by PBSE")

    event = add_event(prev_hash, data_hash, merkle_root, payload, decision, status)

    return {
        "id": event.id,
        "prev_hash": event.prev_hash,
        "data_hash": event.data_hash,
        "merkle_root": event.merkle_root,
        "timestamp": event.timestamp,
        "status": status,
        "pbse_decision": decision,
    }


@app.get("/ledger", dependencies=[Depends(require_token)])
def ledger() -> list[dict]:
    events = get_all_events()
    return [
        {
            "id": event.id,
            "prev_hash": event.prev_hash,
            "data_hash": event.data_hash,
            "merkle_root": event.merkle_root,
            "timestamp": event.timestamp,
            "status": event.status,
            "pbse_decision": event.pbse_decision,
        }
        for event in events
    ]


@app.get("/proof/{event_id}", dependencies=[Depends(require_token)])
def get_proof(event_id: int) -> list[dict]:
    event = get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    return [
        {
            "signer": proof.signer,
            "signature": proof.signature,
            "signed_at": proof.signed_at,
        }
        for proof in event.proofs
    ]


@app.post("/replay", dependencies=[Depends(require_token)])
def replay() -> dict:
    hashes = replay_all()
    return {"hashes": hashes}


@app.post("/proof/{event_id}", dependencies=[Depends(require_token)])
def submit_proof(event_id: int, payload: dict) -> dict:
    signer = payload.get("signer")
    signature = payload.get("signature")
    if not signer or not signature:
        raise HTTPException(status_code=400, detail="Missing signer or signature")

    proof = add_proof(event_id=event_id, signer=signer, signature=signature)
    return {
        "id": proof.id,
        "event_id": proof.event_id,
        "signer": proof.signer,
        "signature": proof.signature,
        "signed_at": proof.signed_at,
    }
