#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib
import json
import subprocess
from pathlib import Path

PBSE_CLI = Path("/usr/local/bin/pbse_cli")
POLICY_PACK = Path("/etc/matverse/policy_pack.json")
POLICY_SIG = Path("/etc/matverse/policy_pack.sig")


def _sha3(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def _run(cmd: list[str]) -> dict:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    return json.loads(result.stdout)


def verify(payload: dict) -> dict:
    payload_hash = _sha3(json.dumps(payload, sort_keys=True).encode())
    output = _run(
        [
            str(PBSE_CLI),
            "--input-hash",
            payload_hash,
            "--policy-pack",
            str(POLICY_PACK),
            "--policy-sig",
            str(POLICY_SIG),
            "--json",
        ]
    )
    return {
        "decision": output["decision"],
        "record_hash": output["record_hash"],
        "new_root": output["new_root"],
        "policy_hash": _sha3(POLICY_PACK.read_bytes()),
    }


def enforce(payload: dict) -> dict:
    result = verify(payload)
    if result["decision"] != "PASS":
        raise PermissionError(f"PBSE decision={result['decision']}")
    return result


def audit(payload: dict, ledger: Path) -> None:
    proof = verify(payload)
    entry = {
        "payload": payload,
        "proof": proof,
        "sha3": _sha3(json.dumps(proof, sort_keys=True).encode()),
    }
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with ledger.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
