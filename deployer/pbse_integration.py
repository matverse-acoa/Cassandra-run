#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PBSE ↔ Cassandra-run Integration
Versão: 1.0.0
Autor: MatVerse ACOA
Descrição: Módulo determinístico de validação antifrágil.
Executa o kernel PBSE antes de qualquer mutação no ledger.
"""

import json
import hashlib
import subprocess
from pathlib import Path

# Caminhos padrão de produção
PBSE_CLI = Path("/usr/local/bin/pbse_cli")
POLICY_PACK = Path("/etc/matverse/policy_pack.json")
POLICY_SIG = Path("/etc/matverse/policy_pack.sig")


# --- UTILIDADES ---------------------------------------------------------------

def _sha3(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def _run_cmd(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


# --- FUNÇÕES PRINCIPAIS -------------------------------------------------------

def verify_payload(payload: dict) -> dict:
    """Valida entrada com PBSE determinístico."""
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    input_hash = _sha3(payload_bytes)

    cmd = [
        str(PBSE_CLI),
        "--input-hash",
        input_hash,
        "--policy-pack",
        str(POLICY_PACK),
        "--policy-sig",
        str(POLICY_SIG),
        "--json",
    ]
    out = _run_cmd(cmd)
    result = json.loads(out)

    return {
        "decision": result.get("decision"),
        "record_hash": result.get("record_hash"),
        "new_root": result.get("new_root"),
        "policy_hash": _sha3(POLICY_PACK.read_bytes()),
    }


def enforce(payload: dict) -> dict:
    """Executa política fail-closed."""
    decision = verify_payload(payload)
    if decision["decision"] != "PASS":
        raise PermissionError(f"PBSE decision={decision['decision']}")
    return decision


def audit_record(payload: dict, ledger_path: Path) -> None:
    """Registra prova antifrágil no ledger operacional."""
    proof = verify_payload(payload)
    entry = {
        "payload": payload,
        "proof": proof,
        "sha3": _sha3(json.dumps(proof, sort_keys=True).encode()),
    }
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# --- EXECUÇÃO DIRETA (TESTE CONTROLADO) --------------------------------------

if __name__ == "__main__":
    sample = {"task": "integrity_check", "value": 42}
    try:
        res = enforce(sample)
        print(json.dumps(res, indent=2))
    except Exception as exc:  # pylint: disable=broad-except
        print(f"[PBSE BLOCK] {exc}")
