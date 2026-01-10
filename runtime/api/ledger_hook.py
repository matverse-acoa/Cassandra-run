from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from runtime.hooks.pbse_integration import audit, enforce

router = APIRouter()
LEDGER = Path("/var/lib/matverse/ledger.jsonl")


@router.post("/blocks")
async def write_block(req: Request) -> dict:
    data = await req.json()
    try:
        proof = enforce(data)
        audit(data, LEDGER)
        return {"status": "PASS", "proof": proof}
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PBSE error: {exc}") from exc
