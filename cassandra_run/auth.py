from fastapi import HTTPException

from config import STATIC_TOKEN


def verify_token(token: str) -> None:
    if not STATIC_TOKEN:
        raise HTTPException(status_code=500, detail="Token not configured")
    if token != STATIC_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")
