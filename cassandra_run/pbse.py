import time
from dataclasses import dataclass
from typing import Any, Dict

import requests

from config import PBSE_DISABLED, PBSE_ENDPOINT, PBSE_RETRIES, PBSE_TIMEOUT


@dataclass
class PBSEDecision:
    decision: str
    metadata: Dict[str, Any]


class PBSEClient:
    def __init__(self) -> None:
        self.endpoint = PBSE_ENDPOINT
        self.timeout = PBSE_TIMEOUT
        self.retries = PBSE_RETRIES

    def evaluate(self, payload: Dict[str, Any]) -> PBSEDecision:
        if PBSE_DISABLED:
            return PBSEDecision(decision="PASS", metadata={"mode": "disabled"})

        if not self.endpoint:
            return PBSEDecision(decision="BLOCK", metadata={"error": "missing endpoint"})

        url = f"{self.endpoint.rstrip('/')}/evaluate"
        last_error: str | None = None
        for attempt in range(1, self.retries + 1):
            try:
                response = requests.post(url, json=payload, timeout=self.timeout)
                response.raise_for_status()
                data = response.json()
                decision = data.get("decision", "BLOCK")
                return PBSEDecision(decision=decision, metadata=data)
            except requests.RequestException as exc:
                last_error = str(exc)
                if attempt < self.retries:
                    time.sleep(0.2 * attempt)

        return PBSEDecision(decision="BLOCK", metadata={"error": last_error or "unknown"})
