from fastapi import FastAPI
from runtime.api.ledger_hook import router as ledger_router

app = FastAPI(title="Cassandra-run PBSE Runtime")
app.include_router(ledger_router, prefix="/v1")


@app.get("/health")
def health():
    return {"status": "ok"}
