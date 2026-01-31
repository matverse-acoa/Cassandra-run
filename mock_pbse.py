from fastapi import FastAPI

app = FastAPI()


@app.post("/evaluate")
def evaluate(event: dict) -> dict:
    return {"decision": "PASS", "details": "mock"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
