"""Main entry point for APIShield FastAPI application."""

from fastapi import FastAPI
from backend.config import HOST, PORT

app = FastAPI(
    title="APIShield",
    description="A controlled platform for evaluating OWASP API Security Top 10 risks",
    version="0.1.0",
)


@app.get("/health")
def health_check() -> dict[str, str]:
    """Health check endpoint to verify server liveness."""
    return {"status": "ok"}
