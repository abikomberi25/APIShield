"""Main entry point for APIShield FastAPI application."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from backend.config import HOST, PORT
from backend.database import Base, engine
import backend.models  # Ensures models are imported and registered with Base.metadata


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager for startup and shutdown tasks."""
    # Create database tables if they do not already exist
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="APIShield",
    description="A controlled platform for evaluating OWASP API Security Top 10 risks",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health_check() -> dict[str, str]:
    """Health check endpoint to verify server liveness."""
    return {"status": "ok"}
