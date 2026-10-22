"""Main entry point for APIShield FastAPI application."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from backend.config import HOST, PORT
from backend.database import Base, engine
import backend.models  # Ensures models are imported and registered with Base.metadata
from backend.routes.admin import router as admin_router
from backend.routes.auth import router as auth_router
from backend.routes.inventory import router as inventory_router
from backend.routes.items import router as items_router
from backend.security.middleware import SecurityGatewayMiddleware


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

# Wire security gateway middleware for latency tracking and headers
app.add_middleware(SecurityGatewayMiddleware)

# Mount application routers
app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(items_router, prefix="/items", tags=["items"])
app.include_router(admin_router, prefix="/admin", tags=["admin"])
app.include_router(inventory_router)  # routes carry their own prefixes (/admin/inventory, /api/v0/items)


@app.get("/health")
def health_check() -> dict[str, str]:
    """Health check endpoint to verify server liveness."""
    return {"status": "ok"}
