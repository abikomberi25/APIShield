
"""Main entry point for the APIShield FastAPI application."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database import Base, engine
import backend.models

from backend.routes.admin import router as admin_router
from backend.routes.auth import router as auth_router
from backend.routes.inventory import router as inventory_router
from backend.routes.items import router as items_router

from backend.security.middleware import SecurityGatewayMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Initialize database tables during application startup."""
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="APIShield",
    description=(
        "A controlled platform for evaluating "
        "OWASP API Security Top 10 risks"
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# Register the security gateway.
# This middleware measures request processing time.
app.add_middleware(SecurityGatewayMiddleware)

# Register CORS so browser preflight requests are handled
# before reaching the security gateway and API routes.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register application routers.
app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(items_router, prefix="/items", tags=["items"])
app.include_router(admin_router, prefix="/admin", tags=["admin"])
app.include_router(inventory_router)


@app.get("/health")
def health_check() -> dict[str, str]:
    """Verify that the API server is running."""
    return {"status": "ok"}
