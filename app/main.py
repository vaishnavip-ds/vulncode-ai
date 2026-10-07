from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.health import router as health_router
from app.api.scans import router as scans_router
from app.api.webhooks import router as webhooks_router
from app.core.config import get_settings
from app.db.session import create_schema


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    settings.validate_for_startup()
    if settings.environment in {"development", "test"}:
        await create_schema()
    yield


app = FastAPI(
    title="VulnCode AI API",
    version="0.1.0",
    description="GitHub-native vulnerability scanning and remediation orchestration.",
    lifespan=lifespan,
)
app.include_router(health_router)
app.include_router(webhooks_router)
app.include_router(scans_router)
