from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.db.models import Base

settings = get_settings()

if settings.database_url.startswith("sqlite") and "///" in settings.database_url:
    sqlite_path = Path(settings.database_url.split("///", 1)[1])
    if str(sqlite_path) != ":memory:":
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)

engine = create_async_engine(settings.database_url, pool_pre_ping=True)
SessionFactory = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionFactory() as session:
        yield session


async def create_schema() -> None:
    """Create development tables. Production deployments should use migrations."""
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
