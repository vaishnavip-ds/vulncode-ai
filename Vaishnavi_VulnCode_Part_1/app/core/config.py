from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

DEVELOPMENT_WEBHOOK_SECRET = "development-webhook-secret-change-me"
DEVELOPMENT_INGEST_TOKEN = "development-ingest-token-change-me"
DEVELOPMENT_API_TOKEN = "development-api-token-change-me"


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str
    database_url: str
    webhook_secret: str
    ingest_token: str
    api_token: str
    github_app_id: str | None
    github_private_key: str | None
    github_api_url: str
    github_api_version: str

    @property
    def github_checks_enabled(self) -> bool:
        return bool(self.github_app_id and self.github_private_key)

    def validate_for_startup(self) -> None:
        if self.environment in {"development", "test"}:
            return
        unsafe_values = {
            DEVELOPMENT_WEBHOOK_SECRET,
            DEVELOPMENT_INGEST_TOKEN,
            DEVELOPMENT_API_TOKEN,
        }
        if {self.webhook_secret, self.ingest_token, self.api_token} & unsafe_values:
            raise RuntimeError("Production cannot start with development credentials")
        if self.database_url.startswith("sqlite"):
            raise RuntimeError("Production requires PostgreSQL; SQLite is development-only")


@lru_cache
def get_settings() -> Settings:
    database_url = (
        os.getenv("VULNCODE_DATABASE_URL")
        or os.getenv("POSTGRES_URL")
        or os.getenv("DATABASE_URL")
        or "sqlite+aiosqlite:///./data/vulncode.db"
    )
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return Settings(
        environment=os.getenv("VULNCODE_ENVIRONMENT", "development"),
        database_url=database_url,
        webhook_secret=os.getenv(
            "VULNCODE_WEBHOOK_SECRET", DEVELOPMENT_WEBHOOK_SECRET
        ),
        ingest_token=os.getenv("VULNCODE_INGEST_TOKEN", DEVELOPMENT_INGEST_TOKEN),
        api_token=os.getenv("VULNCODE_API_TOKEN", DEVELOPMENT_API_TOKEN),
        github_app_id=os.getenv("VULNCODE_GITHUB_APP_ID") or None,
        github_private_key=(os.getenv("VULNCODE_GITHUB_PRIVATE_KEY") or None),
        github_api_url=os.getenv("VULNCODE_GITHUB_API_URL", "https://api.github.com"),
        github_api_version=os.getenv("VULNCODE_GITHUB_API_VERSION", "2026-03-10"),
    )
