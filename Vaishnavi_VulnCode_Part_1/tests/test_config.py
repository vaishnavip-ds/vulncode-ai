from app.core.config import get_settings


def test_vercel_database_url_fallback_uses_asyncpg(monkeypatch) -> None:
    monkeypatch.delenv("VULNCODE_DATABASE_URL", raising=False)
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:password@db.example/vulncode")
    get_settings.cache_clear()
    try:
        settings = get_settings()
        assert settings.database_url == (
            "postgresql+asyncpg://user:password@db.example/vulncode"
        )
    finally:
        get_settings.cache_clear()
