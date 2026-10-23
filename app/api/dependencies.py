from __future__ import annotations

from fastapi import Depends, Header, HTTPException

from app.core.config import Settings, get_settings
from app.core.security import verify_bearer_token


def require_api_token(
    authorization: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    if not verify_bearer_token(authorization, settings.api_token):
        raise HTTPException(status_code=401, detail="Invalid API token")

