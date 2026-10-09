from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/")
async def root() -> dict[str, str]:
    return {
        "name": "VulnCode AI",
        "type": "GitHub App API",
        "status": "ready",
        "health": "/health",
        "docs": "/docs",
    }


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "vulncode-api"}
