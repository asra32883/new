from fastapi import APIRouter

router = APIRouter()


@router.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    """Liveness only. Reveals nothing about configuration or version."""
    return {"status": "ok"}
