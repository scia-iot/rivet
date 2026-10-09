"""Loopback-only FastAPI boundary used by the Playwright smoke test."""

import os
from typing import Annotated

import fastapi
import uvicorn


def required_controlled_token() -> str:
    """Read the per-run credential and fail closed when it is absent."""
    token = os.environ.get("RIVET_E2E_TOKEN", "").strip()
    if not token:
        raise RuntimeError("The controlled E2E token is required.")
    return token


CONTROLLED_TOKEN = required_controlled_token()

app = fastapi.FastAPI(
    docs_url=None,
    openapi_url=None,
    redoc_url=None,
)


@app.get("/__e2e/ready", include_in_schema=False)
def ready() -> dict[str, bool]:
    """Report readiness without invoking application integrations."""
    return {"ready": True}


@app.get("/me", response_model=None)
def current_principal(
    authorization: Annotated[str | None, fastapi.Header()] = None,
) -> fastapi.responses.JSONResponse:
    """Exercise an exact bearer boundary with a controlled test identity."""
    if authorization != f"Bearer {CONTROLLED_TOKEN}":
        return fastapi.responses.JSONResponse(
            content={
                "type": "/errors/unauthorized",
                "title": "Unauthorized",
                "status": 401,
                "detail": "Authentication is required.",
            },
            media_type="application/problem+json",
            status_code=401,
        )

    return fastapi.responses.JSONResponse(
        content={
            "id": 1,
            "display_name": "E2E administrator",
            "issuer": "https://e2e.invalid",
            "subject": "sysadmin",
            "roles": ["sysadmin"],
            "permissions": ["devices:read"],
        }
    )


def main() -> None:
    """Run the controlled API on its dedicated loopback port."""
    uvicorn.run(
        app,
        host="127.0.0.1",
        log_level="warning",
        port=8765,
    )


if __name__ == "__main__":
    main()
