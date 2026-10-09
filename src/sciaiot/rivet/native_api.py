"""Fail-closed entry point for a non-container API service."""

import importlib.util
import os
import sys
import uuid

from sciaiot.rivet.adapters.vpn.settings import BackendSettings

AUTH_NAMES = (
    "AZURE_ENTRAID_TENANT_ID",
    "AZURE_ENTRAID_APP_CLIENT_ID",
    "AZURE_ENTRAID_USER_ROLE",
    "AZURE_ENTRAID_ADMIN_ROLE",
    "AZURE_ENTRAID_SERVICE_ADMIN_ROLE",
)
API_MODULES = ("fastapi", "jose", "sqlmodel", "uvicorn", "yaml")


def validate_environment() -> None:
    """Require a non-root agent-backed API and complete Entra settings.

    Raises:
        ValueError: The native service is unsafe or incomplete.
    """
    if os.geteuid() == 0:
        raise ValueError("Run the native API as an unprivileged account.")
    try:
        backend = BackendSettings.from_environment()
        if backend.backend != "agent" or backend.peer_uid in (
            None,
            0,
            os.geteuid(),
        ):
            raise ValueError
        if any(not os.environ.get(name, "").strip() for name in AUTH_NAMES):
            raise ValueError
        for name in AUTH_NAMES[:2]:
            uuid.UUID(os.environ[name])
        if os.environ.get("HOST", "127.0.0.1") not in ("127.0.0.1", "::1"):
            raise ValueError
    except KeyError, ValueError:
        raise ValueError(
            "Invalid native API configuration; require agent backend, "
            "trusted agent UID, loopback bind and complete Entra settings."
        ) from None


def main() -> None:
    """Start the API only after package and deployment checks pass."""
    missing = [name for name in API_MODULES if importlib.util.find_spec(name) is None]
    if missing:
        raise SystemExit("API dependencies missing; install 'sciaiot-rivet[api]'.")
    try:
        validate_environment()
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from None
    from sciaiot.rivet.main import run

    run()


if __name__ == "__main__":
    main()
