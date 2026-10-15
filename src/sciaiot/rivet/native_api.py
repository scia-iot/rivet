"""Fail-closed entry point for a non-container API service."""

import importlib.util
import os
import sys

from sciaiot.rivet.adapters.vpn.settings import BackendSettings
from sciaiot.rivet.services.provider_settings import (
    AuthenticationSettings,
    StorageSettings,
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
        AuthenticationSettings.from_environment()
        if os.environ.get("HOST", "127.0.0.1") not in ("127.0.0.1", "::1"):
            raise ValueError
        StorageSettings.from_environment()
    except KeyError, ValueError:
        raise ValueError(
            "Invalid native API configuration; require agent backend, "
            "trusted agent UID, loopback bind, complete Entra settings and "
            "valid storage selection and credentials."
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
