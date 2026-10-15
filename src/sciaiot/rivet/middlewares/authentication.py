"""Provider-independent bearer authentication for protected API requests."""

import asyncio
import ipaddress
import logging
import os
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

from fastapi import Request, Response

from sciaiot.rivet import dependencies
from sciaiot.rivet.application.authentication import AuthenticationError
from sciaiot.rivet.problems import problem_response

logger = logging.getLogger(__name__)


def _route_path(request: Request) -> str:
    """Remove the trusted ASGI root prefix from the requested URL path."""
    path = urlparse(str(request.url)).path
    root_path = request.scope.get("root_path", "")
    if not isinstance(root_path, str) or not root_path:
        return path
    if path == root_path:
        return ""
    if path.startswith(root_path) and path[len(root_path)] == "/":
        return path[len(root_path) :]
    return path


def _is_local_connection_hook(request: Request) -> bool:
    """Allow only an exact local OpenVPN hook on host or shadow backends."""
    if os.environ.get("RIVET_VPN_BACKEND", "host") not in {"host", "shadow"}:
        return False
    parts = _route_path(request).strip("/").split("/")
    if (
        len(parts) != 3
        or parts[0] != "clients"
        or parts[2] != "connections"
        or request.method not in {"POST", "PUT"}
        or request.client is None
    ):
        return False
    try:
        return ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        return False


def _bearer_token(request: Request) -> str:
    """Extract one bearer token without exposing it in an error or log."""
    auth = request.headers.get("Authorization")
    if not auth:
        raise AuthenticationError(401, "Authorization header is expected!")
    parts = auth.split()
    if len(parts) != 2:
        if len(parts) == 1 and parts[0].lower() == "bearer":
            raise AuthenticationError(401, "Token not found!")
        raise AuthenticationError(401, "Authorization header must be Bearer token!")
    if parts[0].lower() != "bearer":
        raise AuthenticationError(401, 'Authorization header must start with "Bearer"!')
    return parts[1]


async def authentication_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Authenticate protected requests and preserve exact local exceptions."""
    local_hook = _is_local_connection_hook(request)
    if local_hook:
        request.state.local_connection_hook = True
    if _route_path(request) not in {"/docs", "/openapi.json"} and not local_hook:
        try:
            token = _bearer_token(request)
            service = dependencies.get_authentication_service()
            request.state.verified_identity = await asyncio.to_thread(
                service.authenticate, token
            )
        except AuthenticationError as error:
            return problem_response(request, error.status_code, error.detail)
        except Exception:  # noqa: BLE001
            logger.error("Unexpected error during security check.")
            return problem_response(
                request, 500, "An internal security error occurred."
            )
    return await call_next(request)
