import ipaddress
import json
import logging
import os
from urllib.parse import urlparse
from urllib.request import urlopen

from fastapi import HTTPException, Request, status
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError

from sciaiot.rivet.problems import problem_response

logger = logging.getLogger(__name__)

TENANT_ID = os.environ.get("AZURE_ENTRAID_TENANT_ID")
APP_CLIENT_ID = os.environ.get("AZURE_ENTRAID_APP_CLIENT_ID")
USER_ROLE = os.environ.get("AZURE_ENTRAID_USER_ROLE")
ADMIN_ROLE = os.environ.get("AZURE_ENTRAID_ADMIN_ROLE")
SERVICE_ADMIN_ROLE = os.environ.get("AZURE_ENTRAID_SERVICE_ADMIN_ROLE")
DELEGATED_SCOPE = "access_as_user"
AUTO_REGISTER_USERS_ENV = "AZURE_ENTRAID_AUTO_REGISTER_USERS"


def auto_register_users_enabled() -> bool:
    """Return the strict automatic local-user registration setting.

    Returns:
        ``True`` when unset or explicitly true, and ``False`` when
        explicitly false.

    Raises:
        ValueError: If the environment value is not an explicit boolean.
    """
    value = os.environ.get(AUTO_REGISTER_USERS_ENV)
    if value is None:
        return True
    normalized = value.casefold()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise ValueError("Automatic user registration is misconfigured.")


def get_token(request: Request) -> str:
    """Extract a bearer token without exposing its value in diagnostics."""
    auth = request.headers.get("Authorization", None)
    if not auth:
        logger.error("Authorization header is expected!")
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Authorization header is expected!"
        )

    parts = auth.split()
    if len(parts) != 2:
        if len(parts) == 1 and parts[0].lower() == "bearer":
            logger.error("Token not found!")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token not found!")
        logger.error("Authorization header must be Bearer token!")
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Authorization header must be Bearer token!",
        )

    if parts[0].lower() != "bearer":
        logger.error("Authorization header must start with Bearer!")
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            'Authorization header must start with "Bearer"!',
        )

    token = parts[1]
    return token


def validate_token(request: Request) -> dict[str, object]:
    """Validate a bearer token and return only its verified claims."""
    if not all(
        [
            TENANT_ID,
            APP_CLIENT_ID,
            USER_ROLE,
            ADMIN_ROLE,
            SERVICE_ADMIN_ROLE,
        ]
    ):
        logger.error(
            "Azure Identity environment variables are not properly configured!"
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Authentication service is misconfigured.",
        )

    token = get_token(request)

    # verify headers & claims of token
    keys = urlopen(f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys")
    jwks = json.loads(keys.read())
    unverified_header = jwt.get_unverified_header(token)

    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
            }

    if rsa_key:
        try:
            payload: dict[str, object] = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],
                audience=APP_CLIENT_ID,
                issuer=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
            )
            issuer = payload.get("iss")
            subject = payload.get("sub")
            if (
                not isinstance(issuer, str)
                or not issuer
                or not isinstance(subject, str)
                or not subject
            ):
                raise JWTClaimsError("Stable identity claims are required.")
            return payload
        except ExpiredSignatureError:
            logger.error("Token is expired!")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token is expired!")
        except JWTClaimsError:
            logger.error("Incorrect claims!")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect claims!")
    else:
        logger.error("Unable to find appropriate key for token validation.")
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid authentication token."
        )


def _route_path(request: Request) -> str:
    """Return the URL path with the trusted ASGI root prefix removed."""
    path = urlparse(str(request.url)).path
    scope = getattr(request, "scope", {})
    root_path = scope.get("root_path", "") if isinstance(scope, dict) else ""
    if not isinstance(root_path, str) or not root_path:
        return path
    if path == root_path:
        return ""
    if path.startswith(root_path) and path[len(root_path)] == "/":
        return path[len(root_path) :]
    return path


def _is_local_connection_hook(request: Request) -> bool:
    """Return whether the request is an exact loopback OpenVPN hook."""
    if os.environ.get("RIVET_VPN_BACKEND", "host") not in {"host", "shadow"}:
        return False
    path_parts = _route_path(request).strip("/").split("/")
    is_connection_hook = (
        len(path_parts) == 3
        and path_parts[0] == "clients"
        and path_parts[2] == "connections"
        and request.method in ["POST", "PUT"]
    )
    if request.client is None:
        return False
    try:
        is_loopback = ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        return False
    return is_loopback and is_connection_hook


def _bypasses_authentication(request: Request) -> bool:
    """Allow only documentation and exact localhost OpenVPN hook requests."""
    is_documentation = _route_path(request) in ["/docs", "/openapi.json"]
    return is_documentation or _is_local_connection_hook(request)


async def azure_security_middleware(request: Request, call_next):
    """Validate remote requests while preserving narrow local hook access."""
    if _is_local_connection_hook(request):
        request.state.local_connection_hook = True

    if not _bypasses_authentication(request):
        try:
            logger.info("Checking access token on Azure Entra ID...")
            token_payload = validate_token(request)
            request.state.token_payload = token_payload
            logger.info("Security checking passed, continue to next step.")
        except HTTPException as e:
            logger.error(f"Security checking failed: {e.detail}")
            return problem_response(request, e.status_code, e.detail)
        # This security boundary must fail closed for unexpected validator errors.
        except Exception:  # noqa: BLE001
            logger.error("Unexpected error during security check.")
            return problem_response(
                request,
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "An internal security error occurred.",
            )

    response = await call_next(request)
    return response
