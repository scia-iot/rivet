import json
import logging
import os
from urllib.parse import urlparse
from urllib.request import urlopen

from fastapi import HTTPException, Request, status
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError

from sciaiot.ovpncp.problems import problem_response

logger = logging.getLogger(__name__)

TENANT_ID = os.environ.get("AZURE_ENTRAID_TENANT_ID")
APP_CLIENT_ID = os.environ.get("AZURE_ENTRAID_APP_CLIENT_ID")
APP_ROLE = os.environ.get("AZURE_ENTRAID_APP_ROLE")


def get_token(request: Request):
    auth = request.headers.get("Authorization", None)
    if not auth:
        logger.error("Authorization header is expected!")
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Authorization header is expected!"
        )

    parts = auth.split()
    if parts[0].lower() != "bearer":
        logger.error("Authorization header must start with Bearer!")
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            'Authorization header must start with "Bearer"!',
        )
    elif len(parts) == 1:
        logger.error("Token not found!")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token not found!")
    elif len(parts) > 2:
        logger.error("Authorization header must be Bearer token!")
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Authorization header must be Bearer token!"
        )

    token = parts[1]
    return token


def check_role(token: str):
    unverified_claims = jwt.get_unverified_claims(token)
    if unverified_claims.get("roles"):
        roles = unverified_claims["roles"]
        for role in roles:
            if role == APP_ROLE:
                return

    logger.error(f"Application role {APP_ROLE} is required!")
    raise HTTPException(
        status.HTTP_403_FORBIDDEN, f"Application role {APP_ROLE} is required!"
    )


def validate_token(request: Request):
    if not all([TENANT_ID, APP_CLIENT_ID, APP_ROLE]):
        logger.error(
            "Azure Identity environment variables are not properly configured!"
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Authentication service is misconfigured.",
        )

    token = get_token(request)
    check_role(token)

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
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],
                audience=APP_CLIENT_ID,
                issuer=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
            )
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


async def azure_security_middleware(request: Request, call_next):
    # Bypass the security checkings for localhost accessing, required for scripts of client connection
    url = urlparse(str(request.url))
    if url.hostname not in ["localhost", "127.0.0.1"] and url.path not in [
        "/docs",
        "/openapi.json",
    ]:
        try:
            logger.info("Checking access token on Azure Entra ID...")
            token_payload = validate_token(request)
            request.state.token_payload = token_payload
            logger.info("Security checking passed, continue to next step.")
        except HTTPException as e:
            logger.error(f"Security checking failed: {e.detail}")
            return problem_response(request, e.status_code, e.detail)
        # This security boundary must fail closed for unexpected validator errors.
        except Exception as e:  # noqa: BLE001
            logger.error(f"Unexpected error during security check: {e}")
            return problem_response(
                request,
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "An internal security error occurred.",
            )

    response = await call_next(request)
    return response
