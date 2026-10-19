"""Verify Microsoft Entra access tokens and normalize their identities."""

import json
from collections.abc import Mapping
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from jose import jwt
from jose.exceptions import ExpiredSignatureError, JOSEError, JWTClaimsError

from sciaiot.rivet.application.authentication import (
    AuthenticationError,
    CanonicalRole,
    IdentityKind,
    VerifiedIdentity,
)
from sciaiot.rivet.services.provider_settings import AuthenticationSettings

DELEGATED_SCOPE = "access_as_user"
MAX_DISPLAY_NAME_LENGTH = 255
MAX_JWKS_BYTES = 262_144
KEY_FETCH_TIMEOUT_SECONDS = 5
FALLBACK_DISPLAY_NAME = "Microsoft Entra user"


class EntraIdentityProvider:
    """Validate Entra signatures and turn trusted claims into Rivet identity."""

    def __init__(self, settings: AuthenticationSettings) -> None:
        """Keep validated deployment settings for this provider lifecycle."""
        self._settings = settings
        self._issuer = f"https://login.microsoftonline.com/{settings.tenant_id}/v2.0"
        self._keys_url = (
            "https://login.microsoftonline.com/"
            f"{settings.tenant_id}/discovery/v2.0/keys"
        )

    def authenticate(self, token: str) -> VerifiedIdentity:
        """Verify a signed access token, then normalize its trusted claims."""
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256":
                raise AuthenticationError(401, "Invalid authentication token.")
            key_id = header.get("kid")
            if not isinstance(key_id, str) or not key_id:
                raise AuthenticationError(401, "Invalid authentication token.")
            key = self._trusted_key(key_id)
            payload: dict[str, object] = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=self._settings.client_id,
                issuer=self._issuer,
                options={"require_exp": True, "require_aud": True},
            )
        except AuthenticationError:
            raise
        except ExpiredSignatureError:
            raise AuthenticationError(401, "Token is expired!") from None
        except JWTClaimsError:
            raise AuthenticationError(401, "Incorrect claims!") from None
        except JOSEError, ValueError, TypeError:
            raise AuthenticationError(401, "Invalid authentication token.") from None
        return self.normalize_verified_claims(payload)

    def _trusted_key(self, key_id: str) -> dict[str, str]:
        """Fetch bounded trusted keys from the fixed tenant endpoint."""
        try:
            with urlopen(self._keys_url, timeout=KEY_FETCH_TIMEOUT_SECONDS) as response:
                document = response.read(MAX_JWKS_BYTES + 1)
        except HTTPError, URLError, TimeoutError, OSError:
            raise AuthenticationError(
                500, "Authentication key service is unavailable."
            ) from None
        if len(document) > MAX_JWKS_BYTES:
            raise AuthenticationError(500, "Authentication key service is unavailable.")
        try:
            keys = json.loads(document).get("keys")
        except ValueError, AttributeError, TypeError:
            keys = None
        if not isinstance(keys, list):
            raise AuthenticationError(500, "Authentication key service is unavailable.")
        for candidate in keys:
            if not isinstance(candidate, dict) or candidate.get("kid") != key_id:
                continue
            if candidate.get("kty") != "RSA":
                continue
            if candidate.get("use") not in (None, "sig"):
                continue
            if not all(
                isinstance(candidate.get(field), str) and candidate[field]
                for field in ("n", "e")
            ):
                continue
            return {field: candidate[field] for field in ("kty", "n", "e")}
        raise AuthenticationError(401, "Invalid authentication token.")

    def normalize_verified_claims(self, payload: Mapping[str, Any]) -> VerifiedIdentity:
        """Map signature-verified Entra claims to a bounded identity."""
        issuer = payload.get("iss")
        subject = payload.get("sub")
        if (
            not isinstance(issuer, str)
            or issuer != self._issuer
            or not isinstance(subject, str)
            or not subject
        ):
            raise AuthenticationError(401, "Incorrect claims!")

        role_map: dict[str, CanonicalRole] = {
            self._settings.user_role: "device_user",
            self._settings.admin_role: "sysadmin",
            self._settings.service_admin_role: "service_admin",
        }
        token_roles = payload.get("roles")
        if (
            not isinstance(token_roles, list)
            or len(token_roles) != 1
            or not isinstance(token_roles[0], str)
            or token_roles[0] not in role_map
        ):
            raise AuthenticationError(
                403, "The token has no recognized application role."
            )
        role = role_map[token_roles[0]]
        object_id = payload.get("oid")
        is_app_only = (
            isinstance(object_id, str) and bool(object_id) and object_id == subject
        )
        has_human_object_id = (
            isinstance(object_id, str) and bool(object_id) and object_id != subject
        )
        if role == "service_admin":
            if not is_app_only or payload.get("scp") is not None:
                raise AuthenticationError(
                    403, "The token is not valid for app-only access."
                )
            kind: IdentityKind = "service"
        else:
            scope = payload.get("scp")
            scopes = scope.split() if isinstance(scope, str) else []
            if not has_human_object_id or DELEGATED_SCOPE not in scopes:
                raise AuthenticationError(
                    403, "The token is not valid for delegated access."
                )
            kind = "human"
        return VerifiedIdentity(
            issuer=issuer,
            subject=subject,
            role=role,
            kind=kind,
            display_name=self._display_name(payload),
        )

    @staticmethod
    def _display_name(payload: Mapping[str, Any]) -> str:
        """Use a printable, bounded name from verified Entra claims."""
        for claim in ("name", "preferred_username"):
            value = payload.get(claim)
            if not isinstance(value, str):
                continue
            candidate = value.strip()
            if candidate and all(char.isprintable() for char in candidate):
                return candidate[:MAX_DISPLAY_NAME_LENGTH]
        return FALLBACK_DISPLAY_NAME

    def close(self) -> None:
        """Release provider resources; urllib keeps no owned client open."""
