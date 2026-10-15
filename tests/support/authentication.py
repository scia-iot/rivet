"""Explicit provider fakes for route tests without token or network bypasses."""

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import replace
from unittest.mock import MagicMock, patch

from sciaiot.rivet import dependencies
from sciaiot.rivet.adapters.authentication.entra import EntraIdentityProvider
from sciaiot.rivet.application.authentication import VerifiedIdentity
from sciaiot.rivet.services.authentication import AuthenticationService
from sciaiot.rivet.services.provider_settings import AuthenticationSettings

AUTH_ENVIRONMENT = {
    "AZURE_ENTRAID_TENANT_ID": "11111111-1111-4111-8111-111111111111",
    "AZURE_ENTRAID_APP_CLIENT_ID": "22222222-2222-4222-8222-222222222222",
    "AZURE_ENTRAID_USER_ROLE": "user",
    "AZURE_ENTRAID_ADMIN_ROLE": "admin",
    "AZURE_ENTRAID_SERVICE_ADMIN_ROLE": "ServiceAdmin",
}
DEFAULT_CLAIMS: dict[str, object] = {
    "iss": "https://login.example/tenant/v2.0",
    "sub": "test-subject",
    "oid": "test-object-id",
    "roles": ["admin"],
    "scp": "access_as_user",
}


def normalize_claims(claims: dict[str, object]) -> VerifiedIdentity:
    """Exercise Entra mapping only on explicitly trusted test fixture claims."""
    settings = AuthenticationSettings.from_environment(AUTH_ENVIRONMENT)
    payload = dict(claims)
    issuer = payload.get("iss")
    if isinstance(issuer, str) and issuer:
        payload["iss"] = f"https://login.microsoftonline.com/{settings.tenant_id}/v2.0"
    identity = EntraIdentityProvider(settings).normalize_verified_claims(payload)
    return replace(identity, issuer=str(issuer))


@contextmanager
def authenticated_claims(
    *,
    return_value: Mapping[str, object] | None = None,
    side_effect: Callable[[str], dict[str, object]] | Exception | None = None,
) -> Iterator[MagicMock]:
    """Inject a provider for route tests while retaining real bearer parsing.

    The registration getter parses fixture environment on demand so legacy
    route error tests can inject invalid policy independently of startup.
    Startup validation tests deliberately do not use this helper.
    """
    claims = MagicMock(
        return_value=dict(DEFAULT_CLAIMS) if return_value is None else return_value,
        side_effect=side_effect,
    )
    provider = MagicMock()
    provider.authenticate.side_effect = lambda token: normalize_claims(claims(token))
    service = AuthenticationService(provider)
    settings = AuthenticationSettings.from_environment(AUTH_ENVIRONMENT)
    with (
        patch.dict("os.environ", AUTH_ENVIRONMENT),
        patch.object(dependencies, "authentication_service", service),
        patch.object(dependencies, "authentication_settings", settings),
        patch.object(
            dependencies, "create_authentication_service", return_value=service
        ),
        patch.object(
            dependencies,
            "get_authentication_settings",
            side_effect=AuthenticationSettings.from_environment,
        ),
    ):
        yield claims
