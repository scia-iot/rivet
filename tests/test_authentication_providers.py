"""Provider settings and independent authentication security regressions."""

import asyncio
import json
import os
import runpy
import time
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwk, jwt

from sciaiot.rivet import dependencies, main, native_api
from sciaiot.rivet.adapters.authentication import entra
from sciaiot.rivet.application.authentication import AuthenticationError
from sciaiot.rivet.services.provider_settings import AuthenticationSettings


def authentication_environment() -> dict[str, str]:
    """Return explicit, nonsecret Entra configuration for isolated tests."""
    return {
        "AZURE_ENTRAID_TENANT_ID": "11111111-1111-4111-8111-111111111111",
        "AZURE_ENTRAID_APP_CLIENT_ID": "22222222-2222-4222-8222-222222222222",
        "AZURE_ENTRAID_USER_ROLE": "user",
        "AZURE_ENTRAID_ADMIN_ROLE": "admin",
        "AZURE_ENTRAID_SERVICE_ADMIN_ROLE": "ServiceAdmin",
    }


@pytest.mark.parametrize("provider", ["", " ", "keycloak", "cognito", "ENTRA"])
def test_unknown_identity_provider_is_rejected(provider: str) -> None:
    """Unsupported selections cannot silently choose Entra or bypass auth."""
    values = authentication_environment()
    values["RIVET_AUTH_PROVIDER"] = provider
    with pytest.raises(ValueError, match="RIVET_AUTH_PROVIDER"):
        AuthenticationSettings.from_environment(values)


@pytest.mark.parametrize(
    ("selected", "legacy", "expected"),
    [
        (None, None, True),
        ("true", None, True),
        ("false", None, False),
        (None, "false", False),
        ("FALSE", "false", False),
        ("true", "TRUE", True),
    ],
)
def test_registration_aliases_preserve_defaults(
    selected: str | None, legacy: str | None, expected: bool
) -> None:
    """Strict registration aliases agree or retain the legacy default."""
    values = authentication_environment()
    if selected is not None:
        values["RIVET_AUTH_AUTO_REGISTER_USERS"] = selected
    if legacy is not None:
        values["AZURE_ENTRAID_AUTO_REGISTER_USERS"] = legacy
    settings = AuthenticationSettings.from_environment(values)
    assert settings.provider == "entra"
    assert settings.auto_register_users is expected


@pytest.mark.parametrize(
    ("selected", "legacy"),
    [("true", "false"), ("false", "true"), ("yes", "true"), ("true", "1")],
)
def test_registration_conflicts_and_invalid_aliases_fail_closed(
    selected: str, legacy: str
) -> None:
    """A valid new setting cannot conceal invalid legacy configuration."""
    values = authentication_environment()
    values["RIVET_AUTH_AUTO_REGISTER_USERS"] = selected
    values["AZURE_ENTRAID_AUTO_REGISTER_USERS"] = legacy
    with pytest.raises(ValueError):
        AuthenticationSettings.from_environment(values)


@pytest.mark.parametrize("invalid", ["", " true", "false ", "0", "yes"])
def test_registration_requires_an_explicit_boolean(invalid: str) -> None:
    """Typographical mistakes cannot enable automatic registration."""
    values = authentication_environment()
    values["RIVET_AUTH_AUTO_REGISTER_USERS"] = invalid
    with pytest.raises(ValueError):
        AuthenticationSettings.from_environment(values)


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("AZURE_ENTRAID_TENANT_ID", "https://attacker.example/keys"),
        ("AZURE_ENTRAID_APP_CLIENT_ID", ""),
        ("AZURE_ENTRAID_USER_ROLE", ""),
        ("AZURE_ENTRAID_ADMIN_ROLE", " admin "),
        ("AZURE_ENTRAID_SERVICE_ADMIN_ROLE", "user"),
    ],
)
def test_provider_configuration_rejects_invalid_identity_settings(
    setting: str, value: str
) -> None:
    """Trusted issuer IDs and unambiguous external roles are mandatory."""
    values = authentication_environment()
    values[setting] = value
    with pytest.raises(ValueError):
        AuthenticationSettings.from_environment(values)


def test_missing_identity_configuration_fails_closed() -> None:
    """No environment configuration cannot create an anonymous deployment."""
    with pytest.raises(ValueError):
        AuthenticationSettings.from_environment({})


@pytest.fixture(scope="module")
def signing_key():
    """Generate disposable RSA material for actual signature verification."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token_claims(settings: AuthenticationSettings) -> dict[str, object]:
    """Return a short-lived delegated token for the configured test tenant."""
    return {
        "iss": f"https://login.microsoftonline.com/{settings.tenant_id}/v2.0",
        "aud": settings.client_id,
        "sub": "human-subject",
        "oid": "human-object-id",
        "roles": ["user"],
        "scp": "access_as_user",
        "name": "Test Person",
        "exp": int(time.time()) + 300,
    }


def key_response(signing_key) -> MagicMock:
    """Mock only trusted key delivery, retaining real JWT cryptography."""
    public = jwk.construct(signing_key.public_key(), "RS256").to_dict()
    public.update(kid="test-key", use="sig")
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = json.dumps({"keys": [public]}).encode()
    return response


def test_signed_token_verifies_and_fetches_only_bounded_trusted_keys(
    signing_key,
) -> None:
    """Signed tokens normalize only after verifying with the configured issuer."""
    settings = AuthenticationSettings.from_environment(authentication_environment())
    token = jwt.encode(
        token_claims(settings),
        signing_key,
        algorithm="RS256",
        headers={"kid": "test-key", "jku": "https://attacker.invalid/keys"},
    )
    response = key_response(signing_key)
    with patch.object(entra, "urlopen", return_value=response) as opened:
        identity = entra.EntraIdentityProvider(settings).authenticate(token)
    assert identity.subject == "human-subject"
    assert identity.role == "device_user"
    assert identity.kind == "human"
    assert identity.display_name == "Test Person"
    opened.assert_called_once_with(
        f"https://login.microsoftonline.com/{settings.tenant_id}/discovery/v2.0/keys",
        timeout=entra.KEY_FETCH_TIMEOUT_SECONDS,
    )
    response.read.assert_called_once_with(entra.MAX_JWKS_BYTES + 1)
    response.__exit__.assert_called_once()


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("iss", "https://untrusted.invalid/tenant"),
        ("aud", "different-audience"),
        ("exp", 1),
        ("nbf", 4_000_000_000),
        ("sub", ""),
        ("sub", None),
    ],
)
def test_signed_invalid_claims_fail_authentication(signing_key, claim, value) -> None:
    """Expired, premature, wrongly scoped and incomplete signed tokens fail."""
    settings = AuthenticationSettings.from_environment(authentication_environment())
    claims = token_claims(settings)
    claims[claim] = value
    token = jwt.encode(
        claims, signing_key, algorithm="RS256", headers={"kid": "test-key"}
    )
    with (
        patch.object(entra, "urlopen", return_value=key_response(signing_key)),
        pytest.raises(AuthenticationError) as failure,
    ):
        entra.EntraIdentityProvider(settings).authenticate(token)
    assert failure.value.status_code == 401
    assert token not in str(failure.value)


@pytest.mark.parametrize("missing", ["exp", "aud", "iss", "sub"])
def test_signed_token_requires_identity_audience_and_expiry(
    signing_key, missing
) -> None:
    """Essential verified claims cannot be omitted from a valid signature."""
    settings = AuthenticationSettings.from_environment(authentication_environment())
    claims = token_claims(settings)
    claims.pop(missing)
    token = jwt.encode(
        claims, signing_key, algorithm="RS256", headers={"kid": "test-key"}
    )
    with (
        patch.object(entra, "urlopen", return_value=key_response(signing_key)),
        pytest.raises(AuthenticationError) as failure,
    ):
        entra.EntraIdentityProvider(settings).authenticate(token)
    assert failure.value.status_code == 401


def test_wrong_signature_is_rejected(signing_key) -> None:
    """A matching key ID cannot authorize a token signed by another key."""
    settings = AuthenticationSettings.from_environment(authentication_environment())
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(
        token_claims(settings),
        other.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    with (
        patch.object(entra, "urlopen", return_value=key_response(signing_key)),
        pytest.raises(AuthenticationError) as failure,
    ):
        entra.EntraIdentityProvider(settings).authenticate(token)
    assert failure.value.status_code == 401


@pytest.mark.parametrize("token", ["malformed-token", "", "eyJhbGciOiJub25lIn0.e30."])
def test_malformed_or_unsigned_tokens_do_not_fetch_keys(token: str) -> None:
    """Malformed input and forbidden algorithms fail before network access."""
    settings = AuthenticationSettings.from_environment(authentication_environment())
    with patch.object(entra, "urlopen") as opened, pytest.raises(AuthenticationError):
        entra.EntraIdentityProvider(settings).authenticate(token)
    opened.assert_not_called()


@pytest.mark.parametrize(
    "document",
    [b"not-json", b"[]", b'{"keys":null}', b"x" * (entra.MAX_JWKS_BYTES + 1)],
)
def test_unusable_key_documents_fail_safely(signing_key, document: bytes) -> None:
    """Malformed and oversized trusted-key responses fail without publication."""
    settings = AuthenticationSettings.from_environment(authentication_environment())
    token = jwt.encode(
        token_claims(settings),
        signing_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    response = key_response(signing_key)
    response.read.return_value = document
    with (
        patch.object(entra, "urlopen", return_value=response),
        pytest.raises(AuthenticationError) as failure,
    ):
        entra.EntraIdentityProvider(settings).authenticate(token)
    assert failure.value.status_code == 500
    response.__exit__.assert_called_once()


def test_key_outage_does_not_expose_token_or_transport_details(signing_key) -> None:
    """Transport exceptions become fixed safe server errors."""
    settings = AuthenticationSettings.from_environment(authentication_environment())
    token = jwt.encode(
        token_claims(settings),
        signing_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    with (
        patch.object(
            entra, "urlopen", side_effect=OSError("private-token 198.51.100.4")
        ),
        pytest.raises(AuthenticationError) as failure,
    ):
        entra.EntraIdentityProvider(settings).authenticate(token)
    assert failure.value.status_code == 500
    assert "private-token" not in str(failure.value)
    assert failure.value.__suppress_context__


@pytest.mark.parametrize(
    "failure_stage", [None, "storage_create", "directory", "storage_close"]
)
def test_authentication_lifecycle_always_closes_constructed_provider(
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str | None,
) -> None:
    """Authentication closes even when later startup or shutdown work fails."""
    for name, value in authentication_environment().items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("RIVET_VPN_BACKEND", "host")
    monkeypatch.delenv("RIVET_AUTH_AUTO_REGISTER_USERS", raising=False)
    monkeypatch.delenv("AZURE_ENTRAID_AUTO_REGISTER_USERS", raising=False)
    auth = MagicMock()
    store = MagicMock()
    with (
        patch.object(dependencies, "create_authentication_service", return_value=auth),
        patch.object(
            dependencies, "create_archive_store", return_value=store
        ) as create_store,
        patch.object(main, "get_vpn_control"),
        patch.object(main, "create_app_directory") as create_directory,
        patch.object(main, "create_tables"),
        patch.object(main, "init_scripts"),
    ):
        if failure_stage == "storage_create":
            create_store.side_effect = OSError("failure")
        elif failure_stage == "directory":
            create_directory.side_effect = OSError("failure")
        elif failure_stage == "storage_close":
            store.close.side_effect = OSError("failure")

        async def run() -> None:
            async with main.lifespan(main.app):
                assert dependencies.get_authentication_service() is auth
                monkeypatch.setenv("RIVET_AUTH_AUTO_REGISTER_USERS", "false")
                assert dependencies.get_authentication_settings().auto_register_users

        if failure_stage is None:
            asyncio.run(run())
        else:
            with pytest.raises(OSError, match="failure"):
                asyncio.run(run())
    auth.close.assert_called_once_with()
    assert dependencies.authentication_service is None
    assert dependencies.authentication_settings is None


@pytest.mark.parametrize("entrypoint", ["asgi", "native", "container"])
@pytest.mark.parametrize(
    "overrides",
    [
        {"RIVET_AUTH_PROVIDER": ""},
        {"RIVET_AUTH_PROVIDER": "keycloak"},
        {"RIVET_AUTH_AUTO_REGISTER_USERS": "yes"},
        {
            "RIVET_AUTH_AUTO_REGISTER_USERS": "true",
            "AZURE_ENTRAID_AUTO_REGISTER_USERS": "false",
        },
        {"AZURE_ENTRAID_ADMIN_ROLE": "user"},
        {"AZURE_ENTRAID_TENANT_ID": ""},
    ],
)
def test_all_entrypoints_reject_invalid_authentication_before_serving(
    monkeypatch: pytest.MonkeyPatch, entrypoint: str, overrides: dict[str, str]
) -> None:
    """Every launch mode uses shared fail-closed authentication validation."""
    values = authentication_environment()
    values.update(
        {
            "RIVET_VPN_BACKEND": "agent",
            "RIVET_AGENT_UID": "1235",
            "RIVET_PROXY_IP": "172.30.250.2",
            "HOST": "127.0.0.1",
        }
    )
    values.update(overrides)
    monkeypatch.setattr(native_api.os, "geteuid", lambda: 1234)

    async def asgi_start() -> None:
        async with main.lifespan(main.app):
            pytest.fail("Invalid authentication configuration was served")

    with patch.dict(os.environ, values, clear=True), pytest.raises(ValueError):
        if entrypoint == "asgi":
            asyncio.run(asgi_start())
        elif entrypoint == "native":
            native_api.validate_environment()
        else:
            runpy.run_path("deploy/containers/api_entrypoint.py")["configure"]()
