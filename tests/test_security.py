import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from sciaiot.ovpncp.main import app
from sciaiot.ovpncp.middlewares.azure_security import (
    azure_security_middleware,
    check_role,
    get_token,
)

client = TestClient(app)


@patch("sciaiot.ovpncp.middlewares.azure_security.TENANT_ID", "mocked_tenant_id")
@patch(
    "sciaiot.ovpncp.middlewares.azure_security.APP_CLIENT_ID", "mocked_app_client_id"
)
@patch("sciaiot.ovpncp.middlewares.azure_security.APP_ROLE", "mocked_app_role")
@patch(
    "sciaiot.ovpncp.middlewares.azure_security.validate_token",
    return_value={"sub": "mocked_sub"},
)
def test_azure_security_middleware_success(mock_validate_token):
    # Success case should still work
    response = client.get("/")
    # Middleware passes, FastAPI returns 404 because "/" doesn't exist
    assert response.status_code == 404
    mock_validate_token.assert_called_once()


@patch("sciaiot.ovpncp.middlewares.azure_security.TENANT_ID", "mocked_tenant_id")
@patch(
    "sciaiot.ovpncp.middlewares.azure_security.APP_CLIENT_ID", "mocked_app_client_id"
)
@patch("sciaiot.ovpncp.middlewares.azure_security.APP_ROLE", "mocked_app_role")
@patch(
    "sciaiot.ovpncp.middlewares.azure_security.validate_token",
    side_effect=HTTPException(status_code=401, detail="Mocked Exception"),
)
def test_azure_security_middleware_failure(mock_validate_token):
    response = client.get("/")
    assert response.status_code == 401
    assert response.json() == {
        "type": "/errors/unauthorized",
        "title": "Unauthorized",
        "status": 401,
        "detail": "Mocked Exception",
        "instance": "http://testserver/",
    }


@patch("sciaiot.ovpncp.middlewares.azure_security.TENANT_ID", None)
def test_azure_security_middleware_missing_env_error():
    # Verify that missing env vars now results in 500 error
    request = MagicMock(spec=Request)
    request.url = MagicMock()
    request.url.__str__.return_value = "http://example.com/"

    async def call_next(req):
        return MagicMock()

    import asyncio

    response = asyncio.run(azure_security_middleware(request, call_next))

    assert response.status_code == 500
    assert (
        "Authentication service is misconfigured"
        in json.loads(response.body.decode())["detail"]
    )


@patch(
    "sciaiot.ovpncp.middlewares.azure_security.validate_token",
    return_value={"iss": "issuer", "sub": "subject", "roles": ["role"]},
)
def test_localhost_me_still_requires_authentication(mock_validate_token):
    """Local frontend traffic cannot bypass authentication for `/me`."""
    request = MagicMock(spec=Request)
    request.url = MagicMock()
    request.url.__str__.return_value = "http://127.0.0.1:8000/me"
    request.method = "GET"

    async def call_next(req):
        return MagicMock()

    import asyncio

    asyncio.run(azure_security_middleware(request, call_next))

    mock_validate_token.assert_called_once_with(request)


@patch("sciaiot.ovpncp.middlewares.azure_security.validate_token")
def test_localhost_connection_hook_has_narrow_authentication_bypass(
    mock_validate_token,
):
    """Only the exact local OpenVPN connection hook remains unauthenticated."""
    request = MagicMock(spec=Request)
    request.url = MagicMock()
    request.url.__str__.return_value = (
        "http://127.0.0.1:8000/clients/edge-client/connections"
    )
    request.method = "POST"
    request.client.host = "127.0.0.1"

    async def call_next(req):
        return MagicMock()

    import asyncio

    asyncio.run(azure_security_middleware(request, call_next))

    mock_validate_token.assert_not_called()


@patch(
    "sciaiot.ovpncp.middlewares.azure_security.validate_token",
    return_value={"iss": "issuer", "sub": "subject", "roles": ["role"]},
)
def test_remote_peer_cannot_spoof_local_connection_hook(mock_validate_token):
    """A loopback Host header cannot grant a remote peer the hook bypass."""
    request = MagicMock(spec=Request)
    request.url = MagicMock()
    request.url.__str__.return_value = (
        "http://127.0.0.1:8000/clients/edge-client/connections"
    )
    request.method = "POST"
    request.client.host = "203.0.113.10"

    async def call_next(req):
        return MagicMock()

    import asyncio

    asyncio.run(azure_security_middleware(request, call_next))

    mock_validate_token.assert_called_once_with(request)


def test_get_token_valid():
    request = MagicMock(spec=Request)
    request.headers.get.return_value = "Bearer some_token"
    token = get_token(request)
    assert token == "some_token"


def test_get_token_no_authorization_header():
    request = MagicMock(spec=Request)
    request.headers.get.return_value = None
    with pytest.raises(HTTPException) as exc:
        get_token(request)
    assert exc.value.status_code == 401


@patch("sciaiot.ovpncp.middlewares.azure_security.TENANT_ID", "mocked_tenant_id")
@patch(
    "sciaiot.ovpncp.middlewares.azure_security.APP_CLIENT_ID",
    "mocked_app_client_id",
)
@patch("sciaiot.ovpncp.middlewares.azure_security.APP_ROLE", "mocked_app_role")
def test_blank_authorization_header_returns_problem_401():
    """Whitespace-only bearer input is a handled authentication failure."""
    request = MagicMock(spec=Request)
    request.url = MagicMock()
    request.url.__str__.return_value = "http://example.com/me"
    request.method = "GET"
    request.headers.get.return_value = "   "
    request.client.host = "203.0.113.10"

    async def call_next(req):
        return MagicMock()

    import asyncio

    response = asyncio.run(azure_security_middleware(request, call_next))
    body = json.loads(response.body.decode())

    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/problem+json")
    assert body["status"] == 401
    assert body["detail"] == "Authorization header must be Bearer token!"


@patch("sciaiot.ovpncp.middlewares.azure_security.APP_ROLE", "mocked_app_role")
def test_check_role_uses_only_validated_claims():
    with patch(
        "sciaiot.ovpncp.middlewares.azure_security.jwt.get_unverified_claims"
    ) as get_unverified_claims:
        check_role({"roles": ["mocked_app_role"]})

    get_unverified_claims.assert_not_called()


@patch("sciaiot.ovpncp.middlewares.azure_security.APP_ROLE", "mocked_app_role")
def test_check_role_incorrect():
    with pytest.raises(HTTPException) as exc:
        check_role({"roles": []})
    assert exc.value.status_code == 403


@patch(
    "sciaiot.ovpncp.middlewares.azure_security.validate_token",
    side_effect=RuntimeError("secret-token stable-oauth-subject"),
)
def test_security_errors_do_not_log_token_or_subject(mock_validate_token, caplog):
    response = client.get("/")

    assert response.status_code == 500
    assert "secret-token" not in caplog.text
    assert "stable-oauth-subject" not in caplog.text
