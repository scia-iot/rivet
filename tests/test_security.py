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


@patch("sciaiot.ovpncp.middlewares.azure_security.APP_ROLE", "mocked_app_role")
@patch(
    "sciaiot.ovpncp.middlewares.azure_security.jwt.get_unverified_claims",
    return_value={"roles": ["mocked_app_role"]},
)
def test_check_role_valid(mock_get_unverified_claims):
    token = "some_token"
    check_role(token)


@patch("sciaiot.ovpncp.middlewares.azure_security.APP_ROLE", "mocked_app_role")
@patch(
    "sciaiot.ovpncp.middlewares.azure_security.jwt.get_unverified_claims",
    return_value={},
)
def test_check_role_incorrect(mocked_get_unverified_claims):
    token = "some_token"
    with pytest.raises(HTTPException) as exc:
        check_role(token)
    assert exc.value.status_code == 403
