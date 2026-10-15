"""Generic HTTP authentication, safe failures, and narrow bypass regressions."""

import asyncio
import json
import threading
from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request, Response

from sciaiot.rivet import dependencies
from sciaiot.rivet.application.authentication import AuthenticationError
from sciaiot.rivet.authorization import get_authenticated_principal
from sciaiot.rivet.middlewares.authentication import authentication_middleware
from tests.support.authentication import DEFAULT_CLAIMS, normalize_claims


def request_for(
    path: str = "/me",
    *,
    method: str = "GET",
    peer: str = "203.0.113.10",
    root_path: str = "",
    authorization: str | None = "Bearer fixture",
) -> Request:
    """Build a real ASGI request with explicit trusted peer and root path."""
    headers = (
        [] if authorization is None else [(b"authorization", authorization.encode())]
    )
    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "root_path": root_path,
            "scheme": "http",
            "server": ("localhost", 8000),
            "client": (peer, 43210),
            "headers": headers,
            "query_string": b"",
        }
    )


def test_authentication_publishes_only_verified_identity_off_event_loop() -> None:
    """Provider work runs on a worker and only normalized facts reach routes."""
    identity = normalize_claims(DEFAULT_CLAIMS)
    service = MagicMock()
    main_thread = threading.get_ident()

    def authenticate(token: str):
        assert token == "fixture"
        assert threading.get_ident() != main_thread
        return identity

    service.authenticate.side_effect = authenticate
    request = request_for()
    downstream = AsyncMock(return_value=Response(status_code=204))
    with patch.object(dependencies, "authentication_service", service):
        response = asyncio.run(authentication_middleware(request, downstream))
    assert response.status_code == 204
    assert request.state.verified_identity is identity
    assert not hasattr(request.state, "token_payload")
    downstream.assert_awaited_once_with(request)


@pytest.mark.parametrize(
    "header", [None, "", " ", "Bearer", "Basic secret", "Bearer a b"]
)
def test_malformed_bearer_never_calls_provider(header: str | None) -> None:
    """Malformed HTTP credentials fail safely before invoking any provider."""
    request = request_for(authorization=header)
    service = MagicMock()
    downstream = AsyncMock()
    with patch.object(dependencies, "authentication_service", service):
        response = asyncio.run(authentication_middleware(request, downstream))
    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/problem+json")
    service.authenticate.assert_not_called()
    downstream.assert_not_called()


@pytest.mark.parametrize("status", [401, 403, 500])
def test_safe_provider_errors_preserve_http_status(status: int) -> None:
    """Typed provider errors retain authentication/access/server semantics."""
    service = MagicMock()
    service.authenticate.side_effect = AuthenticationError(status, "Safe failure.")
    downstream = AsyncMock()
    with patch.object(dependencies, "authentication_service", service):
        response = asyncio.run(authentication_middleware(request_for(), downstream))
    assert response.status_code == status
    assert json.loads(bytes(response.body))["detail"] == "Safe failure."
    downstream.assert_not_called()


def test_unexpected_provider_failure_is_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Raw provider tokens, identities, addresses, and URLs never reach logs."""
    service = MagicMock()
    private = "secret-token stable-subject 198.51.100.4 https://private/?sig=secret"
    service.authenticate.side_effect = RuntimeError(private)
    with patch.object(dependencies, "authentication_service", service):
        response = asyncio.run(authentication_middleware(request_for(), AsyncMock()))
    assert response.status_code == 500
    assert private not in caplog.text + bytes(response.body).decode()
    assert "secret-token" not in caplog.text + bytes(response.body).decode()


def test_unstarted_authentication_service_fails_closed() -> None:
    """Requests cannot silently bypass authentication without a lifespan."""
    downstream = AsyncMock()
    with patch.object(dependencies, "authentication_service", None):
        response = asyncio.run(authentication_middleware(request_for(), downstream))
    assert response.status_code == 500
    downstream.assert_not_called()


@pytest.mark.parametrize("root_path", ["", "/api"])
@pytest.mark.parametrize("path", ["/docs", "/openapi.json"])
def test_exact_documentation_paths_bypass_provider(root_path: str, path: str) -> None:
    """Documentation exceptions survive the trusted application root prefix."""
    service = MagicMock()
    downstream = AsyncMock(return_value=Response(status_code=200))
    request = request_for(root_path + path, root_path=root_path, authorization=None)
    with patch.object(dependencies, "authentication_service", service):
        response = asyncio.run(authentication_middleware(request, downstream))
    assert response.status_code == 200
    service.authenticate.assert_not_called()


@pytest.mark.parametrize("backend", ["host", "shadow", "agent"])
@pytest.mark.parametrize("root_path", ["", "/api"])
@pytest.mark.parametrize("method", ["POST", "PUT", "GET", "DELETE"])
def test_local_hook_exception_is_backend_and_method_specific(
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    root_path: str,
    method: str,
) -> None:
    """Only host/shadow loopback mutation hooks bypass token verification."""
    monkeypatch.setenv("RIVET_VPN_BACKEND", backend)
    request = request_for(
        root_path + "/clients/edge-client/connections",
        root_path=root_path,
        method=method,
        peer="127.0.0.1",
        authorization=None,
    )
    downstream = AsyncMock(return_value=Response(status_code=204))
    response = asyncio.run(authentication_middleware(request, downstream))
    allowed = backend in {"host", "shadow"} and method in {"POST", "PUT"}
    assert response.status_code == (204 if allowed else 401)
    assert getattr(request.state, "local_connection_hook", False) is allowed


@pytest.mark.parametrize(
    "path",
    [
        "/me",
        "/docs/private",
        "/openapi.json/",
        "/clients/a/connections/private",
        "/api-extra/docs",
    ],
)
def test_local_non_hook_paths_still_require_authentication(path: str) -> None:
    """Loopback peers and prefix lookalikes cannot bypass normal resources."""
    request = request_for(path, peer="127.0.0.1", root_path="/api", authorization=None)
    response = asyncio.run(authentication_middleware(request, AsyncMock()))
    assert response.status_code == 401


def test_remote_peer_cannot_spoof_local_connection_hook() -> None:
    """A localhost URL cannot grant a remote peer the local-hook exception."""
    request = request_for("/clients/a/connections", method="POST", authorization=None)
    response = asyncio.run(authentication_middleware(request, AsyncMock()))
    assert response.status_code == 401


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("kind", "unknown"),
        ("kind", "service"),
        ("role", "unknown"),
        ("role", "service_admin"),
        ("issuer", ""),
        ("subject", ""),
        ("subject", 42),
    ],
)
def test_application_policy_rejects_invalid_normalized_identity(field, invalid) -> None:
    """An invalid provider result cannot acquire application permissions."""
    request = request_for()
    identity = normalize_claims(DEFAULT_CLAIMS)
    request.state.verified_identity = replace(identity, **{field: invalid})
    with pytest.raises(HTTPException) as failure:
        get_authenticated_principal(request)
    assert failure.value.status_code == 401


def test_raw_claim_dictionary_cannot_select_application_policy() -> None:
    """Only the typed verified result is accepted at the authorization boundary."""
    request = request_for()
    request.state.token_payload = dict(DEFAULT_CLAIMS)
    with pytest.raises(HTTPException) as failure:
        get_authenticated_principal(request)
    assert failure.value.status_code == 401
