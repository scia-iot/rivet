"""Contract tests for deterministic, side-effect-free OpenAPI generation."""

from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

from sciaiot.ovpncp.main import app


@app.get("/test-http-error", include_in_schema=False)
def trigger_http_error() -> None:
    """Raise a handled error without requiring persistence or system access."""
    raise HTTPException(status_code=404, detail="Contract resource was not found.")


def test_openapi_documents_typed_devices_and_problem_responses() -> None:
    """The frontend contract exposes typed data and RFC 7807 failures."""
    app.openapi_schema = None

    schema = app.openapi()

    devices = schema["paths"]["/devices"]["get"]["responses"]
    success_schema = devices["200"]["content"]["application/json"]["schema"]
    problem_schema = devices["401"]["content"]["application/problem+json"]["schema"]

    assert success_schema["type"] == "array"
    assert success_schema["items"]["$ref"].endswith("/Device")
    assert problem_schema["$ref"].endswith("/ProblemDetails")


def test_openapi_documents_current_principal_contract() -> None:
    """The generated frontend contract includes the trusted principal shape."""
    app.openapi_schema = None

    schema = app.openapi()

    response = schema["paths"]["/me"]["get"]["responses"]["200"]
    principal = response["content"]["application/json"]["schema"]
    model = schema["components"]["schemas"]["CurrentPrincipal"]

    assert principal["$ref"].endswith("/CurrentPrincipal")
    assert set(model["required"]) == {
        "id",
        "display_name",
        "issuer",
        "subject",
        "roles",
        "permissions",
    }


def test_openapi_generation_does_not_call_privileged_operations() -> None:
    """Building the schema must never touch VPN, firewall, or route state."""
    app.openapi_schema = None

    with (
        patch("sciaiot.ovpncp.utils.openvpn.get_status") as get_status,
        patch("sciaiot.ovpncp.utils.openvpn.get_server_config") as get_config,
        patch("sciaiot.ovpncp.utils.iptables.list_rules") as list_rules,
        patch("sciaiot.ovpncp.utils.iproute.list") as list_routes,
    ):
        app.openapi()

    get_status.assert_not_called()
    get_config.assert_not_called()
    list_rules.assert_not_called()
    list_routes.assert_not_called()


def test_http_errors_are_rfc7807_problem_details() -> None:
    """Handled HTTP failures use the same safe problem-details contract."""
    with patch(
        "sciaiot.ovpncp.middlewares.azure_security.validate_token",
        return_value={"sub": "test-subject"},
    ):
        response = TestClient(app).get("/test-http-error")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json() == {
        "type": "/errors/not-found",
        "title": "Not Found",
        "status": 404,
        "detail": "Contract resource was not found.",
        "instance": "http://testserver/test-http-error",
    }
