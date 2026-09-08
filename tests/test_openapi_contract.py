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


def test_openapi_documents_current_user_resource_contracts() -> None:
    """Portal operations expose typed data and enforced resource policy."""
    app.openapi_schema = None

    schema = app.openapi()
    policies = {
        ("get", "/me/clients"): "owned-client",
        ("get", "/me/devices"): "granted-device",
        ("get", "/me/devices/{device_id}"): "granted-device",
        (
            "put",
            "/me/clients/{client_name}/package-cert",
        ): "owned-client",
        (
            "get",
            "/me/clients/{client_name}/download-cert",
        ): "owned-client",
    }

    for (method, path), policy in policies.items():
        operation = schema["paths"][path][method]
        assert operation["x-current-user-resource"] == policy
        assert "x-required-permission" not in operation
        assert all(
            parameter["name"] != "user_id"
            for parameter in operation.get("parameters", [])
        )

    clients = schema["paths"]["/me/clients"]["get"]["responses"]["200"]
    client_items = clients["content"]["application/json"]["schema"]["items"]
    devices = schema["paths"]["/me/devices"]["get"]["responses"]["200"]
    device_items = devices["content"]["application/json"]["schema"]["items"]
    assert client_items["$ref"].endswith("/CurrentUserClient")
    assert device_items["$ref"].endswith("/Device")
    client_model = schema["components"]["schemas"]["CurrentUserClient"]
    assert set(client_model["required"]) == {"id", "name", "revoked"}
    assert set(client_model["properties"]) == {"id", "name", "revoked"}

    shared_config = schema["paths"]["/me/client-config"]["get"]
    assert shared_config["x-authenticated-principal"] is True
    assert "x-required-permission" not in shared_config
    config_response = shared_config["responses"]["200"]["content"]
    assert config_response["application/x-openvpn-profile"]["schema"] == {
        "format": "binary",
        "type": "string",
    }


def test_openapi_documents_optional_bulk_client_import_contract() -> None:
    """Bulk import publishes an optional request and every outcome count."""
    app.openapi_schema = None

    schema = app.openapi()
    operation = schema["paths"]["/clients/import"]["post"]
    request_body = operation["requestBody"]
    request_schema = request_body["content"]["application/json"]["schema"]
    request_model = schema["components"]["schemas"]["ClientImportRequest"]
    response = operation["responses"]["200"]["content"]["application/json"]
    summary_reference = response["schema"]
    summary = schema["components"]["schemas"]["ClientImportSummary"]

    assert "required" not in request_body
    assert request_schema["anyOf"] == [
        {"$ref": "#/components/schemas/ClientImportRequest"},
        {"type": "null"},
    ]
    assert request_model["properties"]["create_devices"] == {
        "default": False,
        "title": "Create Devices",
        "type": "boolean",
    }
    assert summary_reference["$ref"].endswith("/ClientImportSummary")
    assert set(summary["properties"]) == {
        "added",
        "updated",
        "clients_skipped",
        "devices_created",
        "devices_already_linked",
        "device_conflicts",
    }
    assert set(summary["required"]) == set(summary["properties"])


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


def test_openapi_documents_every_management_permission() -> None:
    """Generated operations expose the permission enforced by FastAPI."""
    app.openapi_schema = None
    schema = app.openapi()
    expected = {
        ("get", "/devices"): "devices:read",
        ("post", "/devices"): "devices:write",
        ("get", "/devices/{device_id}"): "devices:read",
        ("patch", "/devices/{device_id}"): "devices:write",
        ("delete", "/devices/{device_id}"): "devices:write",
        ("get", "/users"): "users:read",
        ("post", "/users"): "users:write",
        ("get", "/users/{user_id}"): "users:read",
        ("patch", "/users/{user_id}"): "users:write",
        ("delete", "/users/{user_id}"): "users:write",
        ("get", "/users/{user_id}/devices"): "access:read",
        (
            "put",
            "/users/{user_id}/devices/{device_id}",
        ): "access:grant",
        (
            "delete",
            "/users/{user_id}/devices/{device_id}",
        ): "access:grant",
        ("get", "/users/{user_id}/clients"): "users:read",
        (
            "put",
            "/users/{user_id}/clients/{client_id}",
        ): "users:write",
        (
            "delete",
            "/users/{user_id}/clients/{client_id}",
        ): "users:write",
        ("get", "/clients"): "clients:read",
        ("post", "/clients"): "clients:write",
        ("post", "/clients/import"): "clients:write",
        ("delete", "/clients/{client_name}"): "clients:write",
        ("get", "/clients/{client_name}"): "clients:read",
        (
            "put",
            "/clients/{client_name}/package-cert",
        ): "clients:write",
        (
            "get",
            "/clients/{client_name}/download-cert",
        ): "clients:write",
        ("put", "/clients/{client_name}/renew-cert"): "clients:write",
        ("put", "/clients/{client_name}/revoke"): "clients:write",
        ("put", "/clients/{client_name}/assign-ip"): "clients:write",
        (
            "delete",
            "/clients/{client_name}/unassign-ip",
        ): "clients:write",
        (
            "post",
            "/clients/{client_name}/connections",
        ): "clients:write",
        (
            "put",
            "/clients/{client_name}/connections",
        ): "clients:write",
        ("get", "/server"): "server:read",
        ("post", "/server"): "server:write",
        ("put", "/server/client-config"): "server:write",
        ("get", "/server/health"): "server:read",
        (
            "get",
            "/server/assignable-virtual-addresses",
        ): "server:read",
        ("get", "/server/routes"): "server:read",
        ("post", "/server/routes"): "server:write",
        ("delete", "/server/routes"): "server:write",
        ("get", "/networks"): "server:read",
        ("post", "/networks"): "server:write",
        ("get", "/networks/{network_id}"): "server:read",
        ("delete", "/networks/{network_id}"): "server:write",
    }

    actual = {}
    for path, path_item in schema["paths"].items():
        if not path.startswith(
            ("/devices", "/users", "/clients", "/server", "/networks")
        ):
            continue
        for method, operation in path_item.items():
            permission = operation.get("x-required-permission") or operation.get(
                "x-local-hook-or-permission"
            )
            actual[(method, path)] = permission

    assert actual == expected
    for method in ("post", "put"):
        operation = schema["paths"]["/clients/{client_name}/connections"][method]
        assert "x-required-permission" not in operation
        assert operation["x-local-hook-or-permission"] == "clients:write"
