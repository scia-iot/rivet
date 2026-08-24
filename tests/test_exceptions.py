import os

# Set dummy environment variables before importing the app to avoid security middleware failure
os.environ["AZURE_ENTRAID_TENANT_ID"] = "mock"
os.environ["AZURE_ENTRAID_APP_CLIENT_ID"] = "mock"
os.environ["AZURE_ENTRAID_APP_ROLE"] = "mock"

import logging
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from sciaiot.ovpncp.main import app


# We will add a temporary route to 'app' for testing purposes
@app.get("/test-exception")
async def trigger_exception():
    raise RuntimeError("Test exception")


@pytest.fixture(name="client")
def client_fixture():
    # Use a yield fixture with patch to ensure it persists during the test
    with patch(
        "sciaiot.ovpncp.middlewares.azure_security.validate_token"
    ) as mock_validate:
        mock_validate.return_value = {"sub": "test-user"}
        # Also patch the middleware's response to errors
        with patch(
            "sciaiot.ovpncp.middlewares.azure_security.azure_security_middleware"
        ) as mock_middleware:
            # Manually implement the middleware bypass
            async def side_effect(request, call_next):
                return await call_next(request)

            mock_middleware.side_effect = side_effect

            # CRITICAL: raise_server_exceptions=False allows the TestClient to return the 500 response
            # instead of re-raising the exception into the test.
            client = TestClient(app, raise_server_exceptions=False)
            yield client


def test_global_exception_handler_returns_500(client: TestClient):
    """
    Test that an unhandled exception results in a 500 status code.
    """
    response = client.get("/test-exception")
    assert response.status_code == 500


def test_global_exception_handler_rfc7807_format(client: TestClient):
    """
    Test that the response body follows RFC 7807 Problem Details format.
    """
    response = client.get("/test-exception")
    data = response.json()

    assert "type" in data
    assert data["type"] == "/errors/internal-server-error"
    assert "title" in data
    assert data["title"] == "Internal Server Error"
    assert "status" in data
    assert data["status"] == 500
    assert "detail" in data
    assert "instance" in data


def test_global_exception_handler_no_stack_trace(client: TestClient):
    """
    Test that no stack trace is exposed in the response.
    """
    response = client.get("/test-exception")
    content = response.text

    # Check for common stack trace markers
    assert "Traceback" not in content
    assert "RuntimeError: Test exception" not in content


def test_global_exception_handler_logs_error(client: TestClient, caplog):
    """
    Test that the exception is logged.
    """
    caplog.clear()
    with caplog.at_level(logging.ERROR):
        client.get("/test-exception")

    assert "Unhandled exception: Test exception" in caplog.text
    assert "RuntimeError" in caplog.text
