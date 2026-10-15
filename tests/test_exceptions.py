import logging

import pytest
from fastapi.testclient import TestClient

from sciaiot.rivet.main import app
from tests.support.authentication import authenticated_claims


# We will add a temporary route to 'app' for testing purposes
@app.get("/test-exception")
async def trigger_exception():
    raise RuntimeError("Test exception")


@pytest.fixture(name="client")
def client_fixture():
    with authenticated_claims():
        client = TestClient(
            app,
            raise_server_exceptions=False,
            headers={"Authorization": "Bearer fixture"},
        )
        yield client
        client.close()


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
    Test that a fixed failure is logged without exception payloads.
    """
    caplog.clear()
    with caplog.at_level(logging.ERROR):
        client.get("/test-exception")

    assert "Unhandled request failure." in caplog.text
    assert "Test exception" not in caplog.text
    assert "RuntimeError" not in caplog.text
