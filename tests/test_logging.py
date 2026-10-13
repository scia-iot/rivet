import json
import logging

from sciaiot.rivet.utils.logging import JSONFormatter, mask_sensitive


def test_mask_sensitive_sas():
    sas_url = "https://example.blob.core.windows.net/certs/client.ovpn?sv=2022-11-02&ss=b&srt=o&sp=r&se=2026-04-02T18:31:05Z&st=10:31:05Z&spr=https&sig=SENSITIVE_TOKEN"
    masked = mask_sensitive(sas_url)
    assert "sig=" in masked
    assert "SENSITIVE_TOKEN" not in masked
    assert "sig=***" in masked


def test_mask_sensitive_ip():
    message = "Connection from 1.2.3.4 failed"
    masked = mask_sensitive(message)
    assert "1.2.3.4" not in masked
    assert "1.2.3.4" in message
    assert "***.***.***.***" in masked


def test_json_formatter():
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test_path",
        lineno=10,
        msg="Test message",
        args=None,
        exc_info=None,
    )
    output = formatter.format(record)
    json_output = json.loads(output)

    assert json_output["message"] == "Test message"
    assert json_output["levelname"] == "INFO"
    assert json_output["name"] == "test_logger"
    assert "timestamp" in json_output


def test_json_formatter_masking():
    formatter = JSONFormatter()

    # Test message masking
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test_path",
        lineno=10,
        msg="Connection from 1.2.3.4 failed with sig=SENSITIVE_TOKEN",
        args=None,
        exc_info=None,
    )
    output = formatter.format(record)
    json_output = json.loads(output)
    assert "***.***.***.***" in json_output["message"]
    assert "sig=***" in json_output["message"]
    assert "1.2.3.4" not in json_output["message"]
    assert "SENSITIVE_TOKEN" not in json_output["message"]

    # Test exception masking
    try:
        raise ValueError("Error at 10.0.0.1")
    except ValueError:
        import sys

        record = logging.LogRecord(
            name="test_logger",
            level=logging.ERROR,
            pathname="test_path",
            lineno=10,
            msg="An error occurred",
            args=None,
            exc_info=sys.exc_info(),
        )
        output = formatter.format(record)
        json_output = json.loads(output)
        assert "***.***.***.***" in json_output["exc_info"]
        assert "10.0.0.1" not in json_output["exc_info"]
