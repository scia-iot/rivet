"""Validation tests for the shared credential-free OpenVPN profile."""

from pathlib import Path

import pytest

from sciaiot.rivet.services.client_config import (
    ClientConfigReadError,
    client_config_response,
)

SAFE_PROFILE = b"client\ndev tun\nproto udp\nremote vpn.example.test 1194\n"


@pytest.mark.parametrize(
    "content",
    [
        b"\xffclient\nremote vpn.example.test 1194\n",
        SAFE_PROFILE + b"verb 3\x00\n",
        b"# client\nremote vpn.example.test 1194\n",
        b"client\n# remote vpn.example.test 1194\n",
        b"client\nremote\n",
        b"client\nremote <vpn-public-host-or-ip> 1194\n",
        SAFE_PROFILE + b"key laptop.key\n",
        SAFE_PROFILE + b"cert laptop.crt\n",
        SAFE_PROFILE + b"pkcs12 laptop.p12\n",
        SAFE_PROFILE + b"secret static.key\n",
        SAFE_PROFILE + b"tls-auth ta.key 1\n",
        SAFE_PROFILE + b"tls-crypt tls.key\n",
        SAFE_PROFILE + b"auth-user-pass credentials.txt\n",
        b"<ca>\nclient\nremote vpn.example.test 1194\n</ca>\n",
        SAFE_PROFILE + b"<key>\nprivate\n</key>\n",
        SAFE_PROFILE + b"<cert>\ncertificate\n</cert>\n",
        SAFE_PROFILE + b"<pkcs12>\nbundle\n</pkcs12>\n",
        SAFE_PROFILE + b"<secret>\nstatic\n</secret>\n",
        SAFE_PROFILE + b"<tls-auth>\nstatic\n</tls-auth>\n",
        SAFE_PROFILE + b"<tls-crypt>\nstatic\n</tls-crypt>\n",
        SAFE_PROFILE + b"<auth-user-pass>\nuser\npass\n</auth-user-pass>\n",
        SAFE_PROFILE + b"-----BEGIN PRIVATE KEY-----\nsecret\n",
        SAFE_PROFILE + b"-----BEGIN RSA PRIVATE KEY-----\nsecret\n",
        SAFE_PROFILE + b"-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n",
    ],
)
def test_shared_client_config_rejects_unsafe_or_unusable_content(
    tmp_path: Path,
    content: bytes,
) -> None:
    """Only complete text profiles without shared credentials are served."""
    target = tmp_path / "unsafe.ovpn"
    target.write_bytes(content)

    with pytest.raises(ClientConfigReadError):
        client_config_response(str(target))


def test_shared_client_config_allows_safe_comments_and_related_directives(
    tmp_path: Path,
) -> None:
    """Comments and non-credential certificate checks do not false-positive."""
    content = (
        b"# cert laptop.crt and key laptop.key are supplied locally\n"
        b"; auth-user-pass is intentionally unavailable\n"
        + SAFE_PROFILE
        + b"remote-cert-tls server\npersist-key\n"
    )
    target = tmp_path / "safe.ovpn"
    target.write_bytes(content)

    response = client_config_response(str(target))

    assert response.body == content


def test_deployment_template_is_valid_after_remote_is_configured(
    tmp_path: Path,
) -> None:
    """The supplied template becomes downloadable after placeholder setup."""
    repository_root = Path(__file__).resolve().parents[1]
    template = (repository_root / "deploy/client.ovpn.example").read_text(
        encoding="utf-8"
    )
    configured = template.replace(
        "<vpn-public-host-or-ip>",
        "vpn.example.test",
    )
    target = tmp_path / "client.ovpn"
    target.write_text(configured, encoding="utf-8")

    response = client_config_response(str(target))

    assert response.body == configured.encode()
