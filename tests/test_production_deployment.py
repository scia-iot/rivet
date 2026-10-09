"""Production reverse-proxy and release configuration tests."""

import re
from pathlib import Path
from unittest.mock import patch

import pytest

from sciaiot.rivet import main

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
NGINX_TEMPLATE = REPOSITORY_ROOT / "deploy/nginx/rivet.conf.template"
PRODUCTION_RUNBOOK = REPOSITORY_ROOT / "docs/production-deployment.md"
SYSTEMD_SERVICE = REPOSITORY_ROOT / "deploy/systemd/rivet.service"
CLIENT_PROFILE_TEMPLATE = REPOSITORY_ROOT / "deploy/client.ovpn.example"


@pytest.fixture
def nginx_configuration() -> str:
    """Return the production Nginx template."""
    return NGINX_TEMPLATE.read_text(encoding="utf-8")


def _location(configuration: str, declaration: str) -> str:
    """Return one non-nested Nginx location block.

    Args:
        configuration: Complete Nginx configuration text.
        declaration: Exact location declaration without its opening brace.

    Returns:
        The matching location body.

    Raises:
        AssertionError: If the requested block is absent.
    """
    match = re.search(
        rf"{re.escape(declaration)}\s*\{{(?P<body>[^{{}}]*)\}}",
        configuration,
    )
    assert match is not None
    return match.group("body")


def test_api_prefix_is_separate_from_spa_history_fallback(
    nginx_configuration: str,
) -> None:
    """API requests are stripped once and can never fall through to HTML."""
    exact_api = _location(nginx_configuration, "location = /api")
    api_prefix = _location(nginx_configuration, "location ^~ /api/")
    spa = _location(nginx_configuration, "location /")

    for api_location in (exact_api, api_prefix):
        assert "proxy_pass http://rivet_api/;" in api_location
        assert "proxy_set_header X-Forwarded-For $remote_addr;" in api_location
        assert "proxy_set_header Host $http_host;" in api_location
        assert "proxy_set_header X-Forwarded-Host $http_host;" in api_location
        assert "proxy_set_header X-Forwarded-Proto https;" in api_location
        assert "$server_name" not in api_location
        assert "proxy_set_header X-Forwarded-Proto $scheme;" not in api_location
        assert "$proxy_add_x_forwarded_for" not in api_location
        assert "try_files" not in api_location
        assert "proxy_buffering off;" in api_location
        assert "proxy_request_buffering off;" in api_location

    assert "try_files $uri /index.html;" in spa
    assert "proxy_pass" not in spa
    assert nginx_configuration.index("location ^~ /api/") < (
        nginx_configuration.index("location /")
    )


def test_frontend_assets_have_deliberate_cache_policy(
    nginx_configuration: str,
) -> None:
    """Only fingerprinted Vite assets receive immutable caching."""
    cache_map = re.search(
        r"map \$uri \$rivet_cache_control\s*\{(?P<body>[^{}]*)\}",
        nginx_configuration,
    )
    assert cache_map is not None
    cache_policy = cache_map.group("body")

    assert 'default "no-store";' in cache_policy
    assert '~^/assets/ "public, max-age=31536000, immutable";' in cache_policy
    assert '~^/favicon\\.svg$ "public, max-age=3600";' in cache_policy
    cache_header = "add_header Cache-Control $rivet_cache_control always;"
    assert cache_header in nginx_configuration
    assert "location = /index.html" in nginx_configuration
    assert "location ^~ /assets/" in nginx_configuration


def test_frontend_and_api_responses_receive_security_headers(
    nginx_configuration: str,
) -> None:
    """Responses retain browser protections behind the public TLS boundary."""
    normalized_configuration = " ".join(nginx_configuration.split())
    hsts_name = "Strict-Transport-Security "
    hsts_value = '"max-age=31536000; includeSubDomains" always;'
    expected_headers = {
        'Content-Security-Policy "',
        'Cross-Origin-Opener-Policy "same-origin-allow-popups" always;',
        'Cross-Origin-Resource-Policy "same-origin" always;',
        'Permissions-Policy "camera=(), geolocation=(), microphone=()" always;',
        'Referrer-Policy "no-referrer" always;',
        hsts_name + hsts_value,
        'X-Content-Type-Options "nosniff" always;',
        'X-Frame-Options "DENY" always;',
    }
    for header in expected_headers:
        assert f"add_header {header}" in normalized_configuration

    assert "default-src 'self'" in nginx_configuration
    assert "object-src 'none'" in nginx_configuration
    assert "frame-ancestors 'none'" in nginx_configuration
    assert "connect-src 'self' https://login.microsoftonline.com" in (
        nginx_configuration
    )
    assert "frame-src https://login.microsoftonline.com" in nginx_configuration


def test_application_gateway_backend_is_private_plain_http(
    nginx_configuration: str,
) -> None:
    """Application Gateway owns host matching and public TLS enforcement."""
    assert {"${RIVET_FRONTEND_ROOT}"} == set(
        re.findall(r"\$\{RIVET_[A-Z_]+\}", nginx_configuration)
    )
    assert "listen 80 default_server;" in nginx_configuration
    assert "listen [::]:80 default_server;" in nginx_configuration
    assert "server_name _;" in nginx_configuration
    assert "listen 443" not in nginx_configuration
    assert "ssl_certificate" not in nginx_configuration
    assert "return 30" not in nginx_configuration
    assert "server_tokens off;" in nginx_configuration
    assert nginx_configuration.count("access_log off;") == 3
    assert nginx_configuration.count("error_log /dev/null crit;") == 1


def test_runbook_documents_the_application_gateway_trust_boundary() -> None:
    """Operators keep HTTP private and enforce HTTPS at the gateway listener."""
    runbook = PRODUCTION_RUNBOOK.read_text(encoding="utf-8")

    assert "TLS terminates at Azure Application Gateway" in runbook
    assert "Backend protocol: `HTTP`" in runbook
    assert "Backend port: `80`" in runbook
    assert "only from the Application Gateway subnet" in runbook
    assert "Do not expose port 8000" in runbook


def test_systemd_keeps_fastapi_on_the_trusted_loopback_boundary() -> None:
    """The API is unprivileged and exposed only to the trusted HTTP proxy."""
    configuration = SYSTEMD_SERVICE.read_text(encoding="utf-8")

    assert "Environment=HOST=127.0.0.1" in configuration
    assert "Environment=PORT=8000" in configuration
    assert "Environment=RIVET_ROOT_PATH=/api" in configuration
    assert "EnvironmentFile=/etc/rivet/api.env" in configuration
    assert "ExecStart=/usr/local/lib/rivet/api-venv/bin/rivet" in configuration
    assert "Environment=RIVET_VPN_BACKEND=agent" in configuration
    assert "User=ovpn-api" in configuration
    assert "CapabilityBoundingSet=" in configuration
    assert "UMask=0077" in configuration


def test_static_release_is_outside_the_api_writable_tree() -> None:
    """Nginx can read releases that the API cannot modify."""
    runbook = PRODUCTION_RUNBOOK.read_text(encoding="utf-8")
    service = SYSTEMD_SERVICE.read_text(encoding="utf-8")

    assert "/srv/rivet/frontend/current" in runbook
    assert "/opt/rivet/frontend" not in runbook
    assert "sudo chmod -R u=rwX,go=rX" in runbook
    assert "ReadWritePaths=/opt/rivet" in service
    assert "InaccessiblePaths=-/var/lib/ovpn-agent" in service
    assert "ProtectSystem=strict" in service
    assert "/srv/rivet" not in service


def test_shared_client_profile_template_matches_deployed_server() -> None:
    """The operator template is compatible and never contains credentials."""
    profile = CLIENT_PROFILE_TEMPLATE.read_text(encoding="utf-8")

    assert "remote <vpn-public-host-or-ip> 1194" in profile
    assert "proto udp" in profile
    assert "dev tun" in profile
    assert "remote-cert-tls server" in profile
    assert "data-ciphers-fallback AES-256-CBC" in profile
    assert "persist-key" in profile
    assert "persist-tun" in profile
    assert "explicit-exit-notify 1" in profile
    assert "compress" not in profile
    assert "tls-auth" not in profile
    assert "tls-crypt" not in profile
    assert "<ca>" not in profile
    assert "<cert>" not in profile
    assert "<key>" not in profile


def test_runbook_documents_shared_client_profile_generation() -> None:
    """Operators receive an explicit safe generation and migration procedure."""
    runbook = PRODUCTION_RUNBOOK.read_text(encoding="utf-8")
    normalized = " ".join(runbook.split())

    assert "RIVET_CLIENT_CONFIG_PATH" in runbook
    assert "/opt/rivet/client.ovpn" in runbook
    assert "deploy/client.ovpn.example" in runbook
    assert "reachable VPN hostname or IP address" in normalized
    assert "active OpenVPN" in normalized
    assert "PUT /server/client-config" in runbook
    assert "never derives the endpoint" in normalized
    assert "must not contain any client certificate or private key" in runbook
    assert "strict UTF-8" in " ".join(runbook.split())
    assert "--config rivet-client.ovpn" in runbook
    assert "--ca ca.crt" in runbook
    assert '--cert "${RIVET_CLIENT_NAME}.crt"' in runbook
    assert '--key "${RIVET_CLIENT_NAME}.key"' in runbook


def test_application_runner_trusts_only_the_loopback_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Uvicorn cannot trust caller-supplied forwarding headers directly."""
    monkeypatch.setenv("RIVET_ROOT_PATH", "/api")
    with patch.object(main.uvicorn, "run") as uvicorn_run:
        main.run()

    uvicorn_run.assert_called_once_with(
        main.app,
        host=main.HOST,
        port=int(main.PORT),
        log_config=str(main.LOG_CONFIG),
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
        root_path="/api",
        server_header=False,
        access_log=False,
    )


def test_application_runner_rejects_an_unknown_root_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only direct development and the reviewed /api topology are valid."""
    monkeypatch.setenv("RIVET_ROOT_PATH", "/unexpected")

    with (
        patch.object(main.uvicorn, "run") as uvicorn_run,
        pytest.raises(ValueError, match="RIVET_ROOT_PATH"),
    ):
        main.run()
    uvicorn_run.assert_not_called()
