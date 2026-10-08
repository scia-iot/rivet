"""Synthetic local HTTPS JWKS and signed-token probe for isolated Compose tests.

This file is copied into a private disposable mount. It serves only inside an
attested disposable namespace and never prints key or token bytes.
"""

import argparse
import base64
import datetime
import http.client
import json
import os
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from jose import jwt

TENANT = "11111111-1111-4111-8111-111111111111"
AUDIENCE = "22222222-2222-4222-8222-222222222222"
SPA = "33333333-3333-4333-8333-333333333333"
SCOPE = f"api://{AUDIENCE}/access_as_user"
UPGRADE_SCOPE = f"api://{AUDIENCE}/access_as_user-v2"
KID = "synthetic-phase6-key"
FIXTURE = Path("/fixture")


def _write(name: str, payload: bytes, mode: int) -> None:
    """Create one synthetic fixture member with a strict file mode."""
    path = FIXTURE / name
    with path.open("xb") as stream:
        stream.write(payload)
    path.chmod(mode)


def _b64(value: int) -> str:
    """Encode a public RSA integer for a JSON Web Key."""
    data = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pem_key(key: rsa.RSAPrivateKey) -> bytes:
    """Serialize a synthetic private key for this disposable fixture only."""
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def generate() -> None:
    """Generate a short-lived TLS CA/leaf and separate JWT signing key."""
    now = datetime.datetime.now(datetime.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Disposable Phase 6 CA")]
    )
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "login.microsoftonline.com")]
    )
    leaf_certificate = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("login.microsoftonline.com")]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write("ca.crt", ca_certificate.public_bytes(serialization.Encoding.PEM), 0o644)
    _write("tls.crt", leaf_certificate.public_bytes(serialization.Encoding.PEM), 0o644)
    _write("tls.key", _pem_key(leaf_key), 0o600)
    jwt_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _write("jwt.key", _pem_key(jwt_key), 0o600)
    numbers = jwt_key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kid": KID,
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": _b64(numbers.n),
                "e": _b64(numbers.e),
            }
        ]
    }
    _write("jwks.json", json.dumps(jwks).encode(), 0o644)


class JwksHandler(BaseHTTPRequestHandler):
    """Serve the exact Entra discovery path within the disposable namespace."""

    def do_GET(self) -> None:
        """Return only the synthetic public key for the exact discovery URL."""
        if self.path != f"/{TENANT}/discovery/v2.0/keys":
            self.send_error(404)
            return
        payload = (FIXTURE / "jwks.json").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        """Suppress token, path and network logging."""


def serve() -> None:
    """Serve TLS inside a private namespace at a fixed reviewed address."""
    listen = os.environ.get("OVPNCP_FIXTURE_LISTEN", "127.0.0.1")
    if listen not in {"127.0.0.1", "0.0.0.0"}:
        raise ValueError("Invalid disposable fixture listen address.")
    server = HTTPServer((listen, 443), JwksHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(FIXTURE / "tls.crt", FIXTURE / "tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def _token(
    role: str,
    *,
    audience: str = AUDIENCE,
    expires_in: int = 600,
    app_only: bool = False,
) -> str:
    """Sign a short-lived synthetic token with the fixture private key."""
    now = int(datetime.datetime.now(datetime.UTC).timestamp())
    claims = {
        "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
        "aud": audience,
        "sub": "synthetic-service" if app_only else "synthetic-subject",
        "oid": "synthetic-service" if app_only else "synthetic-human-object",
        "roles": [role],
        "iat": now - 5,
        "nbf": now - 5,
        "exp": now + expires_in,
    }
    if not app_only:
        claims["scp"] = "access_as_user"
    return jwt.encode(
        claims,
        (FIXTURE / "jwt.key").read_bytes(),
        algorithm="RS256",
        headers={"kid": KID},
    )


def _request(path: str, token: str | None = None) -> tuple[int, str, bytes, str]:
    """Query Nginx loopback without exposing request or response secrets."""
    connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=5)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        return (
            response.status,
            response.getheader("Content-Type", ""),
            response.read(65536),
            response.getheader("Cache-Control", ""),
        )
    finally:
        connection.close()


def _expect(stage: str, condition: bool) -> None:
    """Report only a fixed, non-sensitive failed assertion label."""
    if not condition:
        raise RuntimeError(stage)


def probe(expected_scope: str) -> None:
    """Exercise UI, proxy, real JWT verification and role policy end to end."""
    status, _, body, _ = _request("/healthz")
    _expect("web_health", status == 200 and body == b"ok\n")
    status, _, body, cache = _request("/runtime-config.js")
    _expect("runtime_config", status == 200 and cache == "no-store")
    _expect("runtime_scope", f'"apiScope":"{expected_scope}"'.encode() in body)
    status, content_type, body, _ = _request("/api/me")
    _expect(
        "anonymous_denied", status == 401 and "application/problem+json" in content_type
    )
    _expect("anonymous_redacted", b"Bearer" not in body)
    status, _, body, _ = _request("/api/me", _token("sysadmin"))
    _expect("admin_identity", status == 200)
    principal = json.loads(body)
    _expect("admin_role", principal["roles"] == ["sysadmin"])
    _expect("admin_permission", "server:read" in principal["permissions"])
    identity = str(principal["id"])
    identity_path = FIXTURE / "admin-id"
    if identity_path.exists():
        _expect("api_identity_persistence", identity_path.read_text() == identity)
    else:
        identity_path.write_text(identity)
    status, _, body, _ = _request("/api/me", _token("device_user"))
    _expect(
        "user_identity", status == 200 and json.loads(body)["roles"] == ["device_user"]
    )
    status, content_type, _, _ = _request("/api/server/health", _token("device_user"))
    _expect(
        "user_forbidden", status == 403 and "application/problem+json" in content_type
    )
    status, _, _, _ = _request(
        "/api/server/health", _token("ServiceAdmin", app_only=True)
    )
    _expect("app_only_service_admin", status == 200)
    status, content_type, _, _ = _request("/api/server/health", _token("ServiceAdmin"))
    _expect(
        "delegated_service_admin_denied",
        status == 403 and "application/problem+json" in content_type,
    )
    for token in (
        _token("sysadmin", audience="wrong-audience"),
        _token("sysadmin", expires_in=-60),
    ):
        status, content_type, _, _ = _request("/api/me", token)
        _expect(
            "invalid_claim_denied",
            status == 401 and "application/problem+json" in content_type,
        )
    token = _token("sysadmin")
    parts = token.split(".")
    signature = parts[2]
    parts[2] = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered = ".".join(parts)
    status, content_type, body, _ = _request("/api/me", tampered)
    _expect(
        "tampered_signature_denied",
        status in {401, 500} and "application/problem+json" in content_type,
    )
    _expect(
        "tampered_signature_redacted",
        token.encode() not in body and tampered.encode() not in body,
    )
    status, content_type, _, _ = _request("/api/me", _token("unknown-role"))
    _expect(
        "unknown_role_denied",
        status == 403 and "application/problem+json" in content_type,
    )


def main() -> None:
    """Run only one explicit fixture action."""
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("generate", "serve", "probe"))
    parser.add_argument("--scope", choices=(SCOPE, UPGRADE_SCOPE))
    args = parser.parse_args()
    if args.action == "generate":
        generate()
    elif args.action == "serve":
        serve()
    elif args.scope is not None:
        status = FIXTURE / "probe-status"
        status.write_text("started")
        try:
            probe(args.scope)
        except RuntimeError as error:
            status.write_text(str(error))
            raise SystemExit(1) from None
        except Exception:  # noqa: BLE001 - never write exception text
            status.write_text("unexpected")
            raise SystemExit(1) from None
        status.write_text("passed")
    else:
        parser.error("Probe requires an expected scope.")


if __name__ == "__main__":
    main()
