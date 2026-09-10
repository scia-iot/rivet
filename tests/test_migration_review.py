"""Independent hostile-bundle regressions for the migration boundary."""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sciaiot.ovpncp.migration import filesystem, source, validation
from sciaiot.ovpncp.migration.models import (
    Directive,
    Entry,
    MigrationError,
)

# Re-export the shared pytest fixture for this independent test module.
from tests.test_migration import legacy as legacy  # noqa: PLC0414


def _add_file(state, name, data):
    """Add an authenticated file as a hostile bundle author could."""
    state.files[name] = data
    state.manifest.files[name] = Entry(sha256=filesystem.digest(data), size=len(data))


def test_bundle_rejects_unreferenced_application_configuration(legacy):
    """Authentication cannot authorize an unrelated application artifact."""
    state = source.capture(legacy[1], writers_frozen=True)
    _add_file(state, "config/backend.db", b"SQLite format 3\x00unrelated")

    with pytest.raises(MigrationError):
        validation.validate(state)


def test_bundle_rejects_recursive_configuration_metadata(legacy):
    """Import repeats include validation independently of source export."""
    state = source.capture(legacy[1], writers_frozen=True)
    name = state.manifest.main_config
    state.manifest.configurations[name].append(
        Directive(name="config", args=[name], references={"0": name})
    )

    with pytest.raises(MigrationError):
        state.manifest.semantics = validation.semantic_state(state)
        validation.validate(state)


def test_bundle_rejects_non_key_tls_asset(legacy):
    """A file reference alone does not make web content an OpenVPN key."""
    state = source.capture(legacy[1], writers_frozen=True)
    name = "assets/frontend.html"
    _add_file(state, name, b"<!doctype html><title>unrelated UI</title>")
    state.manifest.configurations[state.manifest.main_config].append(
        Directive(name="tls-crypt", args=[name], references={"0": name})
    )

    with pytest.raises(MigrationError):
        state.manifest.semantics = validation.semantic_state(state)
        validation.validate(state)


def test_bundle_rejects_server_identity_substitution(legacy):
    """A CA signature and reused serial cannot replace the indexed server."""
    state = source.capture(legacy[1], writers_frozen=True)
    ca = x509.load_pem_x509_certificate(state.files["pki/ca.crt"])
    ca_key = serialization.load_pem_private_key(
        state.files["pki/private/ca.key"], password=None
    )
    server = x509.load_pem_x509_certificate(state.files["pki/issued/server.crt"])
    replacement_key = rsa.generate_private_key(65537, 2048)
    now = datetime.datetime.now(datetime.UTC)
    replacement = (
        x509.CertificateBuilder()
        .subject_name(server.subject)
        .issuer_name(ca.subject)
        .public_key(replacement_key.public_key())
        .serial_number(server.serial_number)
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(ca_key, hashes.SHA256())
    )
    certificate_path = "assets/server.crt"
    key_path = "assets/server.key"
    _add_file(
        state,
        certificate_path,
        replacement.public_bytes(serialization.Encoding.PEM),
    )
    _add_file(
        state,
        key_path,
        replacement_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    for directive in state.manifest.configurations[state.manifest.main_config]:
        if directive.name in ("cert", "key"):
            mapped = certificate_path if directive.name == "cert" else key_path
            directive.args = [mapped]
            directive.references = {"0": mapped}

    with pytest.raises(MigrationError):
        state.manifest.semantics = validation.semantic_state(state)
        validation.validate(state)


@pytest.mark.parametrize(
    "value", ["rsa|id", "rsa&hostname", "rsa>review-output", "rsa<review-input"]
)
def test_easy_rsa_vars_reject_shell_operators(legacy, value):
    """Declarative variables cannot smuggle executable shell operators."""
    state = source.capture(legacy[1], writers_frozen=True)
    _add_file(state, "pki/vars", f"set_var EASYRSA_ALGO {value}\n".encode())

    with pytest.raises(MigrationError):
        validation.validate(state)


def test_openssl_configuration_rejects_quoted_host_path(legacy):
    """Quotes do not authorize a database path outside migrated PKI."""
    state = source.capture(legacy[1], writers_frozen=True)
    _add_file(
        state,
        "pki/openssl-easyrsa.cnf",
        b'database = "/outside-approved-target/index.txt"\n',
    )

    with pytest.raises(MigrationError):
        validation.validate(state)
