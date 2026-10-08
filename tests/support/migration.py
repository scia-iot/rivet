"""Signed, disposable Easy-RSA source tree for migration tests."""

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sciaiot.ovpncp.migration.models import SourceSpec


@pytest.fixture
def legacy(tmp_path: Path) -> tuple[Path, SourceSpec]:
    """Make a real signed Easy-RSA-shaped PKI without system commands."""
    root = tmp_path / "legacy"
    pki = root / "pki"
    for directory in ("private", "issued", "reqs", "certs_by_serial"):
        (pki / directory).mkdir(parents=True, mode=0o700)
    now = datetime.datetime.now(datetime.UTC)
    ca_key = rsa.generate_private_key(65537, 2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=2))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(ca_key, hashes.SHA256())
    )
    (pki / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def write_key(path, key):
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    write_key(pki / "private/ca.key", ca_key)
    entries = []
    for serial, name in ((2, "server"), (3, "client")):
        key = rsa.generate_private_key(65537, 2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=20))
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        x509.ExtendedKeyUsageOID.SERVER_AUTH
                        if name == "server"
                        else x509.ExtendedKeyUsageOID.CLIENT_AUTH
                    ]
                ),
                False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        (pki / f"issued/{name}.crt").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        write_key(pki / f"private/{name}.key", key)
        request = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(cert.subject)
            .sign(key, hashes.SHA256())
        )
        (pki / f"reqs/{name}.req").write_bytes(
            request.public_bytes(serialization.Encoding.PEM)
        )
        (pki / f"certs_by_serial/{serial:02X}.pem").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        expiry = cert.not_valid_after_utc.strftime("%y%m%d%H%M%SZ")
        entries.append(f"V\t{expiry}\t\t{serial:02X}\tunknown\t/CN={name}\n")
    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(4)
        .revocation_date(now - datetime.timedelta(hours=1))
        .build()
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_name)
        .last_update(now - datetime.timedelta(hours=1))
        .next_update(now + datetime.timedelta(days=7))
        .add_revoked_certificate(revoked)
        .sign(ca_key, hashes.SHA256())
    )
    (pki / "crl.pem").write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    (pki / "crl.der").write_bytes(crl.public_bytes(serialization.Encoding.DER))
    expiry = (now + datetime.timedelta(days=20)).strftime("%y%m%d%H%M%SZ")
    revoked_at = revoked.revocation_date_utc.strftime("%y%m%d%H%M%SZ")
    entries.append(f"R\t{expiry}\t{revoked_at}\t04\tunknown\t/CN=removed\n")
    (pki / "index.txt").write_text("".join(entries))
    (pki / "serial").write_text("05\n")
    (pki / "serial.old").write_text("04\n")
    (pki / "crlnumber").write_text("01\n")
    (pki / "index.txt.old").write_text("".join(entries[:2]))
    (pki / "vars").write_text('set_var EASYRSA_ALGO "rsa"\n')
    (pki / "openssl-easyrsa.cnf").write_text("# fixture\n")
    (root / "ccd").mkdir()
    (root / "ccd/client").write_text("ifconfig-push 10.9.0.2 255.255.255.0\n")
    (root / "server.conf").write_text(
        "dev tun\nproto udp\nport 1194\nserver 10.9.0.0 255.255.255.0\n"
        "ca pki/ca.crt\ncert pki/issued/server.crt\n"
        "key pki/private/server.key\ncrl-verify pki/crl.pem\n"
        "dh none\nclient-config-dir ccd\n"
    )
    spec = SourceSpec(
        openvpn_root=str(root),
        easyrsa_root=str(pki),
        server_config="server.conf",
        versions={"openvpn": "2.6.12", "easyrsa": "3.2.1", "openssl": "3.4.0"},
        serial_policy="sequential",
    )
    return root, spec
