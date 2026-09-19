"""Serialized Easy-RSA leaf lifecycle with irreversible-step crash fences."""

import base64
import json
import os
import re
import stat
from collections.abc import Callable

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode

from . import bounded, files, network
from .journal import Journal
from .mutations import CcdMutations, atomic_write, read_optional
from .settings import Settings


class PkiMutations:
    """Use Easy-RSA exclusively; never regenerate a CA or import arbitrary bytes."""

    def __init__(self, settings: Settings, journal: Journal) -> None:
        self.settings = settings
        self.journal = journal

    def _run(self, verb: str, client: str | None, deadline: float) -> None:
        commands = {"build-client-full", "renew", "revoke", "revoke-renewed", "gen-crl"}
        if verb not in commands:
            raise ControlError(ErrorCode.INVALID_INPUT)
        arguments = [
            str(self.settings.easyrsa_path),
            "--batch",
            f"--pki-dir={self.settings.pki_path}",
            verb,
        ]
        if client is not None:
            if client.startswith("-") or len(client) > 240:
                raise ControlError(ErrorCode.INVALID_INPUT)
            s.GetClient(client=client)
            arguments.append(client)
        if verb == "build-client-full":
            arguments.append("nopass")
        bounded.command(arguments, deadline)
        self._sync(deadline)

    def _client(self, name: str, deadline: float) -> s.ClientMetadata | None:
        return next(
            (
                item
                for item in files.clients(self.settings, deadline)
                if item.client == name
            ),
            None,
        )

    def _serial(self, name: str, deadline: float) -> int:
        return x509.load_pem_x509_certificate(
            bounded.read_file(
                files.certificate_path(self.settings, name, deadline), deadline
            )
        ).serial_number

    def _revoked(self, serial: int, deadline: float) -> bool:
        rows = (
            bounded.read_file(self.settings.pki_path / "index.txt", deadline)
            .decode()
            .splitlines()
        )
        return any(
            len(fields := line.split("\t")) == 6
            and fields[0] == "R"
            and int(fields[3], 16) == serial
            for line in rows
        )

    def _once(
        self,
        operation_id: str,
        step: str,
        complete: Callable[[], bool],
        effect: Callable[[], None],
    ) -> None:
        if complete():
            return
        if self.journal.evidence(operation_id, step) is not None:
            raise ControlError(ErrorCode.UNKNOWN_OUTCOME)
        self.journal.stage(operation_id, step, b"started")
        effect()
        if not complete():
            raise ControlError(ErrorCode.UNKNOWN_OUTCOME)

    def apply(self, request: s.Request, deadline: float) -> None:
        """Reconcile certificate/index evidence before any possible command replay."""
        command = request.command
        assert isinstance(command, s.ChangeClient)
        assert request.operation_id is not None
        name = command.client
        if name.startswith("-") or len(name) > 240:
            raise ControlError(ErrorCode.INVALID_INPUT)
        if self.settings.projection_path is None:
            raise ControlError(ErrorCode.UNAVAILABLE)
        evidence = self.journal.evidence(request.operation_id, "pki")
        if evidence is None:
            before = self._client(name, deadline)
            if command.action == "issue" and before is not None:
                raise ControlError(ErrorCode.CONFLICT)
            if command.action != "issue" and before is None:
                raise ControlError(ErrorCode.NOT_FOUND)
            if (
                command.action == "renew"
                and before is not None
                and before.state != "active"
            ):
                raise ControlError(ErrorCode.CONFLICT)
            if command.action == "delete" and self.settings.ownership_path is not None:
                raw_ownership = read_optional(self.settings.ownership_path, deadline)
                inventory = (
                    network.Ownership.model_validate_json(raw_ownership)
                    if raw_ownership
                    else network.Ownership()
                )
                if (
                    any(
                        name in {item.source_client, item.destination_client}
                        for item in inventory.access
                    )
                    or any(item.client == name for item in inventory.pushes)
                    or (
                        before is not None
                        and before.assignment is not None
                        and any(
                            item.gateway == before.assignment.address
                            for item in inventory.routes
                        )
                    )
                ):
                    raise ControlError(ErrorCode.CONFLICT)
            if command.action == "renew":
                version = bounded.command(
                    [str(self.settings.easyrsa_path), "--version"], deadline
                )
                if re.search(rb"\b3\.1\.7\b", version) is None:
                    raise ControlError(ErrorCode.VERSION_MISMATCH)
            evidence = json.dumps(
                {
                    "fingerprint": before.certificate_sha256 if before else None,
                    "serial": self._serial(name, deadline) if before else None,
                }
            ).encode()
            self.journal.stage(request.operation_id, "pki", evidence)
        old = json.loads(evidence)

        def issued() -> bool:
            actual = self._client(name, deadline)
            return (
                actual is not None
                and actual.state == "active"
                and actual.certificate_sha256 != old["fingerprint"]
            )

        if command.action in {"issue", "renew"}:
            self._once(
                request.operation_id,
                "pki_issue",
                issued,
                lambda: self._run(
                    "renew" if command.action == "renew" else "build-client-full",
                    name,
                    deadline,
                ),
            )
        if command.action in {"revoke", "delete", "renew"}:
            serial = old["serial"]
            self._once(
                request.operation_id,
                "pki_revoke",
                lambda: self._revoked(serial, deadline),
                lambda: self._run(
                    "revoke-renewed" if command.action == "renew" else "revoke",
                    name,
                    deadline,
                ),
            )
        self._sync(deadline)
        self.journal.checkpoint(request.operation_id, "pki")
        if command.action in {"revoke", "delete", "renew"}:
            self._publish_crl(request.operation_id, deadline)
            self.journal.checkpoint(request.operation_id, "crl")
        if command.action == "delete":
            CcdMutations(self.settings, self.journal).clear_assignment(
                request.operation_id, name, deadline
            )
            actual = self._client(name, deadline)
            if actual is not None and actual.certificate_sha256 != old["fingerprint"]:
                raise ControlError(ErrorCode.CONFLICT)
            marker_path = self.settings.pki_path / "ovpncp-deleted.json"
            marker = self.journal.evidence(request.operation_id, "delete_marker")
            if marker is None:
                before_marker = read_optional(marker_path, deadline)
                deleted = files.deleted_clients(self.settings, deadline)
                serial_text = next(
                    fields[3]
                    for line in bounded.read_file(
                        self.settings.pki_path / "index.txt", deadline
                    )
                    .decode()
                    .splitlines()
                    if len(fields := line.split("\t")) == 6
                    and int(fields[3], 16) == old["serial"]
                )
                deleted[name] = serial_text
                marker = json.dumps(
                    {
                        "before": before_marker.decode(),
                        "after": json.dumps(deleted, sort_keys=True),
                    }
                ).encode()
                self.journal.stage(request.operation_id, "delete_marker", marker)
            saved_marker = json.loads(marker)
            if read_optional(marker_path, deadline).decode() not in {
                saved_marker["before"],
                saved_marker["after"],
            }:
                raise ControlError(ErrorCode.CONFLICT)
            atomic_write(marker_path, saved_marker["after"].encode(), deadline)
            for directory, suffix in (
                ("private", "key"),
                ("issued", "crt"),
                ("reqs", "req"),
            ):
                path = self.settings.pki_path / directory / f"{name}.{suffix}"
                # Bounded no-follow verification rejects links before unlink.
                if read_optional(path, deadline):
                    path.unlink()
                    fd = os.open(
                        path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    )
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)

            # Retain revoked public certificates/index history, remove matching
            # private material kept by Easy-RSA under serial-based names.
            index = bounded.read_file(
                self.settings.pki_path / "index.txt", deadline
            ).decode()
            for line in index.splitlines():
                fields = line.split("\t")
                if (
                    len(fields) != 6
                    or re.search(rf"(?:^|/)CN={re.escape(name)}(?:/|$)", fields[5])
                    is None
                ):
                    continue
                serial_text = fields[3]
                if re.fullmatch(r"[0-9A-Fa-f]{1,128}", serial_text) is None:
                    raise ControlError(ErrorCode.INTEGRITY)
                for directory, suffix in (
                    ("private_by_serial", "key"),
                    ("reqs_by_serial", "req"),
                ):
                    path = (
                        self.settings.pki_path
                        / "revoked"
                        / directory
                        / f"{serial_text}.{suffix}"
                    )
                    if read_optional(path, deadline):
                        path.unlink()
            self._sync(deadline)

    def _publish_crl(self, operation_id: str, deadline: float) -> None:
        assert self.settings.projection_path is not None
        path = self.settings.projection_path / "crl.pem"
        evidence = self.journal.evidence(operation_id, "crl_projection")
        if evidence is None:
            before = read_optional(path, deadline)
            self._run("gen-crl", None, deadline)
            raw = bounded.read_file(self.settings.pki_path / "crl.pem", deadline)
            evidence = json.dumps(
                {
                    "before": base64.b64encode(before).decode(),
                    "after": base64.b64encode(raw).decode(),
                }
            ).encode()
            self.journal.stage(operation_id, "crl_projection", evidence)
        saved = json.loads(evidence)
        raw = base64.b64decode(saved["after"], validate=True)
        if read_optional(path, deadline) not in {
            base64.b64decode(saved["before"], validate=True),
            raw,
        }:
            raise ControlError(ErrorCode.CONFLICT)
        crl = x509.load_pem_x509_crl(raw)
        ca = x509.load_pem_x509_certificate(
            bounded.read_file(self.settings.pki_path / "ca.crt", deadline)
        )
        public_key = ca.public_key()
        if not isinstance(
            public_key,
            (
                rsa.RSAPublicKey,
                ec.EllipticCurvePublicKey,
                dsa.DSAPublicKey,
                ed25519.Ed25519PublicKey,
                ed448.Ed448PublicKey,
            ),
        ) or not crl.is_signature_valid(public_key):
            raise ControlError(ErrorCode.INTEGRITY)
        expected = {
            int(fields[3], 16)
            for line in bounded.read_file(
                self.settings.pki_path / "index.txt", deadline
            )
            .decode()
            .splitlines()
            if len(fields := line.split("\t")) == 6 and fields[0] == "R"
        }
        if not expected <= {item.serial_number for item in crl}:
            raise ControlError(ErrorCode.INTEGRITY)
        assert self.settings.projection_path is not None
        atomic_write(
            self.settings.projection_path / "crl.pem",
            raw,
            deadline,
            mode=0o640,
            gid=self.settings.management_gid,
        )

    def _sync(self, deadline: float) -> None:
        count = 0
        for directory, directories, names in os.walk(
            self.settings.pki_path, followlinks=False, topdown=False
        ):
            for name in (*directories, *names):
                path = self.settings.pki_path.__class__(directory) / name
                if path.is_symlink():
                    raise ControlError(ErrorCode.INTEGRITY)
            for name in names:
                count += 1
                if count > 100000:
                    raise ControlError(ErrorCode.EXHAUSTED)
                bounded.remaining(deadline)
                descriptor = os.open(
                    os.path.join(directory, name),
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                )
                try:
                    metadata = os.fstat(descriptor)
                    if (
                        metadata.st_nlink != 1
                        or not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.getuid()
                    ):
                        raise ControlError(ErrorCode.INTEGRITY)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            descriptor = os.open(
                directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
