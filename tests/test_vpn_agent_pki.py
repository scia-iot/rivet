"""Synthetic Easy-RSA boundary fixtures and real certificate/archive validation."""

import io
import time
import zipfile

import pytest

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError
from sciaiot.ovpncp.vpn_agent import bounded, files
from tests.support.agent import request
from tests.support.pki import change


def test_lifecycle_archive_renew_revoke_delete(pki_control) -> None:
    control, commands = pki_control
    assert change(control, "issue").state == "succeeded"
    before = files.clients(control.settings, time.monotonic() + 2)[0]
    archive_request = request(s.Archive(client="device", generation=before.generation))
    with control.open_archive(archive_request) as stream:
        data = b"".join(stream)
        assert stream.verified
    assert set(zipfile.ZipFile(io.BytesIO(data)).namelist()) == {
        "ca.crt",
        "issued/device.crt",
        "private/device.key",
    }
    unread = control.open_archive(archive_request)
    assert change(control, "renew").state == "succeeded"
    with pytest.raises(ControlError):
        next(unread)
    assert any("revoke-renewed" in command for command in commands)
    assert change(control, "revoke").state == "succeeded"
    assert change(control, "delete").state == "succeeded"
    assert files.clients(control.settings, time.monotonic() + 2) == ()
    assert len((control.settings.pki_path / "index.txt").read_text().splitlines()) == 2


def test_archive_quota_and_unread_close(pki_control) -> None:
    control, _ = pki_control
    change(control, "issue")
    generation = files.clients(control.settings, time.monotonic() + 2)[0].generation
    intent = request(s.Archive(client="device", generation=generation))
    streams = [control.open_archive(intent) for _ in range(4)]
    with pytest.raises(ControlError):
        control.open_archive(intent)
    streams.pop().close()
    control.open_archive(intent).close()
    for stream in streams:
        stream.close()


def test_interrupted_issue_is_not_blindly_repeated(
    pki_control, monkeypatch: pytest.MonkeyPatch
) -> None:
    control, commands = pki_control
    original = bounded.command

    def interrupted(
        arguments: list[str], deadline: float, input_data: bytes | None = None
    ) -> bytes:
        original(arguments, deadline, input_data)
        raise OSError("lost response after complete effect")

    monkeypatch.setattr(bounded, "command", interrupted)
    intent = request(s.ChangeClient(client="device", action="issue"))
    with pytest.raises(ControlError):
        control.execute(intent)
    count = len(commands)
    control.reconcile()
    assert control.journal.lookup(str(intent.operation_id)).state == "succeeded"
    assert len(commands) == count


def test_reissue_deleted_name_and_revoke_new_serial_remain_observable(
    pki_control,
) -> None:
    control, _ = pki_control
    assert change(control, "issue").state == "succeeded"
    assert change(control, "delete").state == "succeeded"
    assert change(control, "issue").state == "succeeded"
    assert change(control, "revoke").state == "succeeded"
    clients = files.clients(control.settings, time.monotonic() + 2)
    assert len(clients) == 1 and clients[0].state == "revoked"
