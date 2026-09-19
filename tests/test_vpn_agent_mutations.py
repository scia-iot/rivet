"""Owned CCD mutations preserve foreign bytes and crash evidence."""

from pathlib import Path

import pytest

from sciaiot.ovpncp.application.vpn_control.errors import ControlError
from sciaiot.ovpncp.vpn_agent.mutations import replace_block


def test_owned_block_preserves_foreign_bytes() -> None:
    foreign = b'# operator comment\npush "dhcp-option DNS 10.1.1.1"\n'
    result = replace_block(
        foreign, "assignment", b"ifconfig-push 10.8.0.2 255.255.255.0\n"
    )
    assert result.startswith(foreign)
    assert replace_block(result, "assignment", b"") == foreign
    assert (
        replace_block(result, "assignment", b"ifconfig-push 10.8.0.2 255.255.255.0\n")
        == result
    )


def test_foreign_assignment_and_broken_markers_fail_closed() -> None:
    with pytest.raises(ControlError):
        replace_block(b"ifconfig-push 10.8.0.2 255.255.255.0\n", "assignment", b"x\n")
    with pytest.raises(ControlError):
        replace_block(b"# ovpncp:begin:assignment\n", "assignment", b"x\n")


def test_assignment_crash_after_replace_reconciles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dataclasses
    from unittest.mock import patch

    from sciaiot.ovpncp.application.vpn_control import schemas as s
    from sciaiot.ovpncp.vpn_agent import mutations
    from sciaiot.ovpncp.vpn_agent.writer import MutationVpnControl
    from tests.test_vpn_agent import request, settings

    configured = dataclasses.replace(
        settings(tmp_path),
        journal_path=tmp_path,
        mutation_families=frozenset({"assignments"}),
        projection_path=tmp_path / "projection",
    )
    configured.ccd_path.mkdir()
    assert configured.projection_path is not None
    (configured.projection_path / "ccd").mkdir(parents=True)
    configured.config_path.write_text(
        "dev tun0\nserver 10.8.0.0 255.255.255.0\ntopology subnet\ndisable-dco\n"
        f"client-config-dir {configured.projection_path / 'ccd'}\n"
    )
    client = s.ClientMetadata(
        client="device",
        generation=1,
        state="active",
        issuer="ca",
        subject="device",
        certificate_sha256="a" * 64,
        not_before=1,
        not_after=2,
    )
    monkeypatch.setattr(mutations.files, "clients", lambda *_: (client,))
    intent = request(
        s.SetAssignment(client="device", assignment=s.Assignment(address="10.8.0.2"))
    )
    control = MutationVpnControl(configured)
    write = mutations.atomic_write

    def crash(path: Path, data: bytes, deadline: float) -> None:
        write(path, data, deadline)
        raise OSError("injected crash")

    with (
        patch.object(mutations, "atomic_write", side_effect=crash),
        pytest.raises(ControlError),
    ):
        control.execute(intent)
    assert control.journal.lookup(str(intent.operation_id)).state == "pending"
    control.close()
    control = MutationVpnControl(configured)
    control.reconcile()
    result = control.execute(intent).result
    assert isinstance(result, s.MutationResult)
    assert result.state == "succeeded"
    assert control.journal.generation == 1
    control.close()
