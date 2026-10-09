"""Writer flags, recovery availability, bounded admissions and archive transport."""

import dataclasses
import os
import socket
import threading
from pathlib import Path

import pytest

from sciaiot.rivet.adapters.vpn.agent import AgentVpnControl
from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control.errors import ControlError
from sciaiot.rivet.vpn_agent.server import UnixAgentServer
from sciaiot.rivet.vpn_agent.writer import MutationVpnControl
from tests.support.agent import request
from tests.support.pki import change


def test_lookup_and_flags_work_while_unready(pki_control) -> None:
    control, _ = pki_control
    result = change(control, "issue")
    health = control.execute(request(s.Health())).result
    assert isinstance(health, s.HealthResult) and not health.ready
    lookup = control.execute(
        request(s.LookupOperation(operation_id=result.operation_id))
    ).result
    assert lookup == result
    config = control.execute(request(s.ServerConfig())).result
    assert isinstance(config, s.ConfigResult) and config.generation == result.generation
    with pytest.raises(ControlError):
        control.execute(request(s.Reload()))
    with pytest.raises(ControlError):
        control.execute(request(s.PollEvents()))
    with pytest.raises(ControlError):
        control.execute(request(s.Archive(client="device", generation=0)))


def test_writer_admission_is_bounded(pki_control) -> None:
    control, _ = pki_control
    control._admissions = threading.BoundedSemaphore(1)
    control._admissions.acquire()
    with pytest.raises(ControlError, match="exhausted"):
        control.execute(request(s.Health()))
    control._admissions.release()
    entered = threading.Event()
    release = threading.Event()

    def hold() -> None:
        with control._writer:
            entered.set()
            release.wait(2)

    thread = threading.Thread(target=hold)
    thread.start()
    assert entered.wait(1)
    with pytest.raises(ControlError, match="timeout"):
        control.execute(request(s.Health()).model_copy(update={"deadline_ms": 1}))
    release.set()
    thread.join(1)


def test_lost_journal_cannot_replace_existing_identity(pki_control) -> None:
    control, _ = pki_control
    configured = control.settings
    control.close()
    assert configured.journal_path is not None
    path = configured.journal_path / "operations.sqlite3"
    saved = path.with_suffix(".saved")
    path.rename(saved)
    with pytest.raises(ControlError, match="integrity"):
        MutationVpnControl(configured)
    path.unlink()
    saved.rename(path)
    MutationVpnControl(configured).close()


def test_real_archive_transport_and_stale_socket_recovery(
    pki_control, monkeypatch: pytest.MonkeyPatch
) -> None:
    control, _ = pki_control
    change(control, "issue")
    client = control.execute(request(s.GetClient(client="device"))).result
    assert isinstance(client, s.ClientResult)
    socket_path = Path(control.settings.control_socket)
    socket_path.parent.chmod(0o2750)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stale:
        stale.bind(str(socket_path))
    monkeypatch.setattr(
        control,
        "_health",
        lambda _: s.HealthResult(ready=True, generation=control.journal.generation),
    )
    with UnixAgentServer(control.settings, control) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            agent = AgentVpnControl(
                control.settings.control_socket, peer_uid=os.getuid()
            )
            with agent.open_archive(
                request(s.Archive(client="device", generation=client.item.generation))
            ) as stream:
                assert b"".join(stream).startswith(b"PK")
                assert stream.verified
        finally:
            server.shutdown()
            thread.join(2)
    assert not socket_path.exists()


def test_reload_success_replays_without_a_second_signal(
    pki_control, monkeypatch: pytest.MonkeyPatch
) -> None:
    control, _ = pki_control
    control.settings = dataclasses.replace(
        control.settings, mutation_families=frozenset({"pki", "management"})
    )
    config = control.settings.config_path
    config.write_text(config.read_text() + "\npersist-key\npersist-tun\n")
    calls: list[bool] = []
    from sciaiot.rivet.vpn_agent.control import ReadOnlyVpnControl

    monkeypatch.setattr(control, "_network_snapshot", lambda _: b"stable")
    monkeypatch.setattr(
        ReadOnlyVpnControl,
        "_health",
        lambda *_: s.HealthResult(ready=True, generation=0),
    )
    monkeypatch.setattr(control.management, "reload", lambda _: calls.append(True))
    intent = request(s.Reload())
    result = control.execute(intent).result
    assert isinstance(result, s.MutationResult) and result.state == "succeeded"
    assert control.execute(intent).result == result
    assert calls == [True]


def test_older_journal_restore_is_refused_by_config_revision(pki_control) -> None:
    control, _ = pki_control
    configured = control.settings
    assert configured.journal_path is not None
    path = configured.journal_path / "operations.sqlite3"
    before = path.read_bytes()
    change(control, "issue")
    control.close()
    path.write_bytes(before)
    with pytest.raises(ControlError, match="integrity"):
        MutationVpnControl(configured)


@pytest.mark.parametrize(
    "options",
    [
        "",
        "persist-key\n",
        "persist-tun\n",
        "persist-key\npersist-tun\nremap-usr1 SIGHUP\n",
        "persist-key\npersist-tun\nup-restart\n",
    ],
)
def test_reload_rejects_unsafe_reset_before_signal(pki_control, monkeypatch, options):
    control, _ = pki_control
    control.settings = dataclasses.replace(
        control.settings, mutation_families=frozenset({"management"})
    )
    config = control.settings.config_path
    config.write_text(config.read_text() + "\n" + options)
    calls = []
    monkeypatch.setattr(control.management, "reload", lambda _: calls.append(True))
    intent = request(s.Reload())
    result = control.execute(intent).result
    assert isinstance(result, s.MutationResult) and result.state == "failed"
    assert control.journal.evidence(intent.operation_id, "management") is None
    assert calls == []


@pytest.mark.parametrize(
    "option",
    [
        "allow-compression yes",
        "allow-compression asym",
        'push "compress lz4"',
        'push "route-ipv6 2001:db8::/64"',
        'push "ifconfig-ipv6 2001:db8::1/64 2001:db8::2"',
    ],
)
def test_runtime_rejects_pushed_or_permitted_unsupported_modes(pki_control, option):
    import time

    control, _ = pki_control
    config = control.settings.config_path
    config.write_text(config.read_text() + "\n" + option + "\n")
    with pytest.raises(ControlError):
        control._validate_runtime(time.monotonic() + 2)


def test_runtime_allows_explicit_compression_denial(pki_control):
    import time

    control, _ = pki_control
    config = control.settings.config_path
    config.write_text(config.read_text() + "\nallow-compression no\n")
    control._validate_runtime(time.monotonic() + 2)


def test_reload_keeps_network_drift_partial_then_recovers_without_resignal(
    pki_control, monkeypatch
):
    from sciaiot.rivet.vpn_agent.control import ReadOnlyVpnControl

    control, _ = pki_control
    control.settings = dataclasses.replace(
        control.settings, mutation_families=frozenset({"management"})
    )
    config = control.settings.config_path
    config.write_text(config.read_text() + "\npersist-key\npersist-tun\n")
    signals = []
    stable = False
    snapshots = []

    def snapshot(_):
        snapshots.append(True)
        return b"original" if len(snapshots) == 1 or stable else b"changed"

    monkeypatch.setattr(control, "_network_snapshot", snapshot)
    monkeypatch.setattr(
        ReadOnlyVpnControl,
        "_health",
        lambda *_: s.HealthResult(ready=True, generation=0),
    )
    monkeypatch.setattr(control.management, "reload", lambda _: signals.append(True))
    intent = request(s.Reload()).model_copy(update={"deadline_ms": 30})
    result = control.execute(intent).result
    assert isinstance(result, s.MutationResult) and result.state == "partial"
    stable = True
    control.reconcile()
    recovered = control.execute(
        request(s.LookupOperation(operation_id=intent.operation_id))
    ).result
    assert isinstance(recovered, s.MutationResult) and recovered.state == "succeeded"
    assert signals == [True]
