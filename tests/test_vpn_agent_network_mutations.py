"""Owned route and firewall mutation rejection and restart boundaries."""

import dataclasses
import json
from pathlib import Path

import pytest

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.vpn_agent import bounded
from sciaiot.ovpncp.vpn_agent.writer import MutationVpnControl
from tests.test_vpn_agent import request, settings


def configured_control(tmp_path: Path) -> MutationVpnControl:
    """Build only synthetic files and explicitly allocated route ownership."""
    configured = dataclasses.replace(
        settings(tmp_path),
        journal_path=tmp_path,
        mutation_families=frozenset({"routes", "access"}),
        route_protocol=201,
        ownership_path=tmp_path / "ownership.json",
    )
    configured.config_path.write_text(
        "dev tun0\nserver 10.8.0.0 255.255.255.0\ntopology subnet\ndisable-dco\n"
    )
    return MutationVpnControl(configured)


def test_owned_route_reconciles_after_command_before_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sciaiot.ovpncp.application.vpn_control.errors import ControlError

    control = configured_control(tmp_path)
    route = s.ManagedRoute(
        route_id="00000000-0000-4000-8000-000000000001",
        network="192.168.40.0/24",
        gateway="10.8.0.2",
    )
    intent = request(s.SetRoute(route=route, present=True))
    observed: list[dict[str, object]] = []
    commands: list[list[str]] = []
    monkeypatch.setattr(bounded, "observe", lambda *_: json.dumps(observed).encode())

    def execute(arguments: list[str], deadline: float) -> bytes:
        commands.append(arguments)
        observed.append(
            {
                "dst": route.network,
                "gateway": route.gateway,
                "dev": "tun0",
                "protocol": 201,
            }
        )
        raise OSError("reply lost after kernel accepted route")

    monkeypatch.setattr(bounded, "command", execute)
    with pytest.raises(ControlError):
        control.execute(intent)
    assert len(commands) == 1
    control.reconcile()
    result = control.execute(intent).result
    assert isinstance(result, s.MutationResult)
    assert result.state == "succeeded"
    assert len(commands) == 1
    assert control.settings.ownership_path is not None
    assert (
        json.loads(control.settings.ownership_path.read_bytes())["routes"][0][
            "route_id"
        ]
        == route.route_id
    )
    control.close()


def test_foreign_route_never_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = configured_control(tmp_path)
    route = s.ManagedRoute(
        route_id="00000000-0000-4000-8000-000000000001",
        network="192.168.40.0/24",
        gateway="10.8.0.2",
    )
    monkeypatch.setattr(
        bounded,
        "observe",
        lambda *_: json.dumps(
            [
                {
                    "dst": route.network,
                    "gateway": route.gateway,
                    "dev": "tun0",
                    "protocol": 201,
                }
            ]
        ).encode(),
    )
    monkeypatch.setattr(
        bounded, "command", lambda *_: pytest.fail("foreign route changed")
    )
    result = control.execute(request(s.SetRoute(route=route, present=True))).result
    assert isinstance(result, s.MutationResult)
    assert result.state == "failed"
    assert result.completed == ()
    control.close()


@pytest.fixture
def firewall(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Model an atomic filter-table restore while preserving foreign rules."""
    import shlex

    from sciaiot.ovpncp.vpn_agent import files

    control = configured_control(tmp_path)
    control.settings.ccd_path.mkdir()
    state: list[tuple[str, ...]] = [("-A", "FORWARD", "-j", "ACCEPT")]
    foreign = state[0]
    chain = False
    commands: list[bytes] = []
    clients = tuple(
        s.ClientMetadata(
            client=name,
            generation=1,
            state="active",
            issuer="ca",
            subject=name,
            certificate_sha256="a" * 64,
            not_before=1,
            not_after=2,
            assignment=s.Assignment(address=address),
        )
        for name, address in (("alpha", "10.8.0.2"), ("beta", "10.8.0.3"))
    )
    monkeypatch.setattr(files, "clients", lambda *_: clients)

    def observe(kind: str, device: str, deadline: float) -> bytes:
        if kind == "backend":
            return b"iptables v1.8.9 (nf_tables)"
        assert kind == "rules"
        declaration = ":OVPNCP_FORWARD - [0:0]\n" if chain else ""
        return (declaration + "\n".join(shlex.join(rule) for rule in state)).encode()

    def restore(
        arguments: list[str], deadline: float, payload: bytes | None = None
    ) -> bytes:
        nonlocal chain
        assert payload is not None
        commands.append(payload)
        for line in payload.decode().splitlines():
            words = tuple(shlex.split(line))
            if not words or words[0] in {"*filter", "COMMIT"}:
                continue
            if words[0] == ":OVPNCP_FORWARD":
                chain = True
            elif words[0] == "-F":
                state[:] = [rule for rule in state if rule[1] != words[1]]
            elif words[0] == "-D":
                state.remove(("-A", *words[1:]))
            elif words[0] == "-I":
                state.insert(0, ("-A", words[1], *words[3:]))
            else:
                state.append(words)
        return b""

    monkeypatch.setattr(bounded, "observe", observe)
    monkeypatch.setattr(bounded, "command", restore)
    intent = s.AccessIntent(
        access_id="00000000-0000-4000-8000-000000000002",
        source_client="alpha",
        destination_client="beta",
        source_address="10.8.0.2",
        destination_address="10.8.0.3",
        private_networks=("192.168.40.0/24",),
    )
    yield control, state, commands, intent, foreign
    control.close()


def test_paired_access_pushes_and_remove_preserve_foreign_firewall(firewall) -> None:
    import time

    from sciaiot.ovpncp.vpn_agent import files, network

    control, state, commands, intent, foreign = firewall
    ensure = request(s.SetAccess(intent=intent, present=True))
    result = control.execute(ensure).result
    assert isinstance(result, s.MutationResult) and result.state == "succeeded"
    assert state[2] == foreign
    assert state[-1][-1] == "DROP"
    count = len(commands)
    assert control.execute(ensure).result == result
    assert len(commands) == count
    pushes = s.SetPushRoutes(
        client="alpha",
        intent_id=intent.access_id,
        routes=(s.PushRoute(network="192.168.40.0/24", gateway="10.8.0.3"),),
    )
    pushed = control.execute(
        request(pushes).model_copy(
            update={"expected_generation": control.journal.generation}
        )
    ).result
    assert isinstance(pushed, s.MutationResult) and pushed.state == "succeeded"
    config = files.configuration(control.settings, time.monotonic() + 2)
    access, actual_pushes = network.access(
        control.settings, config, time.monotonic() + 2
    )
    assert access == (intent,)
    assert actual_pushes[0].routes == pushes.routes
    cleared = control.execute(
        request(pushes.model_copy(update={"routes": ()})).model_copy(
            update={"expected_generation": control.journal.generation}
        )
    ).result
    assert isinstance(cleared, s.MutationResult) and cleared.state == "succeeded"
    removed = control.execute(
        request(s.SetAccess(intent=intent, present=False)).model_copy(
            update={"expected_generation": control.journal.generation}
        )
    ).result
    assert isinstance(removed, s.MutationResult) and removed.state == "succeeded"
    assert foreign in state and state[-1][-1] == "DROP"


def test_administrator_tun_drop_refuses_prepend(firewall) -> None:
    control, state, commands, intent, _ = firewall
    state.insert(0, ("-A", "FORWARD", "-i", "tun0", "-j", "DROP"))
    result = control.execute(request(s.SetAccess(intent=intent, present=True))).result
    assert isinstance(result, s.MutationResult) and result.state == "failed"
    assert commands == []
    assert state[0][-1] == "DROP"


def test_foreign_owned_chain_rule_refuses_replacement(firewall) -> None:
    control, state, commands, intent, _ = firewall
    control.execute(request(s.SetAccess(intent=intent, present=True)))
    state.append(("-A", "OVPNCP_FORWARD", "-j", "ACCEPT"))
    count = len(commands)
    result = control.execute(
        request(s.SetAccess(intent=intent, present=False)).model_copy(
            update={"expected_generation": control.journal.generation}
        )
    ).result
    assert isinstance(result, s.MutationResult) and result.state == "failed"
    assert len(commands) == count


def test_administrator_goto_is_not_bypassed(firewall) -> None:
    control, state, commands, intent, _ = firewall
    state.insert(0, ("-A", "FORWARD", "-i", "tun0", "-g", "ADMIN_POLICY"))
    result = control.execute(request(s.SetAccess(intent=intent, present=True))).result
    assert isinstance(result, s.MutationResult) and result.state == "failed"
    assert commands == []
