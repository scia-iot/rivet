"""Owned route and firewall mutation rejection and restart boundaries."""

import dataclasses
import json
from pathlib import Path

import pytest

from sciaiot.rivet.application.vpn_control import schemas as s
from sciaiot.rivet.application.vpn_control.errors import ControlError, ErrorCode
from sciaiot.rivet.vpn_agent import access_mutations, bounded, network
from sciaiot.rivet.vpn_agent.writer import MutationVpnControl
from tests.support.agent import request, settings


def configured_control(tmp_path: Path, protocol: int = 201) -> MutationVpnControl:
    """Build only synthetic files and explicitly allocated route ownership."""
    configured = dataclasses.replace(
        settings(tmp_path),
        journal_path=tmp_path,
        mutation_families=frozenset({"routes", "access"}),
        route_protocol=protocol,
        ownership_path=tmp_path / "ownership.json",
    )
    configured.config_path.write_text(
        "dev tun0\nserver 10.8.0.0 255.255.255.0\ntopology subnet\ndisable-dco\n"
    )
    return MutationVpnControl(configured)


def test_owned_route_reconciles_after_command_before_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sciaiot.rivet.application.vpn_control.errors import ControlError

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


def test_named_iproute_protocol_reconciles_from_numeric_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A kernel route named bgp by iproute2 completes its pending journal."""
    control = configured_control(tmp_path, protocol=186)
    route = s.ManagedRoute(
        route_id="00000000-0000-4000-8000-000000000001",
        network="192.168.40.0/24",
        gateway="10.8.0.2",
    )
    intent = request(s.SetRoute(route=route, present=True))
    installed = False
    route_adds = 0
    original_observe = bounded.observe

    def observe(kind: str, device: str, deadline: float) -> bytes:
        if kind == "routes":
            return original_observe(kind, device, deadline)
        return b""

    def command(arguments: list[str], deadline: float) -> bytes:
        nonlocal installed, route_adds
        if arguments[:2] == ["/usr/sbin/ip", "-N"]:
            protocol = "186"
        elif arguments[:2] == ["/usr/sbin/ip", "-j"]:
            protocol = "bgp"
        else:
            protocol = None
        if "show" in arguments:
            rows = (
                [
                    {
                        "dst": route.network,
                        "gateway": route.gateway,
                        "dev": "tun0",
                        "protocol": protocol,
                    }
                ]
                if installed
                else []
            )
            return json.dumps(rows).encode()
        if "add" in arguments:
            route_adds += 1
            installed = True
            raise OSError("reply lost after kernel accepted route")
        pytest.fail("Unexpected system command")

    monkeypatch.setattr(bounded, "observe", observe)
    monkeypatch.setattr(bounded, "command", command)
    with pytest.raises(ControlError):
        control.execute(intent)
    control.reconcile()
    result = control.execute(intent).result
    assert isinstance(result, s.MutationResult)
    assert result.state == "succeeded"
    assert route_adds == 1
    assert control.settings.ownership_path is not None
    assert (
        json.loads(control.settings.ownership_path.read_text())["routes"][0]["route_id"]
        == route.route_id
    )
    control.close()


@pytest.mark.parametrize("gateway", ["10.8.0.1", "10.8.0.2"])
def test_foreign_route_never_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gateway: str
) -> None:
    control = configured_control(tmp_path)
    route = s.ManagedRoute(
        route_id="00000000-0000-4000-8000-000000000001",
        network="192.168.40.0/24",
        gateway=gateway,
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


@pytest.mark.parametrize(
    ("gateway", "destination"),
    [
        ("10.8.0.0", "192.168.40.0/24"),
        ("10.8.0.255", "192.168.40.0/24"),
        ("10.9.0.1", "192.168.40.0/24"),
        ("10.8.0.1", "10.8.0.0/24"),
    ],
)
def test_invalid_route_never_runs_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    gateway: str,
    destination: str,
) -> None:
    """Allowing the server next hop retains pool and overlap validation."""
    control = configured_control(tmp_path)
    route = s.ManagedRoute(
        route_id="00000000-0000-4000-8000-000000000001",
        network=destination,
        gateway=gateway,
    )
    monkeypatch.setattr(
        bounded, "command", lambda *_: pytest.fail("invalid route changed")
    )
    try:
        result = control.execute(request(s.SetRoute(route=route, present=True))).result
        assert isinstance(result, s.MutationResult)
        assert result.state == "failed"
        assert result.failure == ErrorCode.INVALID_INPUT
        assert result.completed == ()
    finally:
        control.close()


def test_server_route_add_and_remove(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Honor the public server-route next hop through the real agent writer."""
    control = configured_control(tmp_path)
    route = s.ManagedRoute(
        route_id="00000000-0000-4000-8000-000000000001",
        network="192.168.40.0/24",
        gateway="10.8.0.1",
    )
    observed: list[dict[str, object]] = []
    commands: list[list[str]] = []
    monkeypatch.setattr(bounded, "observe", lambda *_: json.dumps(observed).encode())

    def execute(arguments: list[str], deadline: float) -> bytes:
        commands.append(arguments)
        assert arguments == [
            "/usr/sbin/ip",
            "-4",
            "route",
            "add" if not observed else "del",
            route.network,
            "via",
            route.gateway,
            "dev",
            "tun0",
            "proto",
            "201",
        ]
        if "add" in arguments:
            observed.append(
                {
                    "dst": route.network,
                    "gateway": route.gateway,
                    "dev": "tun0",
                    "protocol": 201,
                }
            )
        else:
            observed.clear()
        return b""

    monkeypatch.setattr(bounded, "command", execute)
    try:
        for generation, present in enumerate((True, False)):
            intent = request(s.SetRoute(route=route, present=present)).model_copy(
                update={"expected_generation": generation}
            )
            result = control.execute(intent).result
            assert isinstance(result, s.MutationResult)
            assert result.state == "succeeded"
            assert bool(observed) == present
        assert len(commands) == 2
    finally:
        control.close()


@pytest.fixture
def firewall(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Model an atomic filter-table restore while preserving foreign rules."""
    import shlex

    from sciaiot.rivet.vpn_agent import files

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
        declaration = ":FORWARD ACCEPT [0:0]\n"
        if chain:
            declaration += ":OVPNCP_FORWARD - [0:0]\n"
        return (
            "*filter\n"
            + declaration
            + "\n".join(shlex.join(rule) for rule in state)
            + "\nCOMMIT\n"
        ).encode()

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

    from sciaiot.rivet.vpn_agent import files, network

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


def test_access_accepts_are_limited_to_the_configured_tun(firewall) -> None:
    """Even a private-network grant must not bypass Docker bridge policy."""
    _, _, _, intent, _ = firewall
    inventory = network.Ownership(access=(intent,))
    accepts = [
        rule
        for rule in access_mutations.rules(inventory, "tun0")
        if rule[-1] == "ACCEPT"
    ]
    assert len(accepts) == 4
    for rule in accepts:
        assert rule[6:10] == ("-i", "tun0", "-o", "tun0")


DOCKER_FILTER = """*filter
:FORWARD DROP [0:0]
:DOCKER-USER - [0:0]
:DOCKER-FORWARD - [0:0]
:DOCKER-CT - [0:0]
:DOCKER-BRIDGE - [0:0]
:DOCKER - [0:0]
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-FORWARD
-A DOCKER-FORWARD -j DOCKER-CT
-A DOCKER-FORWARD -j DOCKER-BRIDGE
-A DOCKER-FORWARD -i docker0 -j ACCEPT
-A DOCKER-CT -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-BRIDGE -o docker0 -j DOCKER
-A DOCKER ! -i docker0 -o docker0 -j DROP
COMMIT
"""


def test_docker_policy_proof_accepts_only_disjoint_denials() -> None:
    """Docker's bridge-only DROP cannot affect a TUN-to-TUN grant."""
    access_mutations.prove_foreign_forward(DOCKER_FILTER, "tun0")


def test_access_observer_applies_docker_chain_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The production observation path accepts the proven Docker baseline."""
    control = configured_control(tmp_path)
    monkeypatch.setattr(bounded, "observe", lambda *_: DOCKER_FILTER.encode())
    observed = access_mutations.AccessMutations(
        control.settings, control.journal
    )._observe("tun0", 1)
    assert observed[0] is False
    assert observed[1] == ()
    assert len(observed[2]) == 2
    control.close()


def test_root_return_requires_accept_policy() -> None:
    """A root RETURN is harmless only with an ACCEPT fallthrough policy."""
    raw = DOCKER_FILTER.replace(":FORWARD DROP", ":FORWARD ACCEPT")
    raw = raw.replace(
        "-A FORWARD -j DOCKER-USER",
        "-A FORWARD -j RETURN\n-A FORWARD -j DOCKER-USER",
    )
    access_mutations.prove_foreign_forward(raw, "tun0")


@pytest.mark.parametrize(
    "extra",
    [
        "-A DOCKER-USER -i tun0 -j DROP",
        "-A DOCKER-USER -j REJECT",
        "-A DOCKER-USER -j MARK",
        "-A DOCKER-USER -g DOCKER-CT",
        "-A DOCKER-USER -j DOCKER-USER",
        "-A DOCKER-USER -m comment --comment '-o' -j DROP",
        "-A DOCKER-USER -o docker+ -j DROP",
        "-A DOCKER-USER ! -o docker0 -j DROP",
        "-A DOCKER-USER -o docker0 -o tun0 -j DROP",
        "-A DOCKER-USER -o docker0 -j DROP -j ACCEPT",
        "-A DOCKER-USER -o docker0 -j DROP !",
        "-A DOCKER-USER --mystery docker0 -j DROP",
    ],
)
def test_foreign_policy_proof_rejects_unsafe_or_ambiguous_rules(
    extra: str,
) -> None:
    """Foreign denial or ambiguous syntax cannot be bypassed by an allow."""
    raw = DOCKER_FILTER.replace("COMMIT", f"{extra}\nCOMMIT")
    with pytest.raises(ControlError):
        access_mutations.prove_foreign_forward(raw, "tun0")


def test_foreign_policy_proof_rejects_root_return_to_drop() -> None:
    """RETURN from built-in FORWARD reaches its DROP policy."""
    raw = DOCKER_FILTER.replace(
        "-A FORWARD -j DOCKER-USER",
        "-A FORWARD -j RETURN\n-A FORWARD -j DOCKER-USER",
    )
    with pytest.raises(ControlError):
        access_mutations.prove_foreign_forward(raw, "tun0")


def test_foreign_policy_proof_bounds_reachable_chain_depth() -> None:
    """A long acyclic chain graph cannot exhaust the agent stack."""
    declarations = "\n".join(f":N{i} - [0:0]" for i in range(18))
    jumps = "\n".join(f"-A N{i} -j N{i + 1}" for i in range(17))
    raw = (
        "*filter\n:FORWARD ACCEPT [0:0]\n"
        f"{declarations}\n-A FORWARD -j N0\n{jumps}\nCOMMIT\n"
    )
    with pytest.raises(ControlError):
        access_mutations.prove_foreign_forward(raw, "tun0")


@pytest.mark.parametrize(
    "raw",
    [
        ":FORWARD ACCEPT [0:0]\nCOMMIT\n",
        "*filter\n:FORWARD ACCEPT [0:0]\n",
        "*filter\n:FORWARD ACCEPT [0:0]\nCOMMIT\nCOMMIT\n",
        "*filter\n:FORWARD MAYBE [0:0]\nCOMMIT\n",
        "*filter\n:FORWARD ACCEPT [0:0]\n-P FORWARD ACCEPT\nCOMMIT\n",
    ],
)
def test_foreign_policy_proof_rejects_incomplete_observation(raw: str) -> None:
    """Truncated or unsupported filter snapshots are never trusted."""
    with pytest.raises(ControlError):
        access_mutations.prove_foreign_forward(raw, "tun0")


def test_foreign_policy_proof_bounds_reachable_chain_count() -> None:
    """A broad chain graph is bounded even when acyclic and shallow."""
    declarations = "\n".join(f":N{i} - [0:0]" for i in range(70))
    jumps = "\n".join(f"-A FORWARD -j N{i}" for i in range(70))
    raw = f"*filter\n:FORWARD ACCEPT [0:0]\n{declarations}\n{jumps}\nCOMMIT\n"
    with pytest.raises(ControlError):
        access_mutations.prove_foreign_forward(raw, "tun0")


def test_unqualified_owned_access_rule_is_not_adopted(firewall) -> None:
    """An old owned grant lacking interface selectors blocks later writes."""
    control, state, commands, intent, _ = firewall
    initial = control.execute(request(s.SetAccess(intent=intent, present=True))).result
    assert isinstance(initial, s.MutationResult) and initial.state == "succeeded"
    owned = next(
        rule for rule in state if rule[-1] == "ACCEPT" and rule[1] == "OVPNCP_FORWARD"
    )
    state.remove(owned)
    state.append(owned[:6] + owned[10:])
    count = len(commands)
    result = control.execute(
        request(s.SetAccess(intent=intent, present=False)).model_copy(
            update={"expected_generation": control.journal.generation}
        )
    ).result
    assert isinstance(result, s.MutationResult) and result.state == "failed"
    assert len(commands) == count
