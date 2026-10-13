"""Privilege bootstrap fails closed and drops root before executing code."""

import importlib.util
from pathlib import Path
from typing import Any

import pytest


def _module() -> Any:
    path = Path(__file__).resolve().parents[1] / "deploy/containers/agent_bootstrap.py"
    spec = importlib.util.spec_from_file_location("agent_bootstrap", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("health", [False, True])
def test_bootstrap_drops_identity_before_ambient_and_exec(monkeypatch, health) -> None:
    """Only NET_ADMIN survives the identity drop and reaches the daemon."""
    module = _module()
    calls = []
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module, "_prctl", lambda *args: calls.append(args))
    monkeypatch.setattr(module, "_net_admin_only", lambda: calls.append("caps"))
    monkeypatch.setattr(module, "_verify", lambda: calls.append("verify"))
    monkeypatch.setattr(module.os, "setgroups", lambda value: calls.append(value))
    monkeypatch.setattr(module.os, "setresgid", lambda *args: calls.append(args))
    monkeypatch.setattr(module.os, "setresuid", lambda *args: calls.append(args))
    monkeypatch.setattr(module.os, "execv", lambda *args: calls.append(args))
    module.bootstrap(health=health)
    assert calls == [
        (38, 1, 0, 0, 0),
        (8, 1, 0, 0, 0),
        [65531],
        (65532, 65532, 65532),
        (65532, 65532, 65532),
        "caps",
        (8, 0, 0, 0, 0),
        (47, 2, 12, 0, 0),
        "verify",
        (
            module.sys.executable,
            [module.sys.executable, "/opt/agent/agent_health.py"]
            if health
            else [module.sys.executable, "-m", "sciaiot.rivet.vpn_agent.cli"],
        ),
    ]


def test_non_root_bootstrap_is_rejected(monkeypatch) -> None:
    """Missing bootstrap privileges cannot silently launch a broken agent."""
    module = _module()
    monkeypatch.setattr(module.os, "geteuid", lambda: 65532)
    with pytest.raises(RuntimeError):
        module.bootstrap()


def test_main_redacts_bootstrap_failure(monkeypatch, capsys) -> None:
    """No low-level error or execution follows a failed privilege transition."""
    module = _module()

    def fail() -> None:
        raise OSError("sensitive detail")

    monkeypatch.setattr(module.sys, "argv", ["agent_bootstrap.py"])
    monkeypatch.setattr(module, "bootstrap", fail)
    with pytest.raises(SystemExit) as failure:
        module.main()
    assert failure.value.code == 1
    assert "sensitive" not in capsys.readouterr().err


@pytest.mark.parametrize(
    "field",
    [
        None,
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapAmb",
        "NoNewPrivs",
        "uid",
        "gid",
        "groups",
    ],
)
def test_runtime_identity_verification(monkeypatch, field) -> None:
    """Missing caps, retained root, or disabled NNP cannot reach application code."""
    module = _module()
    status = {key: "1000" for key in ("CapInh", "CapPrm", "CapEff", "CapAmb")}
    status["NoNewPrivs"] = "1"
    if field in status:
        status[field] = "0"
    monkeypatch.setattr(
        module.Path,
        "read_text",
        lambda self: "\n".join(f"{k}: {v}" for k, v in status.items()),
    )
    monkeypatch.setattr(
        module.os,
        "getresuid",
        lambda: (0, 65532, 0) if field == "uid" else (65532,) * 3,
    )
    monkeypatch.setattr(
        module.os,
        "getresgid",
        lambda: (0, 65532, 0) if field == "gid" else (65532,) * 3,
    )
    monkeypatch.setattr(
        module.os, "getgroups", lambda: [0, 65531] if field == "groups" else [65531]
    )
    if field is None:
        module._verify()
    else:
        with pytest.raises(RuntimeError):
            module._verify()


@pytest.mark.parametrize("result", [0, -1])
def test_kernel_capability_calls(monkeypatch, result) -> None:
    """The ABI assigns NET_ADMIN alone to all three sets and checks errors."""
    from unittest.mock import Mock

    module = _module()
    libc = Mock()
    libc.prctl.return_value = result
    libc.capset.return_value = result
    monkeypatch.setattr(module.ctypes, "CDLL", lambda *args, **kwargs: libc)
    if result:
        with pytest.raises(OSError):
            module._prctl(38, 1, 0, 0, 0)
        with pytest.raises(OSError):
            module._net_admin_only()
    else:
        module._prctl(38, 1, 0, 0, 0)
        module._net_admin_only()
    header, data = libc.capset.call_args.args
    assert header._obj.version == 0x20080522
    assert header._obj.pid == 0
    assert (data[0].effective, data[0].permitted, data[0].inheritable) == (4096,) * 3
    assert (data[1].effective, data[1].permitted, data[1].inheritable) == (0,) * 3


def test_healthcheck_drops_privileges_too(monkeypatch) -> None:
    """Docker health checks must pass through the same identity transition."""
    from unittest.mock import Mock

    module = _module()
    launch = Mock()
    monkeypatch.setattr(module, "bootstrap", launch)
    monkeypatch.setattr(module.sys, "argv", ["agent_bootstrap.py", "--health"])
    module.main()
    launch.assert_called_once_with(health=True)


def test_unknown_target_is_rejected(monkeypatch) -> None:
    """Bootstrap cannot launch an operator-provided command while privileged."""
    from unittest.mock import Mock

    module = _module()
    launch = Mock()
    monkeypatch.setattr(module, "bootstrap", launch)
    monkeypatch.setattr(module.sys, "argv", ["agent_bootstrap.py", "arbitrary"])
    with pytest.raises(SystemExit):
        module.main()
    launch.assert_not_called()
