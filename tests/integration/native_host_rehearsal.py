"""Opt-in native systemd rehearsal against a private copy of VPN state.

Run this with the installed agent virtual environment on an approved host.
It requires the reviewed numeric accounts and both virtual environments.
Stage, start, verify and cleanup are separate explicit commands. The source
tree is read-only; canonical native paths must be absent before staging.
"""

import argparse
import grp
import hashlib
import ipaddress
import json
import os
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from sciaiot.rivet import native_firewall
from sciaiot.rivet.application.vpn_control.errors import ControlError
from sciaiot.rivet.native_assets import export
from sciaiot.rivet.vpn_agent import access_mutations, bounded, network
from sciaiot.rivet.vpn_agent import files as agent_files

AGENT_UID = 65532
API_UID = 65531
OPENVPN_UID = 65530
RUNTIME_GID = 65532
CONTROL_GID = 65531
RUN_ID = re.compile(r"[a-f0-9]{12}\Z")
SOURCE_NAMES = ("vpn-pki", "vpn-ccd", "vpn-projection")
UNIT_NAMES = (
    "rivet-forward-policy.service",
    "rivet-openvpn.service",
    "rivet-agent.service",
    "rivet.service",
)
TENANT = "11111111-1111-4111-8111-111111111111"
API_APP = "22222222-2222-4222-8222-222222222222"
SPA_APP = "33333333-3333-4333-8333-333333333333"
SCOPE = f"api://{API_APP}/access_as_user"
CANARY_NAME = re.compile(r"native-[a-f0-9]{12}\Z")

API_STATE = Path("/opt/rivet")
AGENT_STATE = Path("/var/lib/ovpn-agent")
OPENVPN_STATE = Path("/var/lib/openvpn")
ETC = Path("/etc/rivet")
SYSTEMD = Path("/etc/systemd/system")
TMPFILES = Path("/etc/tmpfiles.d/rivet.conf")
FRONTEND = Path("/srv/rivet/frontend")
NGINX = Path("/etc/nginx/conf.d/rivet.conf")
API_VENV = Path("/usr/local/lib/rivet/api-venv")
AGENT_VENV = Path("/usr/local/lib/rivet/agent-venv")

AGENT_PROBE = """
import json
import sys
import uuid
from sciaiot.rivet.adapters.vpn.agent import AgentVpnControl
from sciaiot.rivet.application.vpn_control import schemas as s
control = AgentVpnControl('/run/ovpn-agent/agent.sock', peer_uid=65532)
health = control.execute(s.Request(request_id=str(uuid.uuid4()),
    command=s.Health())).result
sessions = control.execute(s.Request(request_id=str(uuid.uuid4()),
    command=s.ListSessions())).result
if not isinstance(health, s.HealthResult) or not isinstance(sessions,
    s.SessionsResult):
    raise SystemExit(1)
expected = sys.argv[1]
print(json.dumps({'ready': health.ready, 'sessions': len(sessions.items),
    'expected_session': not expected or any(item.client == expected
    for item in sessions.items)}))
"""

AGENT_MUTATE = """
import json
import sys
import time
import uuid
from sciaiot.rivet.adapters.vpn.agent import AgentVpnControl
from sciaiot.rivet.application.vpn_control import schemas as s, wire
control = AgentVpnControl('/run/ovpn-agent/agent.sock', peer_uid=65532)
action, name, address = sys.argv[1:]
if action == 'assign':
    command = s.SetAssignment(client=name, assignment=s.Assignment(address=address))
elif action == 'unassign':
    command = s.SetAssignment(client=name, assignment=None)
else:
    command = s.ChangeClient(client=name, action=action)
health = control.execute(s.Request(request_id=str(uuid.uuid4()),
    command=s.Health())).result
if not isinstance(health, s.HealthResult) or not health.ready:
    raise SystemExit(1)
request = s.Request(request_id=str(uuid.uuid4()),
    operation_id=str(uuid.uuid4()), expected_generation=health.generation,
    command=command)
response = control.execute(request)
deadline = time.monotonic() + 60
while isinstance(response.result, s.MutationResult) and response.result.state in (
    'pending', 'partial', 'unknown'):
    if time.monotonic() >= deadline:
        raise SystemExit(1)
    time.sleep(0.2)
    response = control.execute(s.Request(request_id=str(uuid.uuid4()),
        command=s.LookupOperation(operation_id=request.operation_id)))
wire.require_success(response)
print(json.dumps({'action': action, 'state': response.result.state,
    'generation': response.result.generation}))
"""


def _command(*args: str, timeout: int = 30) -> bytes:
    """Run a fixed deployment command without surfacing raw output."""
    result = subprocess.run(
        list(args), capture_output=True, check=False, timeout=timeout
    )
    if result.returncode != 0:
        raise RuntimeError(f"Native command failed: {Path(args[0]).name}.")
    return result.stdout


def _canonical(path: Path) -> None:
    """Reject symlinked or relative source/destination paths."""
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("Native rehearsal requires canonical absolute paths.")


def _tree(path: Path) -> None:
    """Require a regular, single-link state tree with no symlink entries."""
    _canonical(path)
    for root, folders, files in os.walk(path, followlinks=False):
        for name in [*folders, *files]:
            entry = Path(root) / name
            info = entry.lstat()
            if not (
                stat.S_ISDIR(info.st_mode)
                or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            ):
                raise ValueError("Private source contains an unsafe entry.")


def _accounts() -> None:
    """Require the exact dedicated account IDs used by the copied state."""
    for name, uid, gid in (
        ("ovpn-api", API_UID, CONTROL_GID),
        ("ovpn-agent", AGENT_UID, RUNTIME_GID),
        ("ovpn-openvpn", OPENVPN_UID, RUNTIME_GID),
    ):
        item = pwd.getpwnam(name)
        if item.pw_uid != uid or item.pw_gid != gid:
            raise ValueError("Native rehearsal account identity mismatch.")
    for name, gid in (
        ("ovpn-control", CONTROL_GID),
        ("ovpn-runtime", RUNTIME_GID),
    ):
        if grp.getgrnam(name).gr_gid != gid:
            raise ValueError("Native rehearsal group identity mismatch.")
    if "ovpn-agent" not in grp.getgrnam("ovpn-control").gr_mem:
        raise ValueError("Agent lacks the reviewed control group.")


def _chown_tree(path: Path, uid: int, gid: int) -> None:
    """Assign every copied entry to its native runtime owner."""
    for root, folders, files in os.walk(path):
        for name in [*folders, *files]:
            os.chown(Path(root) / name, uid, gid, follow_symlinks=False)
    os.chown(path, uid, gid, follow_symlinks=False)


def render_server_config(raw: str, bind_ip: str | None) -> str:
    """Point copied OpenVPN hooks at the installed native entry point."""
    old = "/usr/local/bin/rivet-vpn-event"
    new = str(AGENT_VENV / "bin/rivet-vpn-event")
    if raw.count(old) != 2 or raw.count("--agent-uid 65532") != 2:
        raise ValueError("Copied server configuration has unexpected hooks.")
    result = raw.replace(old, new)
    if bind_ip is not None:
        address = str(ipaddress.IPv4Address(bind_ip))
        result, count = re.subn(
            r'^(?:"local"|local) (?:"[^"\n]+"|\S+)$',
            f"local {address}",
            result,
            flags=re.MULTILINE,
        )
        if count != 1:
            raise ValueError("Expected one explicit OpenVPN bind address.")
    try:
        options = agent_files.directives(result.encode())
    except ControlError, UnicodeError, ValueError:
        raise ValueError("Copied server configuration is incompatible.") from None
    for name, arguments in (
        ("dev", ["tun0"]),
        ("user", ["ovpn-openvpn"]),
        ("group", ["ovpn-runtime"]),
        ("management", ["/run/openvpn/management.sock", "unix"]),
        ("client-config-dir", ["/var/lib/ovpn-agent/projection/ccd"]),
    ):
        if options.get(name) != [arguments]:
            raise ValueError("Copied server configuration is incompatible.")
    expected_hook = [
        new,
        "--socket",
        "/run/ovpn-events/events.sock",
        "--management-socket",
        "/run/openvpn/management.sock",
        "--agent-uid",
        "65532",
    ]
    for name in ("client-connect", "client-disconnect"):
        values = options.get(name)
        if values is None or len(values) != 1 or len(values[0]) != 1:
            raise ValueError("Copied server configuration has unexpected hooks.")
        if shlex.split(values[0][0]) != expected_hook:
            raise ValueError("Copied server configuration has unexpected hooks.")
    return result


def _owned_file(path: Path, data: bytes, uid: int, gid: int, mode: int) -> None:
    """Create a new file with exact ownership and mode."""
    with path.open("xb") as output:
        output.write(data)
    os.chown(path, uid, gid)
    path.chmod(mode)


def _stage_state(source: Path, bind_ip: str | None, run_id: str) -> None:
    """Copy only test-owned PKI/CCD/projection into canonical native paths."""
    AGENT_STATE.mkdir(mode=0o750)
    AGENT_STATE.chmod(0o750)
    _chown_tree(AGENT_STATE, AGENT_UID, RUNTIME_GID)
    os.chown(AGENT_STATE, AGENT_UID, RUNTIME_GID)
    for name, target in (
        ("vpn-pki", "pki"),
        ("vpn-ccd", "ccd"),
        ("vpn-projection", "projection"),
    ):
        shutil.copytree(source / name, AGENT_STATE / target)
        _chown_tree(AGENT_STATE / target, AGENT_UID, RUNTIME_GID)
    projection = AGENT_STATE / "projection"
    old_anchor = projection / ".ovpncp-journal-identity"
    if old_anchor.exists():
        old_anchor.unlink()
    for root, folders, _ in os.walk(projection):
        Path(root).chmod(0o750)
        for folder in folders:
            (Path(root) / folder).chmod(0o750)
    for root, _, files in os.walk(projection):
        for file in files:
            (Path(root) / file).chmod(0o640)
    for name in ("ca.crt", "server.crt", "server.key", "crl.pem"):
        path = projection / name
        if not path.is_file():
            raise ValueError("Copied projection is incomplete.")
        path.chmod(0o640)
    config = projection / "server.conf"
    rendered = render_server_config(config.read_text(), bind_ip)
    config.write_text(rendered)
    config.chmod(0o640)
    for name in ("config", "journal"):
        path = AGENT_STATE / name
        path.mkdir(mode=0o700)
        os.chown(path, AGENT_UID, RUNTIME_GID)
        path.chmod(0o700)
    _owned_file(
        AGENT_STATE / "config/ownership.json",
        b'{"version":"1.0","routes":[],"access":[],"pushes":[]}\n',
        AGENT_UID,
        RUNTIME_GID,
        0o600,
    )
    _owned_file(
        AGENT_STATE / ".native-rehearsal",
        run_id.encode(),
        AGENT_UID,
        RUNTIME_GID,
        0o600,
    )
    API_STATE.mkdir(mode=0o750)
    API_STATE.chmod(0o750)
    os.chown(API_STATE, API_UID, CONTROL_GID)
    (API_STATE / "certs").mkdir(mode=0o700)
    os.chown(API_STATE / "certs", API_UID, CONTROL_GID)
    _owned_file(
        API_STATE / ".native-rehearsal", run_id.encode(), API_UID, CONTROL_GID, 0o600
    )
    OPENVPN_STATE.mkdir(mode=0o770)
    OPENVPN_STATE.chmod(0o770)
    os.chown(OPENVPN_STATE, OPENVPN_UID, RUNTIME_GID)
    _owned_file(OPENVPN_STATE / "ipp.txt", b"", OPENVPN_UID, RUNTIME_GID, 0o660)
    _owned_file(
        OPENVPN_STATE / ".native-rehearsal",
        run_id.encode(),
        OPENVPN_UID,
        RUNTIME_GID,
        0o600,
    )


def _stage_config(assets: Path, run_id: str, ui_dist: Path) -> list[Path]:
    """Install the exported wheel templates and runtime UI configuration."""
    ETC.mkdir(mode=0o755)
    ETC.chmod(0o755)
    agent_env = (assets / "agent.env.example").read_text()
    agent_env = agent_env.replace("REPLACE_WITH_RUNTIME_GID", str(RUNTIME_GID))
    agent_env = agent_env.replace("REPLACE_WITH_OPENVPN_UID", str(OPENVPN_UID))
    agent_env = agent_env.replace("REPLACE_WITH_API_UID", str(API_UID))
    agent_env = agent_env.replace(
        "RIVET_AGENT_MUTATIONS=",
        "RIVET_AGENT_MUTATIONS=assignments,pki,events,management",
    )
    api_env = (assets / "api.env.example").read_text()
    api_env = api_env.replace("REPLACE_WITH_AGENT_UID", str(AGENT_UID))
    api_env = api_env.replace("REPLACE_WITH_TENANT_UUID", TENANT)
    api_env = api_env.replace("REPLACE_WITH_API_APP_UUID", API_APP)
    if "REPLACE_WITH_" in agent_env + api_env:
        raise ValueError("Native env template placeholders remain.")
    _owned_file(ETC / "agent.env", agent_env.encode(), 0, RUNTIME_GID, 0o640)
    _owned_file(ETC / "api.env", api_env.encode(), 0, 0, 0o600)
    installed = [ETC / "agent.env", ETC / "api.env"]
    for name in UNIT_NAMES:
        target = SYSTEMD / name
        _owned_file(target, (assets / name).read_bytes(), 0, 0, 0o644)
        installed.append(target)
    _owned_file(TMPFILES, (assets / "rivet.conf").read_bytes(), 0, 0, 0o644)
    installed.append(TMPFILES)
    public_parent = FRONTEND.parent
    if public_parent.exists():
        if stat.S_IMODE(public_parent.stat().st_mode) & 0o005 != 0o005:
            raise ValueError("Frontend parent is not traversable by Nginx.")
    else:
        public_parent.mkdir(parents=True, mode=0o755)
        public_parent.chmod(0o755)
    release = FRONTEND / "releases" / f"native-{run_id}"
    release.parent.mkdir(parents=True, mode=0o755)
    FRONTEND.chmod(0o755)
    release.parent.chmod(0o755)
    shutil.copytree(ui_dist, release)
    for root, folders, files in os.walk(release):
        Path(root).chmod(0o755)
        for folder in folders:
            (Path(root) / folder).chmod(0o755)
        for file in files:
            (Path(root) / file).chmod(0o644)
    current = FRONTEND / "current"
    current.symlink_to(release)
    public_env = os.environ.copy()
    public_env.update(
        RIVET_UI_ENTRA_TENANT_ID=TENANT,
        RIVET_UI_ENTRA_CLIENT_ID=SPA_APP,
        RIVET_UI_ENTRA_API_SCOPE=SCOPE,
    )
    result = subprocess.run(
        [str(assets / "web-config.sh")],
        env=public_env,
        capture_output=True,
        check=False,
        timeout=5,
    )
    if result.returncode != 0:
        raise ValueError("Wheel UI config renderer rejected public settings.")
    _owned_file(FRONTEND / "runtime-config.js", result.stdout, 0, 0, 0o644)
    nginx = (
        (assets / "nginx.conf.template")
        .read_text()
        .replace("${RIVET_FRONTEND_ROOT}", str(current))
    )
    if "${" in nginx:
        raise ValueError("Nginx template still has placeholders.")
    _owned_file(NGINX, nginx.encode(), 0, 0, 0o644)
    installed.append(NGINX)
    return installed


def stage(source: Path, ui_dist: Path, run_root: Path, bind_ip: str | None) -> None:
    """Stage a copy only after collision, identity and source checks pass."""
    _canonical(run_root)
    _canonical(source)
    _tree(source)
    _tree(ui_dist)
    if not ui_dist.is_dir() or not (ui_dist / "index.html").is_file():
        raise ValueError("Frontend distribution is incomplete.")
    if source.stat().st_uid != 0 or stat.S_IMODE(source.stat().st_mode) != 0o700:
        raise ValueError("Frozen source copy must be private mode 0700.")
    run_id = run_root.name
    if RUN_ID.fullmatch(run_id) is None:
        raise ValueError("Use a 12-character lowercase hex run ID.")
    _accounts()
    for name in SOURCE_NAMES:
        if not (source / name).is_dir():
            raise ValueError("Frozen source copy lacks VPN state.")
    for target in (
        API_STATE,
        AGENT_STATE,
        OPENVPN_STATE,
        ETC,
        FRONTEND,
        NGINX,
        TMPFILES,
        run_root,
        *(SYSTEMD / name for name in UNIT_NAMES),
    ):
        _canonical(target)
        if target.exists() or target.is_symlink():
            raise FileExistsError("Canonical native test path already exists.")
    for venv in (API_VENV, AGENT_VENV):
        if not (venv / "bin/python").is_file():
            raise ValueError("Native wheel virtual environments are not ready.")
    for unit in (*UNIT_NAMES, "nginx.service"):
        active = subprocess.run(
            ["/usr/bin/systemctl", "is-active", "--quiet", unit],
            capture_output=True,
            check=False,
            timeout=5,
        )
        if active.returncode == 0:
            raise ValueError("Native rehearsal requires inactive host services.")
    run_root.mkdir(mode=0o700)
    assets = run_root / "assets"
    export(assets)
    _stage_state(source, bind_ip, run_id)
    installed = _stage_config(assets, run_id, ui_dist)
    manifest = {
        "run_id": run_id,
        "installed": {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in installed
        },
    }
    _owned_file(run_root / "manifest.json", json.dumps(manifest).encode(), 0, 0, 0o600)
    _command("/usr/bin/systemd-tmpfiles", "--create", str(TMPFILES))
    _command("/usr/bin/systemctl", "daemon-reload")
    _command("/usr/sbin/nginx", "-t")


def _manifest(run_root: Path) -> dict[str, object]:
    """Require the exact private test marker before start or cleanup."""
    _canonical(run_root)
    run_id = run_root.name
    if RUN_ID.fullmatch(run_id) is None:
        raise ValueError("Invalid native rehearsal run ID.")
    marker = run_root / "manifest.json"
    info = marker.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ValueError("Native rehearsal marker is untrusted.")
    result = json.loads(marker.read_text())
    if not isinstance(result, dict) or result.get("run_id") != run_id:
        raise ValueError("Native rehearsal marker does not match run ID.")
    return result


def start(run_root: Path) -> None:
    """Start only the staged native units in dependency order."""
    _manifest(run_root)
    for name in ("rivet-openvpn", "rivet-agent", "rivet", "nginx"):
        _command("/usr/bin/systemctl", "start", name, timeout=90)


def _http(path: str, expected: int) -> tuple[bytes, dict[str, str]]:
    """Read a bounded local HTTP response without exposing body on failure."""
    port = 8000 if path == "/me" else 80
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    try:
        response = urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(65537)
        if response.status != expected or len(body) > 65536:
            raise RuntimeError("Native HTTP boundary returned unexpected status.")
        return body, dict(response.headers)


def _header(headers: dict[str, str], name: str) -> str:
    """Read an HTTP field name without relying on header capitalization."""
    return next(
        (value for key, value in headers.items() if key.casefold() == name.casefold()),
        "",
    )


def verify(run_root: Path, client: str = "") -> dict[str, object]:
    """Verify native process, socket, firewall, API and UI boundaries."""
    _manifest(run_root)
    for name in ("rivet-openvpn", "rivet-agent", "rivet", "nginx"):
        _command("/usr/bin/systemctl", "is-active", "--quiet", name)
    for name, uid, cap in (
        ("rivet", API_UID, 0),
        ("rivet-agent", AGENT_UID, 1 << 12),
        ("rivet-openvpn", OPENVPN_UID, None),
    ):
        pid = int(_command("/usr/bin/systemctl", "show", "-P", "MainPID", name))
        if pid <= 1 or Path(f"/proc/{pid}").stat().st_uid != uid:
            raise RuntimeError("Native process identity differs from unit contract.")
        status = dict(
            line.split(":", 1)
            for line in Path(f"/proc/{pid}/status").read_text().splitlines()
            if ":" in line
        )
        if status.get("NoNewPrivs", "").strip() != "1":
            raise RuntimeError("Native process privilege grant is unexpected.")
        if cap is not None and int(status["CapEff"].strip(), 16) != cap:
            raise RuntimeError("Native process capabilities differ from unit contract.")
    for path, uid, gid, mode in (
        (Path("/run/ovpn-agent"), AGENT_UID, CONTROL_GID, 0o2750),
        (Path("/run/ovpn-agent/agent.sock"), AGENT_UID, CONTROL_GID, 0o660),
        (Path("/run/ovpn-events"), AGENT_UID, RUNTIME_GID, 0o2770),
    ):
        info = path.lstat()
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, mode):
            raise RuntimeError("Native socket ownership differs from contract.")
    if not stat.S_ISSOCK(Path("/run/openvpn/management.sock").lstat().st_mode):
        raise RuntimeError("OpenVPN management listener is absent.")
    probe = _command(
        "/usr/sbin/runuser",
        "-u",
        "ovpn-api",
        "--",
        str(API_VENV / "bin/python"),
        "-I",
        "-c",
        AGENT_PROBE,
        client,
    )
    agent = json.loads(probe)
    if agent.get("ready") is not True or agent.get("expected_session") is not True:
        raise RuntimeError("Native agent health or live session is unavailable.")
    inventory = network.Ownership.model_validate_json(
        (AGENT_STATE / "config/ownership.json").read_bytes()
    )
    snapshot = bounded.observe("rules", "tun0", time.monotonic() + 10).decode()
    if native_firewall.plan(snapshot, inventory, "tun0") is not None:
        raise RuntimeError("Native owned firewall baseline is absent.")
    _, direct = _http("/me", 401)
    if "application/problem+json" not in _header(direct, "Content-Type"):
        raise RuntimeError("Native API authentication did not fail closed.")
    _, proxied = _http("/api/me", 401)
    if "application/problem+json" not in _header(proxied, "Content-Type"):
        raise RuntimeError("Nginx API proxy did not preserve denial.")
    html, _ = _http("/", 200)
    config, headers = _http("/runtime-config.js", 200)
    if b"/assets/" not in html or b"window.__RIVET_CONFIG__" not in config:
        raise RuntimeError("Native UI artifact or runtime config is missing.")
    if "no-store" not in _header(headers, "Cache-Control"):
        raise RuntimeError("Native UI runtime config is cacheable.")
    return {
        "native_services": "active",
        "agent_ready": True,
        "live_sessions": agent["sessions"],
        "expected_session": agent["expected_session"],
        "api_authentication": "denied",
        "ui": "served",
        "owned_firewall": "verified",
    }


def mutate(
    run_root: Path, action: str, name: str, address: str = ""
) -> dict[str, object]:
    """Exercise a single canary lifecycle mutation through the API socket role."""
    _manifest(run_root)
    if CANARY_NAME.fullmatch(name) is None or name != f"native-{run_root.name}":
        raise ValueError("Canary client must match this private run ID.")
    if action not in {"issue", "assign", "unassign", "revoke"}:
        raise ValueError("Unsupported canary action.")
    if action == "assign":
        address = str(ipaddress.IPv4Address(address))
    elif address:
        raise ValueError("Only assignment accepts an address.")
    result = _command(
        "/usr/sbin/runuser",
        "-u",
        "ovpn-api",
        "--",
        str(API_VENV / "bin/python"),
        "-I",
        "-c",
        AGENT_MUTATE,
        action,
        name,
        address,
        timeout=90,
    )
    record = json.loads(result)
    if record.get("action") != action or record.get("state") != "succeeded":
        raise RuntimeError("Native canary mutation did not succeed.")
    return {"canary_action": action, "result": "succeeded"}


def cleanup(run_root: Path) -> None:
    """Stop native units and remove only marker-owned test files and state."""
    manifest = _manifest(run_root)
    for name in ("nginx", "rivet", "rivet-agent", "rivet-openvpn"):
        _command("/usr/bin/systemctl", "stop", name, timeout=90)
    for root in (API_STATE, AGENT_STATE, OPENVPN_STATE):
        if (root / ".native-rehearsal").read_text() != run_root.name:
            raise ValueError("Native test state marker differs from run ID.")
    inventory = network.Ownership.model_validate_json(
        (AGENT_STATE / "config/ownership.json").read_bytes()
    )
    if inventory.routes or inventory.access or inventory.pushes:
        raise ValueError("Owned intents remain; reconcile before cleanup.")
    snapshot = bounded.observe("rules", "tun0", time.monotonic() + 10).decode()
    if f":{access_mutations.CHAIN} " in snapshot:
        if native_firewall.plan(snapshot, inventory, "tun0") is not None:
            raise ValueError("Owned firewall is not exact; retain for review.")
        expected = access_mutations.rules(inventory, "tun0")
        lines = ["*filter"]
        for anchor in expected[:2]:
            lines.append(shlex.join(("-D", *anchor[1:])))
        lines.extend(
            (
                f"-F {access_mutations.CHAIN}",
                f"-X {access_mutations.CHAIN}",
                "COMMIT",
                "",
            )
        )
        bounded.command(
            ["/usr/sbin/iptables-nft-restore", "--noflush", "--wait", "5"],
            time.monotonic() + 10,
            "\n".join(lines).encode(),
        )
    installed = manifest.get("installed")
    if not isinstance(installed, dict):
        raise TypeError("Native installed-file manifest is invalid.")
    for name, digest in installed.items():
        path = Path(name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("Installed native template changed; retain for review.")
    for name in installed:
        Path(name).unlink()
    for root in (API_STATE, AGENT_STATE, OPENVPN_STATE, ETC, FRONTEND):
        shutil.rmtree(root)
    _command("/usr/bin/systemctl", "daemon-reload")
    shutil.rmtree(run_root)


def main() -> None:
    """Run one explicit native host rehearsal stage with redacted output."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    stage_command = commands.add_parser("stage")
    stage_command.add_argument("--source", type=Path, required=True)
    stage_command.add_argument("--ui-dist", type=Path, required=True)
    stage_command.add_argument("--run-root", type=Path, required=True)
    stage_command.add_argument("--bind-ip")
    for name in ("start", "verify", "cleanup", "mutate"):
        selected = commands.add_parser(name)
        selected.add_argument("--run-root", type=Path, required=True)
        if name == "verify":
            selected.add_argument("--client", default="")
        elif name == "mutate":
            selected.add_argument(
                "--action",
                choices=("issue", "assign", "unassign", "revoke"),
                required=True,
            )
            selected.add_argument("--client", required=True)
            selected.add_argument("--address", default="")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Native rehearsal requires an approved root host.")
    try:
        if args.command == "stage":
            stage(args.source, args.ui_dist, args.run_root, args.bind_ip)
            result = {"native_rehearsal": "staged", "run_id": args.run_root.name}
        elif args.command == "start":
            start(args.run_root)
            result = {"native_rehearsal": "started", "run_id": args.run_root.name}
        elif args.command == "verify":
            result = verify(args.run_root, args.client)
        elif args.command == "mutate":
            result = mutate(args.run_root, args.action, args.client, args.address)
        else:
            cleanup(args.run_root)
            result = {"native_rehearsal": "cleaned", "run_id": args.run_root.name}
        print(json.dumps(result, sort_keys=True))
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        RuntimeError,
        subprocess.TimeoutExpired,
    ):
        print(
            f"Native rehearsal {args.command} failed; retain run ID and review "
            "private host evidence.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
