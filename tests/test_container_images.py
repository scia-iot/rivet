"""Static release boundary checks independent of a Docker daemon."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize("component", ["openvpn", "agent", "api", "nginx"])
def test_base_images_are_immutable(component: str) -> None:
    """Every external build stage is digest pinned."""
    content = (ROOT / "deploy" / component / "Dockerfile").read_text()
    for base in re.findall(r"^FROM (\S+)", content, re.MULTILINE):
        assert re.fullmatch(r".+@sha256:[0-9a-f]{64}", base)
    assert "HEALTHCHECK" in content
    assert "USER " in content


def test_context_is_an_allowlist_with_secret_overrides() -> None:
    """Unknown state and local credentials never enter the builder context."""
    content = (ROOT / ".dockerignore").read_text().splitlines()
    assert content[0] == "**"
    assert "**/.env*" in content
    assert "**/*.key" in content
    assert "**/node_modules" in content
    assert "!frontend/src/**" in content
    assert "!frontend/**" not in content


@pytest.mark.parametrize("name", ["api", "agent"])
def test_python_locks_are_exact_and_hashed(name: str) -> None:
    """Runtime installation rejects mutable versions and unverified files."""
    content = (ROOT / "deploy/locks" / f"{name}.txt").read_text()
    requirements = content.replace("\\\n", "").splitlines()
    assert requirements
    for line in requirements:
        if line.startswith("#") or not line.strip():
            continue
        assert re.match(r"[\w.-]+==[\w.]+\s+--hash=sha256:[0-9a-f]{64}", line)


def _entrypoint(name: str):
    import runpy

    return runpy.run_path(str(ROOT / "deploy/containers" / f"{name}.py"))


def test_secret_reader_rejects_unsafe_files(tmp_path: Path) -> None:
    reader = _entrypoint("api_entrypoint")["load_secret"]
    secret = tmp_path / "secret"
    secret.write_text("private-value\n")
    secret.chmod(0o600)
    assert reader(secret) == "private-value"
    secret.chmod(0o644)
    with pytest.raises(ValueError):
        reader(secret)
    secret.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(secret)
    with pytest.raises(OSError):
        reader(link)
    secret.write_text("x" * 16385)
    with pytest.raises(ValueError):
        reader(secret)
    secret.write_text("a\nb")
    with pytest.raises(ValueError):
        reader(secret)


def test_api_startup_requires_authentication_and_agent(monkeypatch) -> None:
    configure = _entrypoint("api_entrypoint")["configure"]
    monkeypatch.setenv("RIVET_VPN_BACKEND", "host")
    with pytest.raises(ValueError):
        configure()
    monkeypatch.setenv("RIVET_VPN_BACKEND", "agent")
    for name in (
        "AZURE_ENTRAID_TENANT_ID",
        "AZURE_ENTRAID_APP_CLIENT_ID",
        "AZURE_ENTRAID_USER_ROLE",
        "AZURE_ENTRAID_ADMIN_ROLE",
        "AZURE_ENTRAID_SERVICE_ADMIN_ROLE",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError):
        configure()
    for name in (
        "AZURE_ENTRAID_TENANT_ID",
        "AZURE_ENTRAID_APP_CLIENT_ID",
        "AZURE_ENTRAID_USER_ROLE",
        "AZURE_ENTRAID_ADMIN_ROLE",
        "AZURE_ENTRAID_SERVICE_ADMIN_ROLE",
    ):
        monkeypatch.setenv(name, "configured")
    monkeypatch.setenv("RIVET_PROXY_IP", "172.30.250.2")
    assert configure() == "172.30.250.2"
    monkeypatch.setenv("RIVET_PROXY_IP", "*")
    with pytest.raises(ValueError):
        configure()
    monkeypatch.setenv("RIVET_PROXY_IP", "172.30.250.2")
    monkeypatch.setenv("AZURE_STORAGE_CONNECTION_STRING_FILE", "/tmp/secret")
    with pytest.raises(ValueError):
        configure()


def test_openvpn_preflight_checks_owner_mode_and_type(monkeypatch) -> None:
    import stat
    from types import SimpleNamespace

    validate = _entrypoint("openvpn_entrypoint")["validate"]
    metadata = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o660,
        st_uid=65530,
        st_gid=65532,
        st_nlink=1,
    )
    monkeypatch.setattr(Path, "lstat", lambda _: metadata)
    validate(Path("/runtime"), directory=False, mode=0o660)
    metadata.st_uid = 0
    with pytest.raises(ValueError):
        validate(Path("/runtime"), directory=False, mode=0o660)
    metadata.st_uid = 65530
    metadata.st_mode = stat.S_IFLNK | 0o660
    with pytest.raises(ValueError):
        validate(Path("/runtime"), directory=False, mode=0o660)
    metadata.st_mode = stat.S_IFREG | 0o600
    with pytest.raises(ValueError):
        validate(Path("/runtime"), directory=False, mode=0o660)


@pytest.mark.parametrize("ready", [True, False])
def test_agent_probe_requires_ready(monkeypatch, ready: bool) -> None:
    from types import SimpleNamespace

    from sciaiot.rivet.application.vpn_control import schemas

    module = _entrypoint("agent_health")
    monkeypatch.setattr(module["Settings"], "from_environment", lambda: None)
    result = schemas.HealthResult(ready=ready, generation=1)
    monkeypatch.setattr(
        module["ReadOnlyVpnControl"],
        "execute",
        lambda *_: SimpleNamespace(result=result),
    )
    if ready:
        module["main"]()
    else:
        with pytest.raises(SystemExit) as error:
            module["main"]()
        assert error.value.code == 1


@pytest.mark.parametrize("status", [200, 401, 403, 500])
def test_api_probe_requires_an_authentication_denial(monkeypatch, status: int) -> None:
    from unittest.mock import Mock

    module = _entrypoint("api_health")
    connection = Mock()
    connection.getresponse.return_value.status = status
    monkeypatch.setattr(
        module["http"].client, "HTTPConnection", lambda *_, **__: connection
    )
    if status in (401, 403):
        module["main"]()
    else:
        with pytest.raises(SystemExit):
            module["main"]()
    connection.close.assert_called_once()


def test_openvpn_probe_requires_daemon_and_management_socket(monkeypatch) -> None:
    import stat
    from types import SimpleNamespace

    module = _entrypoint("openvpn_health")
    monkeypatch.setattr(Path, "read_text", lambda _: "openvpn\n")
    monkeypatch.setattr(
        Path, "lstat", lambda _: SimpleNamespace(st_mode=stat.S_IFSOCK | 0o777)
    )
    module["main"]()
    monkeypatch.setattr(Path, "read_text", lambda _: "python\n")
    with pytest.raises(SystemExit):
        module["main"]()
    monkeypatch.setattr(Path, "read_text", lambda _: "openvpn\n")
    monkeypatch.setattr(
        Path, "lstat", lambda _: SimpleNamespace(st_mode=stat.S_IFREG | 0o777)
    )
    with pytest.raises(SystemExit):
        module["main"]()


def test_event_hook_imports_with_an_empty_environment(tmp_path: Path) -> None:
    """OpenVPN-sanitized hooks establish their own trusted import path."""
    import shutil
    import subprocess
    import sys

    import cryptography
    import pydantic

    staged = tmp_path / "image"
    for line in (ROOT / "deploy/openvpn/Dockerfile").read_text().splitlines():
        if not line.startswith("COPY src/"):
            continue
        _, source, destination = line.split()
        target = staged / Path(destination).relative_to("/opt/agent")
        target.parent.mkdir(parents=True, exist_ok=True)
        original = ROOT / source
        if original.is_dir():
            shutil.copytree(original, target)
        else:
            shutil.copyfile(original, target)
    hook = (ROOT / "deploy/containers/vpn_event.sh").read_text()
    assert "export PYTHONPATH=/opt/agent" in hook
    assert "exec /usr/local/bin/python " in hook
    # Relocate only the immutable image prefix/interpreter for a host test.
    paths = ":".join(
        [
            str(staged),
            str(Path(pydantic.__file__).parents[1]),
            str(Path(cryptography.__file__).parents[1]),
        ]
    )
    hook = hook.replace("/opt/agent", paths).replace(
        "/usr/local/bin/python", sys.executable
    )
    launcher = tmp_path / "hook.sh"
    launcher.write_text(hook)
    result = subprocess.run(
        ["/bin/sh", str(launcher), "--help"],
        env={},
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    assert "--management-socket" in result.stdout


def test_openvpn_startup_validates_before_exec(monkeypatch) -> None:
    from unittest.mock import Mock

    module = _entrypoint("openvpn_entrypoint")
    main = module["main"]
    validate = Mock()
    monkeypatch.setitem(main.__globals__, "validate", validate)
    execute = Mock()
    monkeypatch.setattr(module["os"], "execv", execute)
    monkeypatch.setattr(module["os"], "umask", Mock())
    main()
    assert validate.call_count == 4
    execute.assert_called_once_with(
        "/usr/local/sbin/openvpn",
        ["openvpn", "--config", "/var/lib/ovpn-agent/projection/server.conf"],
    )
    execute.reset_mock()
    validate.side_effect = ValueError("private filesystem details")
    with pytest.raises(SystemExit) as error:
        main()
    assert "private filesystem" not in str(error.value)
    execute.assert_not_called()


def test_api_startup_validates_before_importing_application(monkeypatch) -> None:
    from unittest.mock import Mock

    module = _entrypoint("api_entrypoint")
    main = module["main"]
    configure = Mock(return_value="172.30.250.2")
    monkeypatch.setitem(main.__globals__, "configure", configure)
    run = Mock()
    monkeypatch.setattr(module["uvicorn"], "run", run)
    main()
    assert run.call_args.args == ("sciaiot.rivet.main:app",)
    assert run.call_args.kwargs["forwarded_allow_ips"] == "172.30.250.2"
    assert run.call_args.kwargs["access_log"] is False
    run.reset_mock()
    configure.side_effect = ValueError("private credential")
    with pytest.raises(SystemExit) as error:
        main()
    assert "private credential" not in str(error.value)
    run.assert_not_called()


def test_agent_health_redacts_configuration_failure(monkeypatch) -> None:
    from unittest.mock import Mock

    module = _entrypoint("agent_health")
    monkeypatch.setattr(
        module["Settings"],
        "from_environment",
        Mock(side_effect=ValueError("private configuration")),
    )
    with pytest.raises(SystemExit) as error:
        module["main"]()
    assert error.value.code == 1


def test_api_health_handles_connection_failure(monkeypatch) -> None:
    from unittest.mock import Mock

    module = _entrypoint("api_health")
    connection = Mock()
    connection.request.side_effect = OSError("unavailable")
    monkeypatch.setattr(
        module["http"].client, "HTTPConnection", lambda *_, **__: connection
    )
    with pytest.raises(SystemExit) as error:
        module["main"]()
    assert error.value.code == 1
    connection.close.assert_called_once()


def test_nginx_container_preserves_proxy_and_spa_boundaries() -> None:
    """Proxy headers cannot inherit client spoofing or route API into the SPA."""
    config = (ROOT / "deploy/nginx/container.conf").read_text()
    assert "server api:8000;" in config
    assert "listen 8080 default_server;" in config
    assert "pid /tmp/nginx.pid;" in config
    assert "root /usr/share/nginx/html;" in config
    assert "$proxy_add_x_forwarded_for" not in config
    assert "location ^~ /api/" in config
    assert "location = /api" in config
    assert config.count("proxy_set_header X-Forwarded-For $remote_addr;") == 2
    assert config.count("proxy_set_header X-Forwarded-Proto https;") == 2
    assert config.count("proxy_pass http://rivet_api/;") == 2
    assert "location / {\n        try_files $uri /index.html;" in config
    assert "access_log off;" in config
    assert "error_log /dev/null crit;" in config


@pytest.mark.parametrize("component", ["openvpn", "agent", "api"])
def test_python_runtime_removes_unused_installer_payload(component: str) -> None:
    """Final images cannot retain pip's vendored libraries or bootstrap wheel."""
    content = (ROOT / "deploy" / component / "Dockerfile").read_text()
    runtime = content.rsplit("\nFROM ", 1)[1]
    uninstall = "python -m pip uninstall --yes pip"
    assert uninstall in runtime
    assert "rm -rf /usr/local/lib/python3.14/ensurepip" in runtime
    assert runtime.index(uninstall) > runtime.index(
        "pip install" if component == "openvpn" else "COPY --from=dependencies"
    )
    assert runtime.index(uninstall) < runtime.index("USER ")
    assert "find_spec" in runtime


def test_web_runtime_removes_unused_xml_modules() -> None:
    """Remove only the reviewed XML dependency closure, retaining HTTP tools."""
    content = (ROOT / "deploy/nginx/Dockerfile").read_text()
    runtime = content.rsplit("\nFROM ", 1)[1]
    purge = (
        "apt-get purge --yes --no-download "
        "libxml2 libxslt1.1 nginx-module-njs nginx-module-xslt"
    )
    assert purge in runtime
    assert "autoremove" not in runtime
    assert runtime.index(purge) < runtime.index("USER 101:101")
    assert "${db:Status-Status}" in runtime
    assert "find /usr/lib -name 'libxml2.so*'" in runtime
    assert "nginx -v" in runtime
    assert "curl --version" in runtime
    config = (ROOT / "deploy/nginx/container.conf").read_text()
    assert "load_module" not in config
    assert "xslt_" not in config
    assert "js_import" not in config


@pytest.mark.parametrize(
    ("status", "library", "expected"),
    [
        ("not-installed", "", 0),
        ("", "", 0),
        ("installed", "", 1),
        ("config-files", "", 1),
        ("half-installed", "", 1),
        ("not-installed", "/usr/lib/arch/libxml2.so.2", 1),
    ],
)
def test_web_xml_removal_checks_payload_not_dpkg_metadata(
    tmp_path: Path, status: str, library: str, expected: int
) -> None:
    """Run the real build guard with harmless package-manager/tool stubs."""
    import os
    import subprocess

    content = (ROOT / "deploy/nginx/Dockerfile").read_text()
    instruction = content.split("RUN apt-get purge", 1)[1].split("\nCOPY ", 1)[0]
    command = "apt-get purge " + instruction.replace("\\\n", " ").strip()
    package_manager = tmp_path / "apt-get"
    package_manager.write_text(
        "#!/bin/sh\n"
        '[ "$#" -eq 7 ] && [ "$1" = purge ] && [ "$2" = --yes ] '
        '&& [ "$3" = --no-download ] && [ "$4" = libxml2 ] '
        '&& [ "$5" = libxslt1.1 ] && [ "$6" = nginx-module-njs ] '
        '&& [ "$7" = nginx-module-xslt ] || exit 100\n'
    )
    package_manager.chmod(0o755)
    for executable in ("nginx", "curl"):
        path = tmp_path / executable
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o755)
    for executable, variable in (
        ("dpkg-query", "TEST_STATUS"),
        ("find", "TEST_LIBRARY"),
    ):
        path = tmp_path / executable
        path.write_text(f'#!/bin/sh\nprintf "%s" "${{{variable}}}"\n')
        path.chmod(0o755)
    result = subprocess.run(
        ["/bin/sh", "-c", command],
        env={
            **os.environ,
            "PATH": str(tmp_path),
            "TEST_STATUS": status,
            "TEST_LIBRARY": library,
        },
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode != 100, "Unexpected package-manager arguments"
    assert (result.returncode == 0) == (expected == 0)
