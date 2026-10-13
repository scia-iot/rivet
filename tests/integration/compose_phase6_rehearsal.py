"""Run the real Compose service lifecycle inside pinned disposable namespaces.

Explicit operator invocation only. The production manifest is rendered by
Docker Compose, then its host/bridge attachments are replaced with owned
``--network none`` anchors. No service publishes a port or joins host networking.
"""

import argparse
import copy
import json
import os
import re
import signal
import sys
import time
import traceback
from pathlib import Path
from typing import Any

from tests.integration.vpn_container_rehearsal import (
    Rehearsal,
    validate_image,
    write_file,
)

FIXTURE = Path(__file__).with_name("container_http_fixture.py")
TENANT = "11111111-1111-4111-8111-111111111111"
AUDIENCE = "22222222-2222-4222-8222-222222222222"
SPA = "33333333-3333-4333-8333-333333333333"
SCOPE = f"api://{AUDIENCE}/access_as_user"
UPGRADE_SCOPE = f"api://{AUDIENCE}/access_as_user-v2"
MOUNTS: dict[str, dict[str, tuple[str, bool]]] = {
    "openvpn": {
        "/var/lib/ovpn-agent/projection": ("vpn-projection", True),
        "/var/lib/openvpn": ("vpn-pool", False),
        "/run/openvpn": ("management-socket", False),
        "/run/ovpn-events": ("event-socket", False),
    },
    "agent": {
        "/var/lib/ovpn-agent/config": ("vpn-config", False),
        "/var/lib/ovpn-agent/pki": ("vpn-pki", False),
        "/var/lib/ovpn-agent/ccd": ("vpn-ccd", False),
        "/var/lib/ovpn-agent/journal": ("vpn-journal", False),
        "/var/lib/ovpn-agent/projection": ("vpn-projection", False),
        "/run/ovpn-agent": ("agent-socket", False),
        "/run/openvpn": ("management-socket", True),
        "/run/ovpn-events": ("event-socket", False),
        "/var/lib/openvpn": ("vpn-pool", True),
    },
    "api": {
        "/opt/rivet": ("api-data", False),
        "/opt/rivet/certs": ("api-archives", False),
        "/var/lib/ovpn-api/profile": ("api-profile", False),
        "/run/ovpn-agent": ("agent-socket", True),
    },
    "web": {},
}
SERVICE_KEYS = {
    "openvpn": {
        "cap_add",
        "cap_drop",
        "cpus",
        "command",
        "devices",
        "entrypoint",
        "image",
        "logging",
        "mem_limit",
        "network_mode",
        "pids_limit",
        "platform",
        "read_only",
        "restart",
        "security_opt",
        "stop_grace_period",
        "tmpfs",
        "user",
        "volumes",
    },
    "agent": {
        "cap_add",
        "cap_drop",
        "cpus",
        "command",
        "depends_on",
        "entrypoint",
        "environment",
        "group_add",
        "image",
        "logging",
        "mem_limit",
        "network_mode",
        "pids_limit",
        "platform",
        "read_only",
        "restart",
        "security_opt",
        "stop_grace_period",
        "tmpfs",
        "user",
        "volumes",
    },
    "api": {
        "cap_drop",
        "cpus",
        "command",
        "depends_on",
        "entrypoint",
        "environment",
        "image",
        "logging",
        "mem_limit",
        "networks",
        "pids_limit",
        "platform",
        "read_only",
        "restart",
        "security_opt",
        "stop_grace_period",
        "tmpfs",
        "user",
        "volumes",
    },
    "web": {
        "cap_drop",
        "cpus",
        "command",
        "depends_on",
        "entrypoint",
        "environment",
        "image",
        "logging",
        "mem_limit",
        "networks",
        "pids_limit",
        "platform",
        "ports",
        "read_only",
        "restart",
        "security_opt",
        "stop_grace_period",
        "tmpfs",
        "user",
    },
}


def _attest_service(
    role: str, service: dict[str, Any], state: Path, route_protocol: str = "200"
) -> None:
    """Require the exact reviewed grants, mounts and service-level topology."""
    if set(service) != SERVICE_KEYS[role]:
        raise ValueError("Unexpected rendered Compose service fields.")
    expected_caps = (
        ["NET_ADMIN", "SETUID", "SETGID"] if role in {"openvpn", "agent"} else None
    )
    if (
        service.get("cap_add") != expected_caps
        or service["cap_drop"] != ["ALL"]
        or service["read_only"] is not True
        or service["security_opt"]
        != ["no-new-privileges:true", "apparmor=docker-default"]
        or service["entrypoint"] is not None
        or service["command"] is not None
        or service["platform"] != "linux/amd64"
        or service["cpus"] != 1
        or service["mem_limit"] != "536870912"
        or service["pids_limit"] != 128
        or service["stop_grace_period"] != "30s"
        or service["restart"] != "unless-stopped"
        or service["logging"]
        != {"driver": "local", "options": {"max-size": "10m", "max-file": "3"}}
    ):
        raise ValueError("Rendered Compose security contract changed.")
    if (
        service["user"]
        != {
            "openvpn": "0:65532",
            "agent": "0:65532",
            "api": "65531:65531",
            "web": "101:101",
        }[role]
    ):
        raise ValueError("Rendered Compose identity changed.")
    tmpfs = service["tmpfs"]
    expected_tmpfs = (
        f"/tmp:rw,noexec,nosuid,nodev,"
        f"size={'16m' if role == 'openvpn' else '32m'},mode=1777"
    )
    if tmpfs != [expected_tmpfs]:
        raise ValueError("Rendered Compose tmpfs changed.")
    devices = (
        [
            {
                "source": "/dev/net/tun",
                "target": "/dev/net/tun",
                "permissions": "rwm",
            }
        ]
        if role == "openvpn"
        else None
    )
    if service.get("devices") != devices:
        raise ValueError("Rendered Compose device grant changed.")
    if service.get("group_add") != (["65531"] if role == "agent" else None):
        raise ValueError("Rendered Compose group grant changed.")
    upstream = {"agent": "openvpn", "api": "agent", "web": "api"}.get(role)
    dependency = (
        {upstream: {"condition": "service_healthy", "required": True}}
        if upstream is not None
        else None
    )
    if service.get("depends_on") != dependency:
        raise ValueError("Rendered Compose readiness ordering changed.")
    expected_network = "host" if role in {"openvpn", "agent"} else None
    if service.get("network_mode") != expected_network:
        raise ValueError("Unexpected Compose network mode.")
    web_address = "172.30.250.3" if role == "api" else "172.30.250.2"
    expected_networks = {"web": {"ipv4_address": web_address}}
    if service.get("networks") != (
        expected_networks if role in {"api", "web"} else None
    ):
        raise ValueError("Unexpected Compose bridge attachment.")
    expected_ports = (
        [
            {
                "mode": "ingress",
                "host_ip": "127.0.0.1",
                "target": 8080,
                "published": "8080",
                "protocol": "tcp",
            }
        ]
        if role == "web"
        else None
    )
    if service.get("ports") != expected_ports:
        raise ValueError("Unexpected Compose published port.")
    expected_environments = {
        "openvpn": None,
        "agent": {
            "RIVET_AGENT_CONFIG": "/var/lib/ovpn-agent/config/server.conf",
            "RIVET_AGENT_PKI": "/var/lib/ovpn-agent/pki",
            "RIVET_AGENT_CCD": "/var/lib/ovpn-agent/ccd",
            "RIVET_AGENT_JOURNAL": "/var/lib/ovpn-agent/journal",
            "RIVET_AGENT_PROJECTION": "/var/lib/ovpn-agent/projection",
            "RIVET_AGENT_OWNERSHIP": "/var/lib/ovpn-agent/config/ownership.json",
            "RIVET_AGENT_SOCKET": "/run/ovpn-agent/agent.sock",
            "RIVET_AGENT_EVENT_SOCKET": "/run/ovpn-events/events.sock",
            "RIVET_MANAGEMENT_SOCKET": "/run/openvpn/management.sock",
            "RIVET_MANAGEMENT_UID": "0",
            "RIVET_MANAGEMENT_GID": "65532",
            "RIVET_OPENVPN_UID": "65530",
            "RIVET_API_UID": "65531",
            "RIVET_AGENT_ROUTE_PROTOCOL": route_protocol,
            "RIVET_AGENT_MUTATIONS": "assignments,routes,access,pki,events,management",
            "RIVET_AGENT_EASYRSA": "/usr/share/easy-rsa/easyrsa",
        },
        "api": {
            "RIVET_VPN_BACKEND": "agent",
            "RIVET_AGENT_SOCKET": "/run/ovpn-agent/agent.sock",
            "RIVET_AGENT_UID": "65532",
            "RIVET_CLIENT_CONFIG_PATH": "/var/lib/ovpn-api/profile/client.ovpn",
            "RIVET_VPN_EVENTS": "0",
            "RIVET_VPN_RECONCILE": "0",
            "RIVET_PROXY_IP": "172.30.250.2",
            "AZURE_ENTRAID_TENANT_ID": TENANT,
            "AZURE_ENTRAID_APP_CLIENT_ID": AUDIENCE,
            "AZURE_ENTRAID_USER_ROLE": "device_user",
            "AZURE_ENTRAID_ADMIN_ROLE": "sysadmin",
            "AZURE_ENTRAID_SERVICE_ADMIN_ROLE": "ServiceAdmin",
            "AZURE_ENTRAID_AUTO_REGISTER_USERS": "true",
        },
        "web": {
            "RIVET_UI_ENTRA_TENANT_ID": TENANT,
            "RIVET_UI_ENTRA_CLIENT_ID": SPA,
            "RIVET_UI_ENTRA_API_SCOPE": SCOPE,
        },
    }
    if service.get("environment") != expected_environments[role]:
        raise ValueError("Rendered Compose environment changed.")
    mounts = service.get("volumes", [])
    if not isinstance(mounts, list) or len(mounts) != len(MOUNTS[role]):
        raise ValueError("Unexpected Compose bind count.")
    seen: set[str] = set()
    for mount in mounts:
        if not isinstance(mount, dict) or set(mount) - {
            "type",
            "source",
            "target",
            "read_only",
            "bind",
        }:
            raise ValueError("Unexpected Compose mount properties.")
        target = mount.get("target")
        if not isinstance(target, str) or target not in MOUNTS[role] or target in seen:
            raise ValueError("Unexpected Compose mount target.")
        seen.add(target)
        member, readonly = MOUNTS[role][target]
        source = state / member
        if (
            mount.get("type") != "bind"
            or mount.get("source") != str(source)
            or source.resolve() != source
            or not source.is_dir()
            or mount.get("read_only", False) is not readonly
            or mount.get("bind") != {"create_host_path": False}
        ):
            raise ValueError("Unexpected Compose bind source or mode.")


def isolated_bundle(
    rendered: dict[str, Any],
    *,
    images: dict[str, str],
    state: Path,
    fixture: Path,
    anchors: dict[str, str],
    token: str,
    upgrade: bool = False,
) -> dict[str, Any]:
    """Constrain a rendered deployment to exclusively owned namespace anchors.

    Raises:
        ValueError: The reviewed topology, image or bind-root contract changed.
    """
    model = copy.deepcopy(rendered)
    if set(model) != {"name", "networks", "services", "x-bind", "x-runtime"}:
        raise ValueError("Unexpected top-level Compose resource.")
    if model["name"] != "rivet" or model["networks"] != {
        "web": {
            "name": "rivet_web",
            "driver": "bridge",
            "ipam": {"config": [{"subnet": "172.30.250.0/28"}]},
        }
    }:
        raise ValueError("Unexpected Compose network topology.")
    services = model.get("services")
    if not isinstance(services, dict) or set(services) != set(images):
        raise ValueError("Unexpected Compose service set.")
    if set(anchors) != {"server", "a", "b", "c", "http"}:
        raise ValueError("Missing disposable namespace anchors.")
    if len(set(anchors.values())) != len(anchors) or not all(
        re.fullmatch(rf"rivet-p6-{token}-anchor-{role}", anchor)
        for role, anchor in anchors.items()
    ):
        raise ValueError("Disposable namespace anchor identity changed.")
    if not re.fullmatch(r"[a-f0-9]{12}", token):
        raise ValueError("Invalid disposable run identifier.")
    for role, service in services.items():
        if service.get("image") != images[role]:
            raise ValueError("Compose image differs from reviewed digest.")
        _attest_service(role, service, state)
        service.pop("networks", None)
        service.pop("ports", None)
        service["network_mode"] = (
            f"container:{anchors['server']}"
            if role in {"openvpn", "agent"}
            else f"container:{anchors['http']}"
        )
        service["logging"] = {"driver": "none"}
        service["restart"] = "no"
        service["labels"] = {"rivet.rehearsal": token}
    api = services["api"]
    api["environment"]["RIVET_PROXY_IP"] = "127.0.0.1"
    api["environment"]["SSL_CERT_FILE"] = "/tmp/phase6-ca.crt"
    api["volumes"].append(
        {
            "type": "bind",
            "source": str(fixture / "ca.crt"),
            "target": "/tmp/phase6-ca.crt",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    )
    web = services["web"]
    if upgrade:
        web["environment"]["RIVET_UI_ENTRA_API_SCOPE"] = UPGRADE_SCOPE
    model["name"] = f"rivet-p6-{token}"
    model.pop("networks", None)
    model.pop("x-bind", None)
    model.pop("x-runtime", None)
    return model


class ComposeRehearsal(Rehearsal):
    """Extend the real VPN proof with rendered Compose and HTTP lifecycle."""

    def __init__(
        self,
        agent: str,
        openvpn: str,
        api: str,
        web: str,
        manifest: Path,
        upgrade_api: str | None,
        upgrade_web: str | None,
    ) -> None:
        validate_image(web, "web")
        if upgrade_api is not None:
            validate_image(upgrade_api, "api")
        if upgrade_web is not None:
            validate_image(upgrade_web, "web")
        if not manifest.is_file() or manifest.name != "compose.yml":
            raise ValueError("Reviewed deployment Compose manifest is required.")
        super().__init__(agent, openvpn, api)
        self.images["web"] = web
        self.upgrade_images = dict(self.images)
        if upgrade_api is not None:
            self.upgrade_images["api"] = upgrade_api
        if upgrade_web is not None:
            self.upgrade_images["web"] = upgrade_web
        self.manifest = manifest.resolve()
        self.project = f"rivet-p6-{self.token}"
        self.initial_bundle = self.root / "initial-compose.json"
        self.upgrade_bundle = self.root / "upgrade-compose.json"
        self.active_bundle = self.initial_bundle
        self.compose_invoked = False
        self.cached_image_ids: dict[str, str] = {}

    def compose(self, *argv: str, bundle: Path | None = None) -> bytes:
        """Use an exact private project and rendered bundle on local Docker."""
        selected = bundle if bundle is not None else self.active_bundle
        return self.command(
            [
                "docker",
                "--host=unix:///var/run/docker.sock",
                "compose",
                "--project-name",
                self.project,
                "-f",
                str(selected),
                *argv,
            ],
            timeout=300,
        )

    def topology(self) -> dict[str, str]:
        """Add one isolated HTTP namespace to the existing VPN topology."""
        anchors = super().topology()
        anchors["http"] = self.anchor(
            "http",
            host_aliases=(
                "login.microsoftonline.com=127.0.0.1",
                "api=127.0.0.1",
            ),
        )
        self.network("http", ["ip", "link", "set", "lo", "up"])
        return anchors

    def prepare(self) -> None:
        """Create synthetic VPN state and a private JWKS fixture mount."""
        super().prepare()
        fixture = self.state / "http-fixture"
        fixture.mkdir(mode=0o700)
        os.chown(fixture, 65531, 65531)
        write_file(
            fixture / "fixture.py",
            FIXTURE.read_bytes(),
            65531,
            65531,
            0o400,
        )
        self.launch(
            "jwks-generate",
            self.images["api"],
            [
                "--entrypoint=python",
                "--user=65531:65531",
                *self.mount("http-fixture", "/fixture"),
            ],
            ["/fixture/fixture.py", "generate"],
            detached=False,
        )

    def _render(self, anchors: dict[str, str]) -> None:
        """Render source Compose, attest it, and write two isolated bundles."""
        settings = {
            "RIVET_PLATFORM": "linux/amd64",
            "RIVET_STATE_ROOT": str(self.state),
            "RIVET_AGENT_ROUTE_PROTOCOL": "200",
            "RIVET_AGENT_MUTATIONS": "assignments,routes,access,pki,events,management",
            "RIVET_VPN_EVENTS": "0",
            "RIVET_VPN_RECONCILE": "0",
            "RIVET_UI_ENTRA_TENANT_ID": TENANT,
            "RIVET_UI_ENTRA_CLIENT_ID": SPA,
            "RIVET_UI_ENTRA_API_SCOPE": SCOPE,
            "AZURE_ENTRAID_TENANT_ID": TENANT,
            "AZURE_ENTRAID_APP_CLIENT_ID": AUDIENCE,
            "AZURE_ENTRAID_USER_ROLE": "device_user",
            "AZURE_ENTRAID_ADMIN_ROLE": "sysadmin",
            "AZURE_ENTRAID_SERVICE_ADMIN_ROLE": "ServiceAdmin",
        }
        for role, image in self.images.items():
            settings[f"RIVET_{role.upper()}_IMAGE"] = image
        env_path = self.root / "render.env"
        env_path.write_text(
            "".join(f"{key}={value}\n" for key, value in settings.items())
        )
        env_path.chmod(0o600)
        raw = self.command(
            [
                "docker",
                "--host=unix:///var/run/docker.sock",
                "compose",
                "--env-file",
                str(env_path),
                "-f",
                str(self.manifest),
                "config",
                "--format",
                "json",
            ]
        )
        rendered = json.loads(raw)
        for path, images, upgrade in (
            (self.initial_bundle, self.images, False),
            (self.upgrade_bundle, self.upgrade_images, True),
        ):
            model = isolated_bundle(
                rendered,
                images=self.images,
                state=self.state,
                fixture=self.state / "http-fixture",
                anchors=anchors,
                token=self.token,
                upgrade=upgrade,
            )
            for role in ("api", "web"):
                model["services"][role]["image"] = images[role]
            path.write_text(json.dumps(model))
            path.chmod(0o600)
            self.compose("config", "--quiet", bundle=path)

    def service_identity(self, role: str) -> tuple[str, int]:
        """Get an owned service container ID and host PID for survival checks."""
        container = self.compose("ps", "--all", "-q", role).decode().strip()
        if not re.fullmatch(r"[a-f0-9]{64}", container):
            raise RuntimeError("Compose service identity missing.")
        info = json.loads(self.docker("inspect", container))[0]
        labels = info["Config"]["Labels"]
        if (
            labels.get("rivet.rehearsal") != self.token
            or labels.get("com.docker.compose.project") != self.project
            or labels.get("com.docker.compose.service") != role
            or info["Id"] != container
        ):
            raise RuntimeError("Compose service ownership mismatch.")
        expected = (
            self.images[role]
            if role in {"openvpn", "agent"}
            else (
                self.upgrade_images[role]
                if self.active_bundle == self.upgrade_bundle
                else self.images[role]
            )
        )
        if (
            info["Config"]["Image"] != expected
            or info["Image"] != self.cached_image_ids[expected]
        ):
            raise RuntimeError("Compose service is running an unexpected image.")
        pid = info["State"]["Pid"]
        if type(pid) is not int or pid <= 1:
            raise RuntimeError("Compose service process is not running.")
        return container, pid

    def wait_service_health(self, role: str) -> None:
        """Wait for the image health check after a controlled restart."""
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                container, _ = self.service_identity(role)
                info = json.loads(self.docker("inspect", container))[0]
                if info["State"]["Health"]["Status"] == "healthy":
                    return
            except (RuntimeError, KeyError, IndexError, ValueError):
                pass
            time.sleep(1)
        raise RuntimeError("Compose service readiness deadline exceeded.")

    def http_probe(self, scope: str) -> None:
        """Exercise actual Nginx and API entrypoints with signed JWTs."""
        self.service_identity("api")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                self.docker(
                    "exec",
                    self.jwks,
                    "python",
                    "/fixture/fixture.py",
                    "probe",
                    "--scope",
                    scope,
                )
                return
            except RuntimeError:
                status = self.state / "http-fixture/probe-status"
                if status.is_file():
                    allowed = {
                        "started",
                        "web_health",
                        "runtime_config",
                        "runtime_scope",
                        "anonymous_denied",
                        "anonymous_redacted",
                        "admin_identity",
                        "admin_role",
                        "admin_permission",
                        "api_identity_persistence",
                        "user_identity",
                        "user_forbidden",
                        "app_only_service_admin",
                        "delegated_service_admin_denied",
                        "invalid_claim_denied",
                        "tampered_signature_denied",
                        "tampered_signature_redacted",
                        "unknown_role_denied",
                        "unexpected",
                    }
                    observed = status.read_text()
                    self.http_failure = observed if observed in allowed else "unknown"
                time.sleep(1)
        raise RuntimeError("HTTP, proxy or authorization probe failed.")

    def services(self, anchors: dict[str, str]) -> str:
        """Start all four real service images with Compose health ordering."""
        self.stage = "synthetic-jwks-service"
        self.jwks = self.launch(
            "jwks",
            self.images["api"],
            [
                "--entrypoint=python",
                "--user=65531:65531",
                "--cap-add=NET_BIND_SERVICE",
                *self.mount("http-fixture", "/fixture"),
            ],
            ["/fixture/fixture.py", "serve"],
            network=f"container:{anchors['http']}",
        )
        self.stage = "compose-render"
        self._render(anchors)
        if self.compose("ps", "--all", "-q").strip():
            raise RuntimeError("Disposable Compose project already exists.")
        self.stage = "compose-up-wait"
        self.compose_invoked = True
        self.compose("up", "--pull", "never", "--wait", "--wait-timeout", "240")
        self.http_probe(SCOPE)
        self.probe = self.launch(
            "probe",
            self.images["api"],
            [
                "--user=65531:65531",
                "--entrypoint=/bin/sleep",
                *self.mount("agent-socket", "/run/ovpn-agent", readonly=True),
                *self.mount("probe-credentials", "/probe-credentials"),
            ],
            ["1800"],
        )
        self.wait_ready()
        for role in ("a", "b"):
            self.launch(
                f"client-{role}",
                self.images["openvpn"],
                [
                    "--user=0:0",
                    "--cap-add=NET_ADMIN",
                    "--device=/dev/net/tun:/dev/net/tun:rwm",
                    "--entrypoint=/usr/local/sbin/openvpn",
                    *self.mount(f"client-{role}", "/fixture", readonly=True),
                ],
                ["--config", "/fixture/client.conf"],
                network=f"container:{anchors[role]}",
            )
        return self.service_identity("agent")[0]

    def _data_plane_identity(self) -> dict[str, tuple[str, int]]:
        """Record the two processes that must survive control-plane changes."""
        return {role: self.service_identity(role) for role in ("openvpn", "agent")}

    def control_plane_outage(self) -> None:
        """Prove outage, selected-service recreation and exact bundle rollback."""
        baseline = self._data_plane_identity()
        original_control = {
            role: self.service_identity(role)[0] for role in ("api", "web")
        }
        self.stage = "compose-api-outage"
        self.compose("stop", "web", "api")
        self.docker("stop", "--time=10", self.probe)
        if not self.peer_flow() or self._data_plane_identity() != baseline:
            raise RuntimeError("VPN data plane changed during API outage.")
        self.stage = "compose-api-restart"
        self.compose("start", "api", "web")
        self.docker("start", self.probe)
        for role in ("api", "web"):
            self.wait_service_health(role)
        self.http_probe(SCOPE)
        self.wait_ready()
        if not self.peer_flow() or self._data_plane_identity() != baseline:
            raise RuntimeError("VPN data plane changed after API restart.")
        self.stage = "compose-selected-upgrade"
        self.active_bundle = self.upgrade_bundle
        self.compose(
            "up",
            "--no-deps",
            "--force-recreate",
            "--pull",
            "never",
            "--wait",
            "--wait-timeout",
            "240",
            "api",
            "web",
        )
        upgraded_control = {
            role: self.service_identity(role)[0] for role in ("api", "web")
        }
        if any(
            upgraded_control[role] == original_control[role] for role in ("api", "web")
        ):
            raise RuntimeError("Compose selected service did not recreate.")
        self.http_probe(UPGRADE_SCOPE)
        if not self.peer_flow() or self._data_plane_identity() != baseline:
            raise RuntimeError("VPN data plane changed during selected upgrade.")
        self.stage = "compose-bundle-rollback"
        self.active_bundle = self.initial_bundle
        self.compose(
            "up",
            "--no-deps",
            "--force-recreate",
            "--pull",
            "never",
            "--wait",
            "--wait-timeout",
            "240",
            "api",
            "web",
        )
        if any(
            self.service_identity(role)[0] == upgraded_control[role]
            for role in ("api", "web")
        ):
            raise RuntimeError("Compose rollback did not recreate service.")
        self.http_probe(SCOPE)
        if not self.peer_flow() or self._data_plane_identity() != baseline:
            raise RuntimeError("VPN data plane changed during bundle rollback.")

    def check_image_cache(self) -> None:
        """Pin local image IDs once before any disposable service starts."""
        self.cached_image_ids = {}
        for image in sorted(
            set(self.images.values()) | set(self.upgrade_images.values())
        ):
            details = json.loads(self.docker("image", "inspect", image))
            if len(details) != 1 or not re.fullmatch(
                r"sha256:[a-f0-9]{64}", details[0]["Id"]
            ):
                raise RuntimeError("Reviewed image cache identity is invalid.")
            self.cached_image_ids[image] = details[0]["Id"]

    def execute(self) -> dict[str, object]:
        """Run the prior real-client proof and report added Compose evidence."""
        result = super().execute()
        result["compose_up_wait"] = "passed"
        result["web_proxy_signed_jwt_rbac"] = "passed"
        result["api_identity_persistence"] = "passed"
        result["compose_api_recreate_rollback"] = "passed"
        result["phase6_compose_lifecycle"] = "passed"
        result["production_network_topology"] = False
        result["distinct_upgrade_image"] = any(
            self.images[role] != self.upgrade_images[role] for role in ("api", "web")
        )
        result["full_phase6"] = False
        return result

    def close(self, *, remove_state: bool = True) -> None:
        """Remove only the attested Compose project before namespace anchors."""
        if self.compose_invoked:
            raw = self.docker(
                "ps",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                f"label=com.docker.compose.project={self.project}",
            )
            for container in raw.decode().splitlines():
                if not re.fullmatch(r"[a-f0-9]{64}", container):
                    raise RuntimeError("Unrecognized disposable Compose object.")
                info = json.loads(self.docker("inspect", container))[0]
                labels = info["Config"]["Labels"]
                if (
                    info["Id"] != container
                    or labels.get("rivet.rehearsal") != self.token
                    or labels.get("com.docker.compose.project") != self.project
                    or labels.get("com.docker.compose.service") not in self.images
                ):
                    raise RuntimeError("Compose teardown ownership mismatch.")
                self.docker("rm", "--force", container)
            if self.docker(
                "ps",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                f"label=com.docker.compose.project={self.project}",
            ).strip():
                raise RuntimeError("Compose project cleanup is incomplete.")
        super().close(remove_state=remove_state)


def main() -> int:
    """Require explicit root invocation and redact all failure diagnostics."""
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ("agent", "openvpn", "api", "web"):
        parser.add_argument(f"--{role}-image", required=True)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--upgrade-api-image")
    parser.add_argument("--upgrade-web-image")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Reviewed root execution is required.")
    os.umask(0o077)

    def interrupted(signum: int, frame: object) -> None:
        raise RuntimeError("Disposable Compose rehearsal interrupted.")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    rehearsal = ComposeRehearsal(
        args.agent_image,
        args.openvpn_image,
        args.api_image,
        args.web_image,
        args.compose,
        args.upgrade_api_image,
        args.upgrade_web_image,
    )
    result: dict[str, object] = {}
    code = 0
    try:
        result = rehearsal.execute()
    except Exception as error:  # noqa: BLE001 - raw output is private
        code = 1
        result = {
            "result": "failed",
            "error_type": type(error).__name__,
            "stage": getattr(rehearsal, "stage", "initialization"),
            "last_command": getattr(rehearsal, "last_command", {}),
            "http_failure": getattr(rehearsal, "http_failure", "unknown"),
            "frames": [
                (Path(frame.filename).name, frame.lineno, frame.name)
                for frame in traceback.extract_tb(error.__traceback__)
            ],
        }
    finally:
        try:
            rehearsal.close()
            result["cleanup"] = "passed"
        except Exception:  # noqa: BLE001 - keep state if teardown is uncertain
            code = 1
            result["cleanup"] = "incomplete"
            result["run_id"] = rehearsal.token
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
