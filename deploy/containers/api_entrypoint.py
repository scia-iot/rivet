"""Fail closed before importing application modules or consuming credentials."""

import ipaddress
import os
import stat
from pathlib import Path

import uvicorn

from sciaiot.rivet.services.provider_settings import StorageSettings

SECRET_NAMES = ("SQLALCHEMY_DATABASE_URI", "AZURE_STORAGE_CONNECTION_STRING")


def load_secret(path: Path) -> str:
    """Read a bounded regular credential file without following a symlink."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) not in (0o400, 0o600)
            or metadata.st_size > 16384
        ):
            raise ValueError("Invalid credential file.")
        value = os.read(descriptor, 16385).decode().rstrip("\n")
        if not value or len(value) > 16384 or "\x00" in value or "\n" in value:
            raise ValueError("Invalid credential file.")
        return value
    finally:
        os.close(descriptor)


def configure() -> str:
    """Require agent isolation, explicit authentication, and a narrow proxy IP."""
    if os.environ.get("RIVET_VPN_BACKEND") != "agent":
        raise ValueError("Container requires agent backend.")
    for name in (
        "AZURE_ENTRAID_TENANT_ID",
        "AZURE_ENTRAID_APP_CLIENT_ID",
        "AZURE_ENTRAID_USER_ROLE",
        "AZURE_ENTRAID_ADMIN_ROLE",
        "AZURE_ENTRAID_SERVICE_ADMIN_ROLE",
    ):
        if not os.environ.get(name, "").strip():
            raise ValueError("Container requires complete authentication settings.")
    proxy = str(ipaddress.IPv4Address(os.environ["RIVET_PROXY_IP"]))
    selected_storage = os.environ.get("RIVET_STORAGE_PROVIDER")
    if selected_storage is not None and selected_storage not in {
        "local",
        "azure_blob",
    }:
        raise ValueError("Invalid storage provider.")
    for name in SECRET_NAMES:
        if name == "AZURE_STORAGE_CONNECTION_STRING" and selected_storage == "local":
            continue
        location = os.environ.get(f"{name}_FILE")
        if location is not None:
            if name in os.environ:
                raise ValueError("Conflicting credential sources.")
            path = Path(location)
            if path.parent != Path("/run/secrets"):
                raise ValueError("Credential file must be a direct secret mount.")
            os.environ[name] = load_secret(path)
    StorageSettings.from_environment()
    return proxy


def main() -> None:
    """Start one API worker with bounded, redacted console logging."""
    try:
        proxy = configure()
        uvicorn.run(
            "sciaiot.rivet.main:app",
            host="0.0.0.0",
            port=8000,
            root_path="/api",
            proxy_headers=True,
            forwarded_allow_ips=proxy,
            access_log=False,
            server_header=False,
            log_config=None,
        )
    except KeyError, OSError, ValueError:
        raise SystemExit("API startup failed; check private configuration.") from None


if __name__ == "__main__":
    main()
