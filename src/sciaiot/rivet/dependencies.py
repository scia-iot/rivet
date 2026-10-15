import importlib.resources
import logging
import os
import shutil
import stat
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sciaiot.rivet.application.storage import ArchiveStore
    from sciaiot.rivet.application.vpn_control.port import VpnControl
    from sciaiot.rivet.services.authentication import AuthenticationService
    from sciaiot.rivet.services.provider_settings import AuthenticationSettings
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

logger = logging.getLogger(__name__)

app_directory = "/opt/rivet"
certs_directory = f"{app_directory}/certs"
scripts_directory = f"{app_directory}/scripts"
client_config_path = os.environ.get(
    "RIVET_CLIENT_CONFIG_PATH",
    f"{app_directory}/client.ovpn",
)
sqlite_uri = f"sqlite:///{app_directory}/ovpncp.db"


database_uri = os.getenv("SQLALCHEMY_DATABASE_URI", sqlite_uri)
connect_args = {}
if database_uri.startswith("sqlite"):
    connect_args["check_same_thread"] = False
engine = create_engine(database_uri, echo=False, connect_args=connect_args)


def create_app_directory():
    if not os.path.exists(app_directory):
        os.makedirs(app_directory)
        os.makedirs(certs_directory)
        logger.info("Created the app directory & subdirectories.")


def create_tables():
    SQLModel.metadata.create_all(engine)
    logger.info("Created all tables, existing ones will be skipped.")


def get_session():
    with Session(engine) as session:
        yield session


def init_scripts():
    target_folder = Path(scripts_directory)
    with importlib.resources.path("sciaiot.rivet", "scripts") as source_path:
        if target_folder.exists():
            return

        shutil.copytree(source_path, target_folder)
        logger.info("Copied scripts to the app directory.")

        for path in target_folder.rglob("*.sh"):
            path.chmod(path.stat().st_mode | stat.S_IEXEC)
            logger.info(f"Made script {path} executable.")


vpn_control: VpnControl | None = None
archive_store: ArchiveStore | None = None
authentication_service: AuthenticationService | None = None
authentication_settings: AuthenticationSettings | None = None


def create_authentication_service() -> AuthenticationService:
    """Construct the selected identity provider for one application lifecycle."""
    from sciaiot.rivet.adapters.authentication.entra import EntraIdentityProvider
    from sciaiot.rivet.services.authentication import AuthenticationService
    from sciaiot.rivet.services.provider_settings import AuthenticationSettings

    settings = AuthenticationSettings.from_environment()
    if settings.provider == "entra":
        return AuthenticationService(EntraIdentityProvider(settings))
    raise ValueError("RIVET_AUTH_PROVIDER must be entra.")


def get_authentication_service() -> AuthenticationService:
    """Return the active lifecycle authentication service, failing closed."""
    if authentication_service is None:
        raise RuntimeError("Authentication service has not started.")
    return authentication_service


def get_authentication_settings() -> AuthenticationSettings:
    """Return the registration policy pinned at application startup."""
    if authentication_settings is None:
        raise RuntimeError("Authentication settings have not started.")
    return authentication_settings


@lru_cache(maxsize=1)
def _configured_vpn_control() -> VpnControl:
    """Build only the explicitly configured local VPN implementation."""
    from sciaiot.rivet.adapters.vpn.settings import BackendSettings

    settings = BackendSettings.from_environment()
    if settings.backend in {"agent", "shadow"}:
        from sciaiot.rivet.adapters.vpn.agent import AgentVpnControl

        agent = AgentVpnControl(settings.socket_path, peer_uid=settings.peer_uid)
        if settings.backend == "shadow":
            from sciaiot.rivet.adapters.vpn.shadow import ShadowHostVpnControl

            return ShadowHostVpnControl(agent, archive_directory=certs_directory)
        return agent
    from sciaiot.rivet.adapters.vpn.host import HostVpnControl

    return HostVpnControl(archive_directory=certs_directory)


def get_vpn_control() -> VpnControl:
    """Return the configured backend or an explicitly injected test port."""
    return vpn_control if vpn_control is not None else _configured_vpn_control()


def create_archive_store() -> ArchiveStore:
    """Construct the selected archive store once per application lifecycle."""
    from sciaiot.rivet.adapters.storage.azure_blob import AzureBlobArchiveStore
    from sciaiot.rivet.adapters.storage.local import LocalArchiveStore
    from sciaiot.rivet.services.provider_settings import StorageSettings

    settings = StorageSettings.from_environment()
    if settings.provider == "azure_blob":
        assert settings.connection_string is not None
        return AzureBlobArchiveStore(settings.connection_string)
    return LocalArchiveStore(certs_directory)


def get_archive_store() -> ArchiveStore:
    """Return the lifecycle store or a local test fallback."""
    if archive_store is not None:
        return archive_store
    from sciaiot.rivet.adapters.storage.local import LocalArchiveStore
    from sciaiot.rivet.services.provider_settings import StorageSettings

    if StorageSettings.from_environment().provider != "local":
        raise RuntimeError("Archive storage has not started.")
    return LocalArchiveStore(certs_directory)
