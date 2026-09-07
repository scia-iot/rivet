import importlib.resources
import logging
import os
import shutil
import stat
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

logger = logging.getLogger(__name__)

app_directory = "/opt/ovpncp"
certs_directory = f"{app_directory}/certs"
scripts_directory = f"{app_directory}/scripts"
client_config_path = os.environ.get(
    "OVPNCP_CLIENT_CONFIG_PATH",
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
    with importlib.resources.path("sciaiot.ovpncp", "scripts") as source_path:
        if target_folder.exists():
            return

        shutil.copytree(source_path, target_folder)
        logger.info("Copied scripts to the app directory.")

        for path in target_folder.rglob("*.sh"):
            path.chmod(path.stat().st_mode | stat.S_IEXEC)
            logger.info(f"Made script {path} executable.")
