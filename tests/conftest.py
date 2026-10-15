"""Shared test fixtures with disposable database storage."""

from collections.abc import Generator
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine

pytest_plugins = ("tests.support.migration", "tests.support.pki")


@pytest.fixture
def authentication_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure actual Entra startup for tests of unrelated lifespan work."""
    from tests.support.authentication import AUTH_ENVIRONMENT

    for name, value in AUTH_ENVIRONMENT.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("RIVET_AUTH_PROVIDER", "entra")
    monkeypatch.delenv("RIVET_AUTH_AUTO_REGISTER_USERS", raising=False)
    monkeypatch.delenv("AZURE_ENTRAID_AUTO_REGISTER_USERS", raising=False)


@pytest.fixture
def db_engine(tmp_path: Path) -> Generator[Engine]:
    """Give each test an isolated SQLite database under pytest storage."""
    database = tmp_path / "ovpncp.db"
    engine = create_engine(f"sqlite:///{database}")
    SQLModel.metadata.create_all(engine)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Generator[Session]:
    """Keep one database session open for each test's API requests."""
    with Session(db_engine) as session:
        yield session
