"""Storage selection and archive adapter contract tests."""

import asyncio
import os
import runpy
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sciaiot.rivet import dependencies, main, native_api
from sciaiot.rivet.adapters.storage.azure_blob import AzureBlobArchiveStore
from sciaiot.rivet.adapters.storage.local import LocalArchiveStore
from sciaiot.rivet.application.storage import ArchiveNotFoundError, ArchiveStoreError
from sciaiot.rivet.application.vpn_control.schemas import MAX_ARCHIVE_BYTES
from sciaiot.rivet.services.provider_settings import StorageSettings


def test_storage_settings_infer_legacy_blob_and_honor_explicit_local(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit local choice leaves legacy Blob credentials unused."""
    monkeypatch.setenv("AZURE_STORAGE_CONNECTION_STRING", "legacy-secret")
    monkeypatch.delenv("RIVET_STORAGE_PROVIDER", raising=False)
    assert StorageSettings.from_environment().provider == "azure_blob"
    monkeypatch.setenv("RIVET_STORAGE_PROVIDER", "local")
    assert StorageSettings.from_environment().provider == "local"
    monkeypatch.setenv("RIVET_STORAGE_PROVIDER", "s3")
    with pytest.raises(ValueError, match="RIVET_STORAGE_PROVIDER"):
        StorageSettings.from_environment()


def test_local_archive_contract_and_unsafe_names(tmp_path: Path) -> None:
    """Archive names cannot select a path outside the configured directory."""
    store = LocalArchiveStore(tmp_path)
    store.put("safe_1", b"archive")
    assert store.get("safe_1") == b"archive"
    store.delete("safe_1")
    store.delete("safe_1")
    with pytest.raises(ArchiveNotFoundError):
        store.get("safe_1")
    with pytest.raises(ValueError):
        store.put("../outside", b"archive")
    assert not (tmp_path.parent / "outside.zip").exists()


@pytest.mark.parametrize("selection", ["", " ", "s3", "minio", "LOCAL"])
def test_storage_rejects_unsupported_selection(selection: str) -> None:
    """An invalid explicit choice never falls back to legacy inference."""
    with pytest.raises(ValueError, match="RIVET_STORAGE_PROVIDER"):
        StorageSettings.from_environment({"RIVET_STORAGE_PROVIDER": selection})


@pytest.mark.parametrize("credential", [None, "", " \t"])
def test_selected_blob_requires_credentials(credential: str | None) -> None:
    """Selected Blob requires nonblank private configuration."""
    values = {"RIVET_STORAGE_PROVIDER": "azure_blob"}
    if credential is not None:
        values["AZURE_STORAGE_CONNECTION_STRING"] = credential
    with pytest.raises(ValueError, match="credentials"):
        StorageSettings.from_environment(values)


def test_defaults_and_private_settings_representation() -> None:
    """Defaults stay local and settings repr never includes credentials."""
    assert StorageSettings.from_environment({}).provider == "local"
    settings = StorageSettings.from_environment(
        {"AZURE_STORAGE_CONNECTION_STRING": "sensitive-credential"}
    )
    assert "sensitive-credential" not in repr(settings)
    ignored = StorageSettings.from_environment(
        {
            "RIVET_STORAGE_PROVIDER": "local",
            "AZURE_STORAGE_CONNECTION_STRING": "sensitive-credential",
            "AZURE_STORAGE_CONNECTION_STRING_FILE": "/missing/secret",
        }
    )
    assert ignored.connection_string is None


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "empty", "large"])
def test_local_rejects_unsafe_or_unbounded_reads(tmp_path: Path, kind: str) -> None:
    """Only nonempty, bounded regular files owned by one name can be read."""
    archive = tmp_path / "client.zip"
    target = tmp_path / "private"
    target.write_bytes(b"private material")
    if kind == "symlink":
        archive.symlink_to(target)
    elif kind == "hardlink":
        archive.hardlink_to(target)
    elif kind == "fifo":
        os.mkfifo(archive)
    elif kind == "empty":
        archive.touch()
    else:
        with archive.open("wb") as stream:
            stream.truncate(MAX_ARCHIVE_BYTES + 1)
    with pytest.raises(ArchiveStoreError):
        LocalArchiveStore(tmp_path).get("client")
    assert target.read_bytes() == b"private material"


def test_local_never_follows_directory_symlinks(tmp_path: Path) -> None:
    """A configured directory link cannot redirect any archive operation."""
    target = tmp_path / "private"
    target.mkdir()
    archive = target / "client.zip"
    archive.write_bytes(b"original")
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    store = LocalArchiveStore(link)
    with pytest.raises(ArchiveStoreError):
        store.get("client")
    with pytest.raises(ArchiveStoreError):
        store.put("client", b"replacement")
    with pytest.raises(ArchiveStoreError):
        store.delete("client")
    assert archive.read_bytes() == b"original"


@pytest.mark.parametrize("failure", ["write", "generation", "replace"])
def test_local_failed_publication_preserves_previous_archive(
    tmp_path: Path, failure: str
) -> None:
    """Failed staging never replaces the prior file or leaves secret staging."""
    store = LocalArchiveStore(tmp_path)
    store.put("client", b"original")
    callback = MagicMock()
    if failure == "generation":
        callback.side_effect = ArchiveStoreError("generation changed")
    target = "os.fsync" if failure == "write" else "os.replace"
    with patch(target, wraps=getattr(os, target.split(".")[1])) as operation:
        if failure != "generation":
            operation.side_effect = OSError("/private/location")
        with pytest.raises(ArchiveStoreError):
            store.put("client", b"replacement", before_publish=callback)
    assert store.get("client") == b"original"
    assert list(tmp_path.glob(".archive-*")) == []
    assert (tmp_path / "client.zip").stat().st_mode & 0o777 == 0o600


def test_local_bounds_writes_and_creates_private_directories(tmp_path: Path) -> None:
    """Nested local storage creates private directories and bounds writes."""
    store = LocalArchiveStore(tmp_path / "nested" / "certs")
    store.delete("missing")
    with pytest.raises(ArchiveNotFoundError):
        store.get("missing")
    for content in (b"", b"x" * (MAX_ARCHIVE_BYTES + 1)):
        with pytest.raises(ArchiveStoreError):
            store.put("client", content)
    store.put("client", b"archive")
    assert store.get("client") == b"archive"
    assert store.directory.stat().st_mode & 0o777 == 0o700
    store.close()
    with pytest.raises(ValueError):
        LocalArchiveStore("relative")


def test_missing_blob_sdk_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Optional Azure imports are required only when Blob is constructed."""
    monkeypatch.setitem(sys.modules, "azure.storage.blob", None)
    with pytest.raises(ValueError, match="dependencies"):
        AzureBlobArchiveStore("private-credential")
    monkeypatch.setenv("RIVET_STORAGE_PROVIDER", "local")
    assert isinstance(dependencies.create_archive_store(), LocalArchiveStore)


def test_blob_partial_construction_closes_resources() -> None:
    """SDK constructor failures close transports and suppress private context."""
    service = MagicMock()
    service.get_container_client.side_effect = RuntimeError("private-credential")
    with (
        patch(
            "azure.storage.blob.BlobServiceClient.from_connection_string",
            return_value=service,
        ),
        pytest.raises(ValueError) as failure,
    ):
        AzureBlobArchiveStore("private-credential")
    service.close.assert_called_once_with()
    assert failure.value.__suppress_context__
    assert "private-credential" not in str(failure.value)


@pytest.mark.parametrize("fail_startup", [False, True])
def test_storage_lifecycle_closes_on_shutdown_or_startup_failure(
    monkeypatch: pytest.MonkeyPatch, fail_startup: bool
) -> None:
    """One constructed provider is always closed, including partial startup."""
    monkeypatch.setenv("RIVET_VPN_BACKEND", "host")
    store = MagicMock()
    with (
        patch.object(
            dependencies, "create_archive_store", return_value=store
        ) as factory,
        patch.object(main, "get_vpn_control"),
        patch.object(main, "create_app_directory") as create_directory,
        patch.object(main, "create_tables"),
        patch.object(main, "init_scripts"),
    ):
        if fail_startup:
            create_directory.side_effect = OSError("startup failed")

        async def run() -> None:
            async with main.lifespan(main.app):
                assert dependencies.get_archive_store() is store
                factory.assert_called_once_with()

        if fail_startup:
            with pytest.raises(OSError, match="startup failed"):
                asyncio.run(run())
        else:
            asyncio.run(run())
    store.close.assert_called_once_with()
    assert dependencies.archive_store is None


@pytest.mark.parametrize("entrypoint", ["native", "container"])
@pytest.mark.parametrize("selection", ["local", "azure_blob", "", "s3"])
def test_startup_paths_share_storage_validation(
    monkeypatch: pytest.MonkeyPatch, entrypoint: str, selection: str
) -> None:
    """Both launch paths reject invalid storage settings before serving."""
    for name in (
        "AZURE_STORAGE_CONNECTION_STRING",
        "AZURE_STORAGE_CONNECTION_STRING_FILE",
        "SQLALCHEMY_DATABASE_URI_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("RIVET_STORAGE_PROVIDER", selection)
    monkeypatch.setenv("RIVET_VPN_BACKEND", "agent")
    monkeypatch.setenv("RIVET_AGENT_UID", "1235")
    monkeypatch.setenv("RIVET_PROXY_IP", "172.30.250.2")
    monkeypatch.setenv("HOST", "127.0.0.1")
    monkeypatch.setattr(native_api.os, "geteuid", lambda: 1234)
    for name in native_api.AUTH_NAMES:
        monkeypatch.setenv(name, "11111111-1111-4111-8111-111111111111")
    configure = native_api.validate_environment
    if entrypoint == "container":
        configure = runpy.run_path("deploy/containers/api_entrypoint.py")["configure"]
    if selection == "local":
        monkeypatch.setenv("AZURE_STORAGE_CONNECTION_STRING", "unused")
        monkeypatch.setenv("AZURE_STORAGE_CONNECTION_STRING_FILE", "/missing/secret")
        configure()
    else:
        with pytest.raises(ValueError):
            configure()


def test_lifespan_rejects_blob_without_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    """Direct ASGI startup cannot silently substitute local storage for Blob."""
    monkeypatch.setenv("RIVET_VPN_BACKEND", "host")
    monkeypatch.setenv("RIVET_STORAGE_PROVIDER", "azure_blob")
    monkeypatch.setenv("AZURE_STORAGE_CONNECTION_STRING", "private-value")
    monkeypatch.setitem(sys.modules, "azure.storage.blob", None)

    async def run() -> None:
        async with main.lifespan(main.app):
            pytest.fail("ASGI accepted unavailable storage")

    with (
        patch.object(main, "get_vpn_control"),
        patch.object(main, "create_app_directory") as create_directory,
        pytest.raises(ValueError, match="dependencies"),
    ):
        asyncio.run(run())
    create_directory.assert_not_called()
