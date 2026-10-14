"""VPN client deletion lifecycle tests."""

from collections.abc import Generator
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from sciaiot.rivet.data.identity import AccessGrant, Device, User, UserClient
from sciaiot.rivet.data.server import Cert, Client, Connection, VirtualAddress
from sciaiot.rivet.dependencies import get_session
from sciaiot.rivet.main import app


@pytest.fixture(name="deletion_context")
def deletion_context_fixture() -> Generator[tuple[TestClient, Session, Client]]:
    """Create an isolated ServiceAdmin deletion context."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        address = VirtualAddress(ip="10.8.0.9", server_id=1)
        client = Client(
            name="deleted-client",
            revoked=True,
            virtual_address=address,
        )
        user = User(
            display_name="Owner",
            issuer="https://login.example/tenant/v2.0",
            subject="owner-subject",
        )
        session.add_all([address, client, user])
        session.commit()
        session.refresh(client)
        session.refresh(user)
        assert client.id is not None
        assert user.id is not None
        device = Device(name="edge-device", client_id=client.id)
        session.add_all(
            [
                device,
                Cert(
                    client_id=client.id,
                    issued_by="test-ca",
                    issued_to=client.name,
                    issued_on=datetime(2026, 1, 1, tzinfo=UTC),
                    expires_on=datetime(2027, 1, 1, tzinfo=UTC),
                ),
                Connection(
                    client_id=client.id,
                    remote_address="198.51.100.5",
                    connected_time=datetime(2026, 1, 2, tzinfo=UTC),
                ),
                UserClient(user_id=user.id, client_id=client.id),
            ]
        )
        session.commit()
        session.refresh(device)
        assert device.id is not None
        session.add(AccessGrant(user_id=user.id, device_id=device.id))
        session.commit()

        def get_session_override() -> Generator[Session]:
            yield session

        app.dependency_overrides[get_session] = get_session_override
        with (
            patch("sciaiot.rivet.main.create_app_directory"),
            patch("sciaiot.rivet.main.create_tables"),
            patch("sciaiot.rivet.main.init_scripts"),
            patch(
                "sciaiot.rivet.middlewares.azure_security.validate_token",
                return_value={
                    "iss": "https://login.example/tenant/v2.0",
                    "sub": "service-object-id",
                    "oid": "service-object-id",
                    "roles": ["ServiceAdmin"],
                },
            ),
            patch("sciaiot.rivet.middlewares.azure_security.USER_ROLE", "user"),
            patch("sciaiot.rivet.middlewares.azure_security.ADMIN_ROLE", "admin"),
            patch(
                "sciaiot.rivet.middlewares.azure_security.SERVICE_ADMIN_ROLE",
                "ServiceAdmin",
            ),
            TestClient(app) as test_client,
        ):
            yield test_client, session, client

    app.dependency_overrides.clear()
    SQLModel.metadata.drop_all(engine)
    engine.dispose()


def test_delete_revoked_client_cleans_relations_and_detaches_device(
    deletion_context: tuple[TestClient, Session, Client],
) -> None:
    """Deletion removes client-owned state but preserves Device access grants."""
    test_client, session, deleted = deletion_context
    client_id = deleted.id
    staged = MagicMock()
    with patch(
        "sciaiot.rivet.utils.openvpn.stage_client_file_removal",
        return_value=staged,
    ) as stage:
        response = test_client.delete(f"/clients/{deleted.name}")

    assert response.status_code == 204
    stage.assert_called_once_with(deleted.name, "/opt/rivet/certs")
    staged.discard.assert_called_once_with()
    staged.restore.assert_not_called()
    assert session.exec(select(Client).where(Client.id == client_id)).first() is None
    assert session.exec(select(Cert)).all() == []
    assert session.exec(select(Connection)).all() == []
    assert session.exec(select(UserClient)).all() == []
    assert session.exec(select(VirtualAddress)).one().ip == "10.8.0.9"
    device = session.exec(select(Device)).one()
    assert device.client_id is None
    assert session.exec(select(AccessGrant)).one().device_id == device.id


def test_delete_discard_failure_keeps_success_and_safe_guidance(
    deletion_context: tuple[TestClient, Session, Client],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Post-commit unlink failure reports manual cleanup without secrets."""
    test_client, _session, client = deletion_context
    sensitive = "/private/deleted-client.key"
    staged = MagicMock()
    staged.discard.side_effect = OSError(sensitive)
    with (
        patch(
            "sciaiot.rivet.utils.openvpn.stage_client_file_removal",
            return_value=staged,
        ),
        caplog.at_level("ERROR"),
    ):
        response = test_client.delete(f"/clients/{client.name}")

    assert response.status_code == 204
    assert ".rivet-delete-* artifacts" in caplog.text
    assert sensitive not in caplog.text


def test_revoked_client_cannot_receive_virtual_address(
    deletion_context: tuple[TestClient, Session, Client],
) -> None:
    """Revoked credentials cannot consume an address from the VPN pool."""
    test_client, session, client = deletion_context
    client.virtual_address = None
    session.add(client)
    session.commit()
    address = session.exec(select(VirtualAddress)).one()

    with patch("sciaiot.rivet.utils.openvpn.assign_client_ip") as assign:
        response = test_client.put(
            f"/clients/{client.name}/assign-ip",
            json={"ip": address.ip},
        )

    assert response.status_code == 409
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["detail"] == (
        "Revoked VPN clients cannot be assigned virtual addresses."
    )
    assign.assert_not_called()
    session.refresh(client)
    assert client.virtual_address is None


def test_delete_active_client_returns_actionable_problem(
    deletion_context: tuple[TestClient, Session, Client],
) -> None:
    """Active credentials must be revoked before destructive cleanup."""
    test_client, session, client = deletion_context
    client.revoked = False
    session.add(client)
    session.commit()
    with patch("sciaiot.rivet.utils.openvpn.stage_client_file_removal") as stage:
        response = test_client.delete(f"/clients/{client.name}")

    assert response.status_code == 409
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["detail"] == (
        "Revoke the client certificate before deleting this VPN client."
    )
    stage.assert_not_called()
    assert session.exec(select(Client).where(Client.id == client.id)).one()


def test_delete_cleanup_failure_preserves_database(
    deletion_context: tuple[TestClient, Session, Client],
) -> None:
    """Filesystem staging failure leaves all persisted client state intact."""
    test_client, session, client = deletion_context
    with patch(
        "sciaiot.rivet.utils.openvpn.stage_client_file_removal",
        side_effect=OSError("/private/client.key"),
    ):
        response = test_client.delete(f"/clients/{client.name}")

    assert response.status_code == 500
    assert response.json()["detail"] == (
        "The VPN client could not be deleted. Check host certificate files and retry."
    )
    assert "/private/client.key" not in response.text
    assert session.exec(select(Client).where(Client.id == client.id)).one()
    assert session.exec(select(Cert)).one()
    assert session.exec(select(Connection)).one()
    assert session.exec(select(UserClient)).one()
    assert session.exec(select(Device)).one().client_id == client.id


def test_delete_database_failure_restores_staged_files_and_records(
    deletion_context: tuple[TestClient, Session, Client],
) -> None:
    """A database failure restores files and rolls persisted cleanup back."""
    test_client, session, client = deletion_context
    client_id = client.id
    staged = MagicMock()
    with (
        patch(
            "sciaiot.rivet.utils.openvpn.stage_client_file_removal",
            return_value=staged,
        ),
        patch.object(session, "commit", side_effect=RuntimeError("db failed")),
        patch("sciaiot.rivet.dependencies.archive_store") as store,
    ):
        response = test_client.delete(f"/clients/{client.name}")

    assert response.status_code == 500
    assert response.json()["detail"] == (
        "The VPN client could not be deleted. Check database and host "
        "certificate files before retrying."
    )
    staged.restore.assert_called_once_with()
    staged.discard.assert_not_called()
    store.delete.assert_not_called()
    assert session.exec(select(Client).where(Client.id == client_id)).one()
    assert session.exec(select(Cert)).one()
    assert session.exec(select(Connection)).one()
    assert session.exec(select(UserClient)).one()
    assert session.exec(select(Device)).one().client_id == client_id


@pytest.mark.parametrize("storage_failure", [False, True])
def test_archive_cleanup_follows_durable_deletion(
    deletion_context: tuple[TestClient, Session, Client],
    caplog: pytest.LogCaptureFixture,
    storage_failure: bool,
) -> None:
    """Storage runs after SQL commit and staging discard without changing 204."""
    test_client, session, client = deletion_context
    client_id = client.id
    client_name = client.name
    staged = MagicMock()
    secret = "https://private.example/archive?sig=credential"

    def delete_archive(name: str) -> None:
        assert name == client_name
        assert (
            session.exec(select(Client).where(Client.id == client_id)).first() is None
        )
        staged.discard.assert_called_once_with()
        if storage_failure:
            raise RuntimeError(secret)

    with (
        patch(
            "sciaiot.rivet.utils.openvpn.stage_client_file_removal",
            return_value=staged,
        ),
        patch("sciaiot.rivet.dependencies.archive_store") as store,
        caplog.at_level("ERROR"),
    ):
        store.delete.side_effect = delete_archive
        response = test_client.delete(f"/clients/{client_name}")
    assert response.status_code == 204
    assert response.content == b""
    store.delete.assert_called_once_with(client_name)
    staged.restore.assert_not_called()
    if storage_failure:
        assert "manually" in caplog.text
    assert secret not in caplog.text
    assert secret not in response.text


def test_import_skips_names_revoked_in_ca_index(
    deletion_context: tuple[TestClient, Session, Client],
) -> None:
    """Durable CA revocation evidence prevents a deleted name reappearing."""
    test_client, session, deleted = deletion_context
    for assignment in session.exec(select(UserClient)).all():
        session.delete(assignment)
    for connection in session.exec(select(Connection)).all():
        session.delete(connection)
    for certificate in session.exec(select(Cert)).all():
        session.delete(certificate)
    session.exec(select(Device)).one().client_id = None
    session.delete(deleted)
    session.commit()
    with (
        patch(
            "sciaiot.rivet.utils.openvpn.list_client_certs",
            return_value=[deleted.name],
        ),
        patch(
            "sciaiot.rivet.utils.openvpn.client_is_revoked",
            return_value=True,
        ),
        patch("sciaiot.rivet.utils.openvpn.read_client_cert") as read_cert,
    ):
        response = test_client.post("/clients/import")

    assert response.status_code == 200
    assert response.json()["clients_skipped"] == 1
    assert response.json()["added"] == 0
    read_cert.assert_not_called()
    assert (
        session.exec(select(Client).where(Client.name == deleted.name)).first() is None
    )
