"""Transactional bulk Easy-RSA client and Device import tests."""

from collections.abc import Generator
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from sciaiot.rivet.data.identity import Device
from sciaiot.rivet.data.server import Client
from sciaiot.rivet.dependencies import get_session
from sciaiot.rivet.main import app


@pytest.fixture(name="import_context")
def import_context_fixture() -> Generator[tuple[TestClient, Session]]:
    """Create an isolated authenticated client-import context."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    with Session(engine) as session:

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
            yield test_client, session

    app.dependency_overrides.clear()
    SQLModel.metadata.drop_all(engine)
    engine.dispose()


def certificate_details(name: str) -> dict[str, object]:
    """Return deterministic certificate details for one imported client."""
    return {
        "issued_by": "test-ca",
        "issued_to": name,
        "issued_on": datetime(2026, 1, 1, tzinfo=UTC),
        "expires_on": datetime(2027, 1, 1, tzinfo=UTC),
    }


def expected_summary(
    *,
    added: int = 0,
    updated: int = 0,
    clients_skipped: int = 0,
    devices_created: int = 0,
    devices_already_linked: int = 0,
    device_conflicts: int = 0,
) -> dict[str, int]:
    """Build the complete import response expected by callers."""
    return {
        "added": added,
        "updated": updated,
        "clients_skipped": clients_skipped,
        "devices_created": devices_created,
        "devices_already_linked": devices_already_linked,
        "device_conflicts": device_conflicts,
    }


@pytest.mark.parametrize("request_body", [None, {"create_devices": False}])
def test_import_defaults_to_client_only_with_or_without_body(
    request_body: dict[str, bool] | None,
    import_context: tuple[TestClient, Session],
) -> None:
    """No body and an explicit false option preserve client-only behavior."""
    test_client, session = import_context
    with (
        patch(
            "sciaiot.rivet.utils.openvpn.list_client_certs",
            return_value=["client-only"],
        ),
        patch(
            "sciaiot.rivet.utils.openvpn.read_client_cert",
            return_value=certificate_details("client-only"),
        ),
        patch("sciaiot.rivet.utils.openvpn.read_client_ip", return_value=None),
    ):
        if request_body is None:
            response = test_client.post("/clients/import")
        else:
            response = test_client.post("/clients/import", json=request_body)

    assert response.status_code == 200
    assert response.json() == expected_summary(added=1)
    assert session.exec(select(Device)).all() == []


def test_import_can_create_matching_devices_idempotently(
    import_context: tuple[TestClient, Session],
) -> None:
    """Selected imports link one matching Device per new or existing Client."""
    test_client, session = import_context
    existing_client = Client(name="existing-edge")
    session.add(existing_client)
    session.commit()

    names = ["new-edge", "existing-edge"]

    def read_certificate(name: str) -> dict[str, object]:
        return certificate_details(name)

    with (
        patch(
            "sciaiot.rivet.utils.openvpn.list_client_certs",
            return_value=names,
        ),
        patch(
            "sciaiot.rivet.utils.openvpn.read_client_cert",
            side_effect=read_certificate,
        ),
        patch("sciaiot.rivet.utils.openvpn.read_client_ip", return_value=None),
    ):
        first = test_client.post(
            "/clients/import",
            json={"create_devices": True},
        )
        second = test_client.post(
            "/clients/import",
            json={"create_devices": True},
        )

    assert first.status_code == 200
    assert first.json() == expected_summary(
        added=1,
        updated=1,
        devices_created=2,
    )
    assert second.status_code == 200
    assert second.json() == expected_summary(
        updated=2,
        devices_already_linked=2,
    )

    clients = {client.name: client for client in session.exec(select(Client)).all()}
    devices = {device.name: device for device in session.exec(select(Device)).all()}
    assert set(devices) == set(names)
    assert devices["new-edge"].client_id == clients["new-edge"].id
    assert devices["existing-edge"].client_id == clients["existing-edge"].id


def test_import_counts_name_and_link_conflicts_without_reassignment(
    import_context: tuple[TestClient, Session],
) -> None:
    """Conflicting Device names and links remain unchanged and visible."""
    test_client, session = import_context
    already_linked_client = Client(name="already-linked")
    unlinked_name_client = Client(name="unlinked-name")
    other_name_client = Client(name="other-name")
    different_name_client = Client(name="different-name")
    other_client = Client(name="other-client")
    session.add_all(
        [
            already_linked_client,
            unlinked_name_client,
            other_name_client,
            different_name_client,
            other_client,
        ]
    )
    session.commit()
    for client in (
        already_linked_client,
        unlinked_name_client,
        other_name_client,
        different_name_client,
        other_client,
    ):
        session.refresh(client)

    already_linked = Device(
        name="already-linked",
        client_id=already_linked_client.id,
    )
    unlinked_same_name = Device(name="unlinked-name", client_id=None)
    same_name_other_client = Device(
        name="other-name",
        client_id=other_client.id,
    )
    different_name_same_client = Device(
        name="different-device",
        client_id=different_name_client.id,
    )
    session.add_all(
        [
            already_linked,
            unlinked_same_name,
            same_name_other_client,
            different_name_same_client,
        ]
    )
    session.commit()
    original_relationships = {
        device.name: device.client_id for device in session.exec(select(Device)).all()
    }

    with (
        patch(
            "sciaiot.rivet.utils.openvpn.list_client_certs",
            return_value=[
                "already-linked",
                "unlinked-name",
                "other-name",
                "different-name",
            ],
        ),
        patch(
            "sciaiot.rivet.utils.openvpn.read_client_cert",
            side_effect=lambda name: certificate_details(name),
        ),
        patch("sciaiot.rivet.utils.openvpn.read_client_ip", return_value=None),
    ):
        response = test_client.post(
            "/clients/import",
            json={"create_devices": True},
        )

    assert response.status_code == 200
    assert response.json() == expected_summary(
        updated=4,
        devices_already_linked=1,
        device_conflicts=3,
    )
    final_relationships = {
        device.name: device.client_id for device in session.exec(select(Device)).all()
    }
    assert final_relationships == original_relationships


def test_import_skips_invalid_names_and_unreadable_certificates(
    import_context: tuple[TestClient, Session],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Invalid discovery entries never reach certificate, IP, or Device writes."""
    test_client, session = import_context
    overlong_name = "a" * 256
    with (
        patch("sciaiot.rivet.utils.openvpn.read_client_cert") as read_certificate,
        patch("sciaiot.rivet.utils.openvpn.read_client_ip") as read_ip,
    ):
        read_certificate.side_effect = lambda name: (
            {} if name == "missing-cert" else certificate_details(name)
        )
        read_ip.return_value = None
        with patch(
            "sciaiot.rivet.utils.openvpn.list_client_certs",
            return_value=[
                "valid-edge",
                "../invalid",
                overlong_name,
                "missing-cert",
            ],
        ):
            response = test_client.post(
                "/clients/import",
                json={"create_devices": True},
            )

    assert response.status_code == 200
    assert response.json() == expected_summary(
        added=1,
        clients_skipped=3,
        devices_created=1,
    )
    assert [call.args[0] for call in read_certificate.call_args_list] == [
        "valid-edge",
        "missing-cert",
    ]
    read_ip.assert_called_once_with("valid-edge")
    assert "../invalid" not in caplog.text
    assert overlong_name not in caplog.text
    assert [client.name for client in session.exec(select(Client)).all()] == [
        "valid-edge"
    ]
    assert [device.name for device in session.exec(select(Device)).all()] == [
        "valid-edge"
    ]


def test_import_rolls_back_staged_clients_and_devices_on_failure(
    import_context: tuple[TestClient, Session],
) -> None:
    """An unexpected database failure rolls back the complete import."""
    test_client, session = import_context
    sensitive = "/private/easy-rsa/client.crt?token=secret"
    with (
        patch(
            "sciaiot.rivet.utils.openvpn.list_client_certs",
            return_value=["rollback-edge"],
        ),
        patch(
            "sciaiot.rivet.utils.openvpn.read_client_cert",
            return_value=certificate_details("rollback-edge"),
        ),
        patch("sciaiot.rivet.utils.openvpn.read_client_ip", return_value=None),
        patch.object(session, "commit", side_effect=RuntimeError(sensitive)),
    ):
        response = test_client.post(
            "/clients/import",
            json={"create_devices": True},
        )

    assert response.status_code == 500
    assert response.json()["detail"] == "The certificate operation failed."
    assert sensitive not in response.text
    assert session.exec(select(Client)).all() == []
    assert session.exec(select(Device)).all() == []
