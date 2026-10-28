"""Atomic, additive device sharing across existing local users."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlmodel import Session, select

from sciaiot.rivet.data.identity import AccessGrant, Device, User
from sciaiot.rivet.services.identity import AccessService, EntityConflictError
from tests.test_identity_api import identity_client_fixture  # noqa: F401


def seed(session: Session) -> tuple[int, list[int]]:
    """Create one device and three distinct local users."""
    device = Device(name="shared-device")
    users = [
        User(display_name=f"User {i}", issuer="issuer", subject=str(i))
        for i in range(3)
    ]
    session.add_all([device, *users])
    session.commit()
    assert device.id is not None
    ids = [user.id for user in users]
    assert all(user_id is not None for user_id in ids)
    return device.id, [int(user_id) for user_id in ids if user_id is not None]


def test_batch_is_additive_idempotent_and_ordered(db_session: Session) -> None:
    """Duplicate input and existing grants count each user once."""
    device_id, ids = seed(db_session)
    service = AccessService(db_session)
    service.grant(ids[0], device_id)
    result = service.grant_batch(device_id, [ids[1], ids[0], ids[1]])
    assert result.created == 1
    assert result.already_granted == 1
    assert [grant.user_id for grant in result.grants] == [ids[1], ids[0]]
    retry = service.grant_batch(device_id, ids[:2])
    assert (retry.created, retry.already_granted) == (0, 2)
    assert len(service.list_grants(device_id)) == 2
    for user_id in ids[:2]:
        assert [device.id for device in service.list_devices(user_id)] == [device_id]


@pytest.mark.parametrize("failure", ["missing-user", "missing-device"])
def test_batch_validates_every_entity_before_writing(
    db_session: Session, failure: str
) -> None:
    """A missing target leaves all grants untouched."""
    from sciaiot.rivet.services.identity import EntityNotFoundError

    device_id, ids = seed(db_session)
    with pytest.raises(EntityNotFoundError):
        AccessService(db_session).grant_batch(
            999 if failure == "missing-device" else device_id,
            [ids[0], 999] if failure == "missing-user" else ids,
        )
    assert db_session.exec(select(AccessGrant)).all() == []


@pytest.mark.parametrize("integrity", [True, False])
def test_batch_rolls_back_all_pending_inserts(
    db_session: Session, integrity: bool
) -> None:
    """Failures after a flush remove the entire batch and reset the session."""
    device_id, ids = seed(db_session)
    error = (
        IntegrityError("private SQL", {}, Exception("private DB detail"))
        if integrity
        else OperationalError("private SQL", {}, Exception("private DB detail"))
    )

    def fail_commit() -> None:
        db_session.flush()
        raise error

    expected = EntityConflictError if integrity else OperationalError
    with (
        patch.object(db_session, "commit", side_effect=fail_commit),
        pytest.raises(expected),
    ):
        AccessService(db_session).grant_batch(device_id, ids)
    assert db_session.exec(select(AccessGrant)).all() == []
    assert AccessService(db_session).grant_batch(device_id, ids).created == 3


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"user_ids": []},
        {"user_ids": [0]},
        {"user_ids": [-1]},
        {"user_ids": [True]},
        {"user_ids": ["1"]},
        {"user_ids": [1.0]},
        {"user_ids": [None]},
        {"user_ids": [1] * 101},
        {"user_ids": [1], "replace": True},
    ],
)
def test_batch_api_rejects_invalid_payload(
    identity_client: TestClient, body: dict[str, object]
) -> None:
    """Only a bounded list of strict positive integer IDs is accepted."""
    response = identity_client.post("/devices/1/access-grants", json=body)
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")


def test_batch_api_lifecycle_and_missing_user(identity_client: TestClient) -> None:
    """Batch recipients also appear through the existing user-device API."""
    device = identity_client.post("/devices", json={"name": "shared"}).json()
    ids = [
        identity_client.post(
            "/users",
            json={
                "display_name": f"User {i}",
                "issuer": "issuer",
                "subject": str(i),
            },
        ).json()["id"]
        for i in range(2)
    ]
    path = f"/devices/{device['id']}/access-grants"
    missing = identity_client.post(path, json={"user_ids": [ids[0], 999]})
    assert missing.status_code == 404
    assert identity_client.get(path).json() == []
    response = identity_client.post(path, json={"user_ids": ids + ids})
    assert response.status_code == 200
    assert response.json()["created"] == 2
    assert response.json()["already_granted"] == 0
    assert identity_client.get(path).json() == response.json()["grants"]
    for user_id in ids:
        assert identity_client.get(f"/users/{user_id}/devices").json() == [device]
    retry = identity_client.post(path, json={"user_ids": ids})
    assert retry.json()["already_granted"] == 2
    assert retry.json()["created"] == 0
    assert identity_client.get("/devices/999/access-grants").status_code == 404


def test_batch_conflict_is_safe_problem(identity_client: TestClient) -> None:
    """Concurrent changes yield an actionable conflict without SQL details."""
    with patch.object(
        AccessService,
        "grant_batch",
        side_effect=EntityConflictError(
            "Device access changed concurrently. Retry the batch."
        ),
    ):
        response = identity_client.post(
            "/devices/1/access-grants", json={"user_ids": [1]}
        )
    assert response.status_code == 409
    assert response.json()["detail"] == (
        "Device access changed concurrently. Retry the batch."
    )
