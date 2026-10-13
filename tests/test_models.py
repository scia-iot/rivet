from datetime import UTC, datetime

from sqlmodel import Session

from sciaiot.rivet.data.server import Client, Connection


def test_connection_history_model(db_session: Session):
    # Testing that we can create a client and then a connection for them.
    # We use the existing Connection model as it seems to match the requirements.
    client = Client(name="test_user", cidr="10.8.0.0/24")
    db_session.add(client)
    db_session.commit()
    db_session.refresh(client)

    start_time = datetime.now(UTC)
    conn = Connection(
        client_id=client.id, remote_address="1.2.3.4", connected_time=start_time
    )
    db_session.add(conn)
    db_session.commit()
    db_session.refresh(conn)

    assert conn.id is not None
    assert conn.client_id == client.id
    assert conn.remote_address == "1.2.3.4"
    # Older SQLModel versions drop UTC metadata when reading SQLite timestamps.
    assert conn.connected_time.replace(tzinfo=UTC) == start_time
    assert conn.disconnected_time is None

    # Test updating disconnect time
    end_time = datetime.now(UTC)
    conn.disconnected_time = end_time
    db_session.add(conn)
    db_session.commit()
    db_session.refresh(conn)

    assert conn.disconnected_time is not None
    assert conn.disconnected_time.replace(tzinfo=UTC) == end_time


def test_connection_relationship(db_session: Session):
    client = Client(name="test_rel_user")
    Connection(
        remote_address="1.1.1.1",
        connected_time=datetime.now(UTC),
        client=client,
    )
    Connection(
        remote_address="2.2.2.2",
        connected_time=datetime.now(UTC),
        client=client,
    )

    db_session.add(client)
    db_session.commit()
    db_session.refresh(client)

    assert len(client.connections) == 2
    assert client.connections[0].remote_address in ["1.1.1.1", "2.2.2.2"]
