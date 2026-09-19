"""Bounded durable at-least-once spool independent of API availability."""

import time
import uuid
from typing import Literal

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode

from .journal import Journal


class EventSpool:
    """Keep monotonic sequences and explicit overflow/restart gap evidence."""

    def __init__(self, journal: Journal, maximum: int = 100000) -> None:
        if not 2 <= maximum <= 100000:
            raise ValueError("Invalid bounded event capacity.")
        self.journal = journal
        self.maximum = maximum
        with journal._lock, journal._db:
            journal._db.executescript(
                "CREATE TABLE IF NOT EXISTS event_state "
                "(singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
                "sequence INTEGER NOT NULL, acknowledged INTEGER NOT NULL, "
                "count INTEGER NOT NULL, bytes INTEGER NOT NULL);"
                "INSERT OR IGNORE INTO event_state VALUES(1,0,0,0,0);"
                "CREATE TABLE IF NOT EXISTS events "
                "(sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL, "
                "created REAL NOT NULL);"
                "CREATE TABLE IF NOT EXISTS event_sessions "
                "(key TEXT PRIMARY KEY,payload TEXT NOT NULL,client_id INTEGER);"
            )

    def gap(self) -> s.Event:
        """Durably flag lost continuity so consumers request a live snapshot."""
        return self.append("gap", None)

    def append(
        self,
        kind: Literal["connect", "disconnect", "gap"],
        session: s.Session | None,
        *,
        occurred_at: int | None = None,
    ) -> s.Event:
        """Commit an event before making it visible to any API poll."""
        journal = self.journal
        with journal._lock, journal._db:
            self._trim()
            return self._append(kind, session, occurred_at=occurred_at)

    def _append(
        self,
        kind: Literal["connect", "disconnect", "gap"],
        session: s.Session | None,
        *,
        occurred_at: int | None = None,
    ) -> s.Event:
        self._trim(reserve=1)
        sequence = (
            int(
                self.journal._db.execute("SELECT sequence FROM event_state").fetchone()[
                    0
                ]
            )
            + 1
        )
        event = s.Event(
            sequence=sequence,
            event_id=str(uuid.uuid4()),
            occurred_at=time.time_ns() // 1000 if occurred_at is None else occurred_at,
            event=kind,
            session=session,
        )
        self.journal._db.execute(
            "INSERT INTO events VALUES(?,?,?)",
            (sequence, event.model_dump_json(), time.time()),
        )
        self.journal._db.execute(
            "UPDATE event_state SET sequence=?,count=count+1,bytes=bytes+?",
            (sequence, len(event.model_dump_json().encode())),
        )
        return event

    def poll(self, command: s.PollEvents) -> s.EventsResult:
        """Return ordered retained events after a validated sequence cursor."""
        if command.cursor is not None:
            raise ControlError(ErrorCode.INVALID_INPUT)
        with self.journal._lock, self.journal._db:
            self._trim()
            last, _ack = self.journal._db.execute(
                "SELECT sequence,acknowledged FROM event_state"
            ).fetchone()
            if command.after > last:
                raise ControlError(ErrorCode.CONFLICT)
            rows = self.journal._db.execute(
                "SELECT payload FROM events WHERE sequence>? ORDER BY sequence LIMIT ?",
                (command.after, command.limit),
            ).fetchall()
            return s.EventsResult(
                items=tuple(s.Event.model_validate_json(row[0]) for row in rows)
            )

    def acknowledge(self, through: int) -> None:
        """Remove only a committed prefix; repeating an old acknowledgement is safe."""
        with self.journal._lock, self.journal._db:
            last, ack = self.journal._db.execute(
                "SELECT sequence,acknowledged FROM event_state"
            ).fetchone()
            if through > last:
                raise ControlError(ErrorCode.CONFLICT)
            if through > ack:
                count, size = self.journal._db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(length(CAST(payload AS BLOB))),0) "
                    "FROM events WHERE sequence<=?",
                    (through,),
                ).fetchone()
                self.journal._db.execute(
                    "DELETE FROM events WHERE sequence<=?", (through,)
                )
                self.journal._db.execute(
                    "UPDATE event_state SET acknowledged=?,count=count-?,bytes=bytes-?",
                    (through, count, size),
                )

    def _trim(self, reserve: int = 0) -> None:
        count, size = self.journal._db.execute(
            "SELECT count,bytes FROM event_state"
        ).fetchone()
        oldest = self.journal._db.execute(
            "SELECT created FROM events ORDER BY sequence LIMIT 1"
        ).fetchone()
        # Reserve 8 MiB for SQLite page/index overhead, and one bounded event.
        expired = oldest is not None and oldest[0] < time.time() - 24 * 60 * 60
        if count > self.maximum - reserve or size > 120 * 1024 * 1024 - 4096 or expired:
            self.journal._db.execute("DELETE FROM events")
            self.journal._db.execute("UPDATE event_state SET count=0,bytes=0")
            self._append("gap", None)

    def produce(self, event: s.Event) -> None:
        """Give each daemon connect a distinct durable identity before delivery."""
        assert event.session is not None
        session = event.session
        with self.journal._lock, self.journal._db:
            self._trim()
            row = self.journal._db.execute(
                "SELECT payload FROM event_sessions WHERE key=?", (session.session_id,)
            ).fetchone()
            if event.event == "connect":
                if row is not None:
                    self._append("gap", None)
                session = session.model_copy(update={"session_id": str(uuid.uuid4())})
                self._session_capacity(event.session.session_id)
                self.journal._db.execute(
                    "INSERT OR REPLACE INTO event_sessions VALUES(?,?,NULL)",
                    (event.session.session_id, session.model_dump_json()),
                )
            elif row is not None:
                session = s.Session.model_validate_json(row[0])
                self.journal._db.execute(
                    "DELETE FROM event_sessions WHERE key=?",
                    (event.session.session_id,),
                )
            else:
                self._append("gap", None)
            self._append(event.event, session, occurred_at=event.occurred_at)

    def normalize(self, session: s.Session, client_id: int) -> s.Session:
        """Bind a live daemon client ID without aliasing a replacement session."""
        with self.journal._lock, self.journal._db:
            row = self.journal._db.execute(
                "SELECT payload,client_id FROM event_sessions WHERE key=?",
                (session.session_id,),
            ).fetchone()
            if row is not None and row[1] in {None, client_id}:
                original = s.Session.model_validate_json(row[0])
                self.journal._db.execute(
                    "UPDATE event_sessions SET client_id=? WHERE key=?",
                    (client_id, session.session_id),
                )
                return session.model_copy(update={"session_id": original.session_id})
            if row is not None:
                self._append("gap", None)
            self._session_capacity(session.session_id)
            # UUID4 identity is private durable metadata, never a client-selected key.
            normalized = session.model_copy(update={"session_id": str(uuid.uuid4())})
            self.journal._db.execute(
                "INSERT OR REPLACE INTO event_sessions VALUES(?,?,?)",
                (session.session_id, normalized.model_dump_json(), client_id),
            )
            return normalized

    def _session_capacity(self, key: str) -> None:
        if (
            self.journal._db.execute(
                "SELECT 1 FROM event_sessions WHERE key=?", (key,)
            ).fetchone()
            is None
            and self.journal._db.execute(
                "SELECT COUNT(*) FROM event_sessions"
            ).fetchone()[0]
            >= 10000
        ):
            raise ControlError(ErrorCode.EXHAUSTED)
