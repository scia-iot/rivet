"""Single-writer SQLite intent ledger with durable effect checkpoints."""

import fcntl
import os
import sqlite3
import stat
import threading
import time
import uuid
from pathlib import Path
from typing import Literal, Self

from sciaiot.ovpncp.application.vpn_control import schemas as s
from sciaiot.ovpncp.application.vpn_control import wire
from sciaiot.ovpncp.application.vpn_control.errors import ControlError, ErrorCode

Effect = Literal[
    "pki", "crl", "ccd", "routes", "access", "sessions", "events", "reload"
]
RETENTION_SECONDS = 35 * 24 * 60 * 60


class Journal:
    """Persist accepted intent before effects and retain identity tombstones.

    The deployment must supply a private agent-owned durable directory. One
    process holds its advisory writer lock for the whole journal lifetime;
    threads serialize through a reentrant lock and SQLite FULL transactions.
    """

    def __init__(self, directory: Path) -> None:
        for ancestor in (directory, *directory.parents):
            if not stat.S_ISDIR(ancestor.lstat().st_mode):
                raise ControlError(ErrorCode.UNAUTHORIZED)
        metadata = directory.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o022
        ):
            raise ControlError(ErrorCode.UNAUTHORIZED)
        self.directory = directory
        self._lock = threading.RLock()
        self._fd = os.open(
            directory / "writer.lock",
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self._fd)
            raise ControlError(ErrorCode.CONFLICT) from None
        try:
            path = directory / "operations.sqlite3"
            if path.exists() or path.is_symlink():
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ControlError(ErrorCode.UNAUTHORIZED)
            self._db = sqlite3.connect(path, check_same_thread=False)
            os.chmod(path, 0o600)
            self._db.execute("PRAGMA journal_mode=DELETE")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA max_page_count=262144")
            self._db.executescript(
                "CREATE TABLE IF NOT EXISTS identity (value TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS revision (singleton INTEGER PRIMARY KEY, value INTEGER NOT NULL);"
                "INSERT OR IGNORE INTO revision VALUES(1,0);"
                "CREATE TABLE IF NOT EXISTS state "
                "(singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
                "generation INTEGER NOT NULL);"
                "INSERT OR IGNORE INTO state VALUES(1,0);"
                "CREATE TABLE IF NOT EXISTS operations "
                "(id TEXT PRIMARY KEY, digest TEXT NOT NULL, request BLOB, "
                "result TEXT NOT NULL, updated REAL NOT NULL, "
                "terminal INTEGER NOT NULL);"
                "CREATE INDEX IF NOT EXISTS operation_expiry ON operations(terminal,updated);"
                "CREATE TABLE IF NOT EXISTS evidence "
                "(operation_id TEXT NOT NULL, name TEXT NOT NULL, value BLOB NOT NULL, "
                "PRIMARY KEY(operation_id,name));"
            )
            with self._db:
                if self._db.execute("SELECT value FROM identity").fetchone() is None:
                    self._db.execute(
                        "INSERT INTO identity VALUES(?)", (str(uuid.uuid4()),)
                    )
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except BaseException:
            os.close(self._fd)
            raise

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the database before releasing exclusive process ownership."""
        self._db.close()
        os.close(self._fd)

    @property
    def generation(self) -> int:
        """Return the durable global mutation generation."""
        with self._lock:
            return int(self._db.execute("SELECT generation FROM state").fetchone()[0])

    def lookup(self, operation_id: str) -> s.MutationResult:
        """Return original evidence including lifetime expired-ID tombstones."""
        with self._lock:
            row = self._db.execute(
                "SELECT result FROM operations WHERE id=?", (operation_id,)
            ).fetchone()
            if row is None:
                raise ControlError(ErrorCode.NOT_FOUND)
            return s.MutationResult.model_validate_json(row[0])

    def accept(self, request: s.Request) -> s.MutationResult:
        """Commit a new pending intent or return an exact existing replay.

        An unresolved intent fences subsequent writes until reconciliation
        establishes its outcome. Changed reuse never reaches an effect handler.
        """
        request = wire.decode_request(wire.encode(request))
        digest = wire.intent_digest(request)
        assert request.operation_id is not None
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT digest,result FROM operations WHERE id=?",
                (request.operation_id,),
            ).fetchone()
            if row is not None:
                if row[0] != digest:
                    raise ControlError(ErrorCode.CONFLICT)
                return s.MutationResult.model_validate_json(row[1])
            page_size = self._db.execute("PRAGMA page_size").fetchone()[0]
            used = (
                self._db.execute("PRAGMA page_count").fetchone()[0]
                - self._db.execute("PRAGMA freelist_count").fetchone()[0]
            )
            disk = os.statvfs(self.directory)
            if (
                used * page_size > 896 * 1024 * 1024
                or disk.f_bavail * disk.f_frsize < 128 * 1024 * 1024
            ):
                raise ControlError(ErrorCode.EXHAUSTED)
            rejected = (
                bool(
                    self._db.execute(
                        "SELECT 1 FROM operations WHERE terminal=0 LIMIT 1"
                    ).fetchone()
                )
                or request.expected_generation != self.generation
            )
            assert request.expected_generation is not None
            result = s.MutationResult(
                operation_id=request.operation_id,
                generation=request.expected_generation,
                state="failed" if rejected else "pending",
                failure=ErrorCode.CONFLICT if rejected else None,
                intent_sha256=digest,
                client=getattr(request.command, "client", None),
            )
            self._db.execute(
                "INSERT INTO operations VALUES(?,?,?,?,?,?)",
                (
                    request.operation_id,
                    digest,
                    wire.encode(request),
                    result.model_dump_json(),
                    time.time(),
                    int(rejected),
                ),
            )
            self._db.execute("UPDATE revision SET value=value+1")
            return result

    def pending(self) -> tuple[s.Request, ...]:
        """Load exact unresolved requests for actual-state reconciliation."""
        with self._lock:
            return tuple(
                wire.decode_request(row[0])
                for row in self._db.execute(
                    "SELECT request FROM operations WHERE terminal=0 ORDER BY updated"
                )
            )

    def checkpoint(self, operation_id: str, effect: Effect) -> s.MutationResult:
        """Record a verified committed effect, never an attempted command."""
        with self._lock, self._db:
            result = self.lookup(operation_id)
            if result.state not in {"pending", "partial", "unknown"}:
                raise ControlError(ErrorCode.CONFLICT)
            effects = tuple(dict.fromkeys((*result.completed, effect)))
            result = s.MutationResult.model_validate(
                result.model_copy(update={"state": "partial", "completed": effects})
            )
            self._store(result, terminal=False)
            return result

    def finish(
        self, operation_id: str, failure: ErrorCode | None = None
    ) -> s.MutationResult:
        """Commit verified success or a proven failure without side effects."""
        with self._lock, self._db:
            result = self.lookup(operation_id)
            if result.state not in {"pending", "partial", "unknown"}:
                raise ControlError(ErrorCode.CONFLICT)
            if failure is not None and result.completed:
                raise ControlError(ErrorCode.PARTIAL_FAILURE)
            generation = result.generation + (failure is None)
            result = s.MutationResult.model_validate(
                result.model_copy(
                    update={
                        "state": "succeeded" if failure is None else "failed",
                        "failure": failure,
                        "generation": generation,
                    }
                )
            )
            self._store(result, terminal=True)
            self._db.execute("UPDATE state SET generation=?", (generation,))
            return result

    def _store(self, result: s.MutationResult, *, terminal: bool) -> None:
        self._db.execute(
            "UPDATE operations SET result=?,updated=?,terminal=? WHERE id=?",
            (
                result.model_dump_json(),
                time.time(),
                int(terminal),
                result.operation_id,
            ),
        )

    def expire(self, *, now: float | None = None) -> None:
        """Discard old full results while retaining every ID and intent binding."""
        cutoff = (time.time() if now is None else now) - RETENTION_SECONDS
        with self._lock, self._db:
            rows = self._db.execute(
                "SELECT id,result FROM operations "
                "WHERE terminal=1 AND request IS NOT NULL AND updated<? LIMIT 1000",
                (cutoff,),
            ).fetchall()
            for operation_id, payload in rows:
                result = s.MutationResult.model_validate_json(payload)
                expired = s.MutationResult(
                    operation_id=operation_id,
                    generation=result.generation,
                    state="expired",
                    intent_sha256=result.intent_sha256,
                    client=result.client,
                )
                self._db.execute(
                    "DELETE FROM evidence WHERE operation_id=?", (operation_id,)
                )
                self._db.execute(
                    "UPDATE operations SET request=NULL,result=? WHERE id=?",
                    (expired.model_dump_json(), operation_id),
                )

    def evidence(self, operation_id: str, name: str) -> bytes | None:
        """Read private reconciliation evidence; never exposed on the wire."""
        with self._lock:
            row = self._db.execute(
                "SELECT value FROM evidence WHERE operation_id=? AND name=?",
                (operation_id, name),
            ).fetchone()
            return bytes(row[0]) if row is not None else None

    def stage(self, operation_id: str, name: str, value: bytes) -> None:
        """Durably bind immutable before/after evidence before external effects."""
        if len(value) > 4 * 1024 * 1024:
            raise ControlError(ErrorCode.EXHAUSTED)
        with self._lock, self._db:
            if self.lookup(operation_id).state not in {"pending", "partial", "unknown"}:
                raise ControlError(ErrorCode.CONFLICT)
            old = self.evidence(operation_id, name)
            if old is not None and old != value:
                raise ControlError(ErrorCode.CONFLICT)
            self._db.execute(
                "INSERT OR IGNORE INTO evidence VALUES(?,?,?)",
                (operation_id, name, value),
            )

    @property
    def identity(self) -> str:
        """Return the persistent journal identity bound to the config volume."""
        with self._lock:
            return str(self._db.execute("SELECT value FROM identity").fetchone()[0])

    @property
    def revision(self) -> int:
        """Return monotonic acceptance sequence, retained across compaction."""
        with self._lock:
            return int(self._db.execute("SELECT value FROM revision").fetchone()[0])
