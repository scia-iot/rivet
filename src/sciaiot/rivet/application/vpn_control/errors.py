"""Stable redacted failures and conservative retry decisions."""

import enum


class ErrorCode(enum.StrEnum):
    """Finite protocol error vocabulary, never raw backend diagnostics."""

    INVALID_INPUT = "invalid_input"
    UNAUTHORIZED = "unauthorized"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    EXHAUSTED = "exhausted"
    VERSION_MISMATCH = "version_mismatch"
    PARTIAL_FAILURE = "partial_failure"
    UNKNOWN_OUTCOME = "unknown_outcome"
    EXPIRED_OPERATION = "expired_operation"
    INTEGRITY = "integrity"


class ControlError(Exception):
    """Expose only a fixed code, regardless of the underlying failure."""

    def __init__(self, code: ErrorCode) -> None:
        self.code = ErrorCode(code)
        super().__init__(self.code.value)

    def __repr__(self) -> str:
        return f"ControlError({self.code.value!r})"


class RetryAction(enum.StrEnum):
    """Caller action after a bounded attempt; no automatic mutation replay."""

    STOP = "stop"
    RETRY_READ = "retry_read"
    QUERY_OPERATION = "query_operation"
    RECONCILE = "reconcile"


def retry_action(code: ErrorCode, *, mutation: bool) -> RetryAction:
    """Choose safe retry behavior without guessing whether a write ran."""
    if code == ErrorCode.INTEGRITY and mutation:
        return RetryAction.RECONCILE
    if code in {ErrorCode.PARTIAL_FAILURE, ErrorCode.EXPIRED_OPERATION}:
        return RetryAction.RECONCILE
    if code == ErrorCode.UNKNOWN_OUTCOME:
        return RetryAction.QUERY_OPERATION
    if code in {ErrorCode.UNAVAILABLE, ErrorCode.TIMEOUT, ErrorCode.EXHAUSTED}:
        return RetryAction.QUERY_OPERATION if mutation else RetryAction.RETRY_READ
    return RetryAction.STOP


def problem_status(code: ErrorCode) -> int:
    """Map to an RFC 7807 HTTP status without importing an HTTP framework."""
    return {
        ErrorCode.INVALID_INPUT: 422,
        ErrorCode.UNAUTHORIZED: 403,
        ErrorCode.NOT_FOUND: 404,
        ErrorCode.CONFLICT: 409,
        ErrorCode.UNAVAILABLE: 503,
        ErrorCode.TIMEOUT: 504,
        ErrorCode.EXHAUSTED: 503,
        ErrorCode.VERSION_MISMATCH: 503,
        ErrorCode.PARTIAL_FAILURE: 503,
        ErrorCode.UNKNOWN_OUTCOME: 503,
        ErrorCode.EXPIRED_OPERATION: 409,
        ErrorCode.INTEGRITY: 502,
    }[code]
