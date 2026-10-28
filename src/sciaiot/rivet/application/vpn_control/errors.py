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


def problem_detail(code: ErrorCode) -> str:
    """Explain recovery using fixed text without privileged diagnostics."""
    return {
        ErrorCode.INVALID_INPUT: (
            "The VPN agent rejected the operation parameters. Check the "
            "requested network and address against the VPN configuration."
        ),
        ErrorCode.UNAUTHORIZED: (
            "The VPN agent denied this operation. Ask an administrator to "
            "check the agent peer authorization policy."
        ),
        ErrorCode.NOT_FOUND: (
            "The VPN resource was not found. Refresh the client and route "
            "inventory before retrying."
        ),
        ErrorCode.CONFLICT: (
            "The VPN operation conflicts with existing or pending state. "
            "Refresh the client and route inventory and check pending "
            "operations. Imported CCD assignments and existing routes need "
            "explicit ownership review before Rivet can change them."
        ),
        ErrorCode.UNAVAILABLE: (
            "The VPN agent is unavailable or not ready. Check agent health "
            "and enabled mutation families, then retry the same request."
        ),
        ErrorCode.TIMEOUT: (
            "The VPN operation timed out; changes may already have occurred. "
            "Check agent health and reconcile the pending operation before "
            "changing the request."
        ),
        ErrorCode.EXHAUSTED: (
            "The VPN agent reached a capacity limit. Check agent capacity "
            "and pending operations before retrying the same request."
        ),
        ErrorCode.VERSION_MISMATCH: (
            "The API and VPN agent protocols are incompatible. Install "
            "compatible versions before retrying."
        ),
        ErrorCode.PARTIAL_FAILURE: (
            "The VPN operation may have applied only some changes. Reconcile "
            "the retained operation before submitting a different request."
        ),
        ErrorCode.UNKNOWN_OUTCOME: (
            "The VPN operation outcome is unknown. Check agent health and "
            "reconcile the retained operation before changing the request."
        ),
        ErrorCode.EXPIRED_OPERATION: (
            "The retained VPN operation has expired. Ask an administrator "
            "to reconcile its outcome before starting a new operation."
        ),
        ErrorCode.INTEGRITY: (
            "VPN state or response verification failed. Ask an administrator "
            "to check agent state and reconcile pending operations."
        ),
    }[code]
