"""Bounded JSON codec, correlation and canonical mutation fingerprints."""

import hashlib
import json
from typing import Any

import pydantic

from . import schemas
from .errors import ControlError, ErrorCode


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ControlError(ErrorCode.INVALID_INPUT)
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ControlError(ErrorCode.INVALID_INPUT)


def _bounded_json(data: bytes) -> dict[str, Any]:
    if not isinstance(data, bytes) or len(data) > schemas.MAX_JSON_BYTES:
        raise ControlError(ErrorCode.INVALID_INPUT)
    depth = 0
    quoted = False
    escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > schemas.MAX_DEPTH:
                raise ControlError(ErrorCode.INVALID_INPUT)
        elif byte in (93, 125):
            depth -= 1
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
        )
    except (ValueError, UnicodeError, RecursionError):
        raise ControlError(ErrorCode.INVALID_INPUT) from None
    if not isinstance(value, dict):
        raise ControlError(ErrorCode.INVALID_INPUT)
    if value.get("version") != "1.0":
        raise ControlError(ErrorCode.VERSION_MISMATCH)
    return value


def encode(message: schemas.Request | schemas.Response) -> bytes:
    """Validate even copied/constructed models before serializing bounded JSON."""
    try:
        if message.version != "1.0":
            raise ControlError(ErrorCode.VERSION_MISMATCH)
        message = type(message).model_validate(message)
        data = message.model_dump_json().encode("utf-8")
        _bounded_json(data)
        type(message).model_validate_json(data)
    except (pydantic.ValidationError, ValueError, TypeError):
        raise ControlError(ErrorCode.INVALID_INPUT) from None
    return data


def decode_request(data: bytes) -> schemas.Request:
    """Reject malformed/ambiguous input and hide every parser diagnostic."""
    _bounded_json(data)
    try:
        return schemas.Request.model_validate_json(data)
    except pydantic.ValidationError:
        raise ControlError(ErrorCode.INVALID_INPUT) from None


def intent_digest(request: schemas.Request) -> str:
    """Bind durable operation ID to canonical command and expected generation."""
    validated = decode_request(encode(request))
    if validated.operation_id is None:
        raise ControlError(ErrorCode.INVALID_INPUT)
    payload = {
        "version": validated.version,
        "command": validated.command.model_dump(mode="json"),
        "expected_generation": validated.expected_generation,
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def validate_response(
    response: schemas.Response,
    request: schemas.Request,
) -> schemas.Response:
    """Require exact request/result identity before any data is consumed."""
    if response.request_id != request.request_id:
        raise ControlError(ErrorCode.INTEGRITY)
    result = response.result
    command = request.command
    if isinstance(result, schemas.Failure):
        return response
    if isinstance(result, schemas.MutationResult):
        lookup = isinstance(command, schemas.LookupOperation)
        operation_id = (
            command.operation_id
            if isinstance(command, schemas.LookupOperation)
            else request.operation_id
        )
        if result.operation_id != operation_id:
            raise ControlError(ErrorCode.INTEGRITY)
        if not lookup and (
            result.intent_sha256 != intent_digest(request)
            or result.client != getattr(command, "client", None)
            or request.expected_generation is None
            or result.generation < request.expected_generation
            or result.generation > request.expected_generation + 1
            or (
                result.state in {"failed", "pending"}
                and result.generation != request.expected_generation
            )
            or (
                result.state == "succeeded"
                and result.generation != request.expected_generation + 1
            )
        ):
            raise ControlError(ErrorCode.INTEGRITY)
        return response
    if result.kind != command.kind:
        raise ControlError(ErrorCode.INTEGRITY)
    if isinstance(result, schemas.ClientResult) and (
        not isinstance(command, schemas.GetClient)
        or result.item.client != command.client
    ):
        raise ControlError(ErrorCode.INTEGRITY)
    if isinstance(result, schemas.ArchiveManifest) and (
        not isinstance(command, schemas.Archive)
        or result.request_id != request.request_id
        or result.client != command.client
        or result.generation != command.generation
    ):
        raise ControlError(ErrorCode.INTEGRITY)
    if (
        isinstance(command, schemas.Page)
        and hasattr(result, "items")
        and len(result.items) > command.limit
    ):
        raise ControlError(ErrorCode.INTEGRITY)
    if (
        isinstance(command, schemas.Page)
        and isinstance(result, schemas.AccessResult)
        and len(result.pushes) > command.limit
    ):
        raise ControlError(ErrorCode.INTEGRITY)
    if (
        isinstance(command, schemas.PollEvents)
        and isinstance(result, schemas.EventsResult)
        and any(item.sequence <= command.after for item in result.items)
    ):
        raise ControlError(ErrorCode.INTEGRITY)
    return response


def decode_response(data: bytes, request: schemas.Request) -> schemas.Response:
    """Validate result schema and its correlation with the caller's request."""
    _bounded_json(data)
    try:
        response = schemas.Response.model_validate_json(data)
    except pydantic.ValidationError:
        raise ControlError(ErrorCode.INVALID_INPUT) from None
    return validate_response(response, request)


def require_success(response: schemas.Response) -> None:
    """Reject nonterminal/partial results before a synchronous public success.

    Call only after decode_response correlation. Lookup callers inspect the
    ledger directly to reconcile; they need not require successful completion.
    """
    result = response.result
    if isinstance(result, schemas.Failure):
        raise ControlError(result.code)
    if isinstance(result, schemas.MutationResult) and result.state != "succeeded":
        code = {
            "pending": ErrorCode.UNKNOWN_OUTCOME,
            "unknown": ErrorCode.UNKNOWN_OUTCOME,
            "partial": ErrorCode.PARTIAL_FAILURE,
            "expired": ErrorCode.EXPIRED_OPERATION,
            "failed": result.failure or ErrorCode.UNKNOWN_OUTCOME,
        }[result.state]
        raise ControlError(code)
