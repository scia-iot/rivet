"""RFC 7807 problem-details models and response helpers."""

from http import HTTPStatus
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class ProblemDetails(BaseModel):
    """A machine-readable RFC 7807 error response."""

    type: str
    title: str
    status: int
    detail: str | None = None
    instance: str | None = None


PROBLEM_STATUS_CODES = (400, 401, 403, 404, 409, 412, 422, 500, 502, 503, 504)
PROBLEM_RESPONSES: dict[int | str, dict[str, Any]] = {
    status_code: {
        "model": ProblemDetails,
        "description": HTTPStatus(status_code).phrase,
        "content": {
            "application/problem+json": {
                "schema": {
                    "$ref": "#/components/schemas/ProblemDetails",
                }
            }
        },
    }
    for status_code in PROBLEM_STATUS_CODES
}


def problem_response(
    request: Request,
    status_code: int,
    detail: Any,
    *,
    problem_type: str | None = None,
    title: str | None = None,
) -> JSONResponse:
    """Build a safe problem-details response for an HTTP failure.

    Args:
        request: The request whose processing failed.
        status_code: HTTP response status.
        detail: A safe, caller-facing explanation.
        problem_type: Optional stable problem type identifier.
        title: Optional short problem title.

    Returns:
        An RFC 7807 JSON response.
    """
    try:
        default_title = HTTPStatus(status_code).phrase
    except ValueError:
        default_title = "Request Failed"

    resolved_title = title or default_title
    resolved_type = problem_type or (
        f"/errors/{resolved_title.lower().replace(' ', '-')}"
    )
    problem = ProblemDetails(
        type=resolved_type,
        title=resolved_title,
        status=status_code,
        detail=str(detail) if detail is not None else None,
        instance=str(request.url),
    )
    return JSONResponse(
        status_code=status_code,
        content=problem.model_dump(exclude_none=True),
        media_type="application/problem+json",
    )
