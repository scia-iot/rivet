"""Keep synchronous VPN and database workflows off the ASGI event loop."""

import functools
from collections.abc import Awaitable, Callable
from typing import ParamSpec, TypeVar

from starlette.concurrency import run_in_threadpool

P = ParamSpec("P")
R = TypeVar("R")


def threaded(function: Callable[P, R]) -> Callable[P, Awaitable[R]]:
    """Preserve handler signatures and awaitability while using a worker."""

    @functools.wraps(function)
    async def dispatch(*args: P.args, **kwargs: P.kwargs) -> R:
        return await run_in_threadpool(function, *args, **kwargs)

    return dispatch
