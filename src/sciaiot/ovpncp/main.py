import importlib
import importlib.resources
import logging
import logging.config
import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from sciaiot.ovpncp.dependencies import (
    create_app_directory,
    create_tables,
    get_vpn_control,
    init_scripts,
)
from sciaiot.ovpncp.problems import PROBLEM_RESPONSES, problem_response
from sciaiot.ovpncp.routes import client, identity, network, server

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = os.environ.get("PORT", "8000")
LOG_CONFIG = importlib.resources.files("sciaiot.ovpncp").joinpath("log.yml")

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup
    from sciaiot.ovpncp.adapters.vpn.settings import BackendSettings

    settings = BackendSettings.from_environment()
    get_vpn_control()
    create_app_directory()
    create_tables()
    if settings.backend == "host":
        init_scripts()
    logger.info("Startup events finished.")

    yield

    # shutdown
    logger.info("Shutdown events finished.")


app = FastAPI(lifespan=lifespan, responses=PROBLEM_RESPONSES)

# Register optional middlewares
for mw in ["azure_security", "azure_storage"]:
    try:
        module = importlib.import_module(f"sciaiot.ovpncp.middlewares.{mw}")
        app.middleware("http")(getattr(module, f"{mw}_middleware"))
    except ImportError:
        logger.debug(f"Optional middleware {mw} not loaded: dependencies missing.")

app.include_router(server.router, prefix="/server", tags=["server"])
app.include_router(client.router, prefix="/clients", tags=["client"])
app.include_router(network.router, prefix="/networks", tags=["server"])
app.include_router(identity.device_router, prefix="/devices", tags=["device"])
app.include_router(identity.user_router, prefix="/users", tags=["user"])
app.include_router(identity.principal_router, tags=["identity"])


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Return handled HTTP failures as RFC 7807 problem details."""
    return problem_response(request, exc.status_code, exc.detail)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Return request validation failures without exposing internals."""
    return problem_response(
        request,
        422,
        "The request did not satisfy the API contract.",
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler to catch all unhandled errors."""
    # FastAPI invokes this outside the originating exception block.
    logger.error("Unhandled request failure.")
    return problem_response(
        request,
        500,
        "An unexpected error occurred on the server.",
    )


def run() -> None:
    """Run the API with the reviewed direct or /api proxy topology."""
    root_path = os.environ.get("OVPNCP_ROOT_PATH", "").strip()
    if root_path not in ("", "/api"):
        raise ValueError("OVPNCP_ROOT_PATH must be empty or /api.")

    uvicorn.run(
        app,
        host=HOST,
        port=int(PORT),
        log_config=str(LOG_CONFIG),
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
        root_path=root_path,
        server_header=False,
        access_log=False,
    )
