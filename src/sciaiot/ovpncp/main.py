import importlib
import importlib.resources
import logging
import logging.config
import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from sciaiot.ovpncp.dependencies import (
    create_app_directory,
    create_tables,
    init_scripts,
)
from sciaiot.ovpncp.routes import client, identity, network, server

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = os.environ.get("PORT", "8000")
LOG_CONFIG = importlib.resources.files("sciaiot.ovpncp").joinpath("log.yml")

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup
    create_app_directory()
    create_tables()
    init_scripts()
    logger.info("Startup events finished.")

    yield

    # shutdown
    logger.info("Shutdown events finished.")


app = FastAPI(lifespan=lifespan)

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


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler to catch all unhandled errors."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "type": "/errors/internal-server-error",
            "title": "Internal Server Error",
            "status": 500,
            "detail": "An unexpected error occurred on the server.",
            "instance": str(request.url),
        },
    )


def run():
    uvicorn.run(app, host=HOST, port=int(PORT), log_config=str(LOG_CONFIG))
