"""Export the FastAPI schema without starting application services."""

import argparse
import json
from pathlib import Path

from sciaiot.ovpncp.main import app


def main() -> None:
    """Write a stable, sorted OpenAPI document for frontend generation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).parents[1] / "openapi.json",
    )
    args = parser.parse_args()

    app.openapi_schema = None
    schema = app.openapi()
    args.output.write_text(
        f"{json.dumps(schema, indent=2, sort_keys=True)}\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
