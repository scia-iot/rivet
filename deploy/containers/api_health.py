"""Check API HTTP liveness without credentials or a public health bypass."""

import http.client


def main() -> None:
    """Authentication denial proves the HTTP middleware is serving requests."""
    connection = http.client.HTTPConnection("127.0.0.1", 8000, timeout=3)
    try:
        connection.request("GET", "/server/health")
        if connection.getresponse().status not in (401, 403):
            raise SystemExit(1)
    except OSError:
        raise SystemExit(1) from None
    finally:
        connection.close()


if __name__ == "__main__":
    main()
