"""Safe download responses for the deployment-managed client profile."""

import re
import shlex
import unicodedata
from pathlib import Path

from fastapi import Response

CLIENT_CONFIG_FILE_NAME = "ovpncp-client.ovpn"
CLIENT_CONFIG_MEDIA_TYPE = "application/x-openvpn-profile"
MAX_CLIENT_CONFIG_BYTES = 1024 * 1024
FORBIDDEN_CREDENTIAL_DIRECTIVES = frozenset(
    {
        "askpass",
        "auth-gen-token-secret",
        "auth-user-pass",
        "cert",
        "http-proxy-user-pass",
        "key",
        "pkcs12",
        "secret",
        "tls-auth",
        "tls-crypt",
        "tls-crypt-v2",
    }
)
INLINE_BLOCK_PATTERN = re.compile(
    r"^</?\s*[a-z0-9-]+\s*>",
    re.IGNORECASE,
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----",
    re.IGNORECASE,
)


class ClientConfigNotFoundError(Exception):
    """Raised when the configured shared client profile does not exist."""


class ClientConfigReadError(Exception):
    """Raised when the shared client profile cannot be read safely."""


def _tokens(line: str) -> list[str]:
    """Split one OpenVPN option line with comments and quoting honored."""
    lexer = shlex.shlex(line, posix=True)
    lexer.commenters = "#;"
    lexer.whitespace_split = True
    return list(lexer)


def _validate_client_config(content: bytes) -> None:
    """Reject non-text, credential-bearing, or incomplete client profiles.

    Args:
        content: Bounded bytes loaded from the deployment-managed file.

    Raises:
        ClientConfigReadError: If content is unsafe or unusable.
    """
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ClientConfigReadError from error

    if any(
        unicodedata.category(character) == "Cc" and character not in "\t\n\r"
        for character in text
    ):
        raise ClientConfigReadError
    if PRIVATE_KEY_PATTERN.search(text) is not None:
        raise ClientConfigReadError

    has_client = False
    has_remote = False
    try:
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if INLINE_BLOCK_PATTERN.match(line) is not None:
                raise ClientConfigReadError

            tokens = _tokens(line)
            if not tokens:
                continue
            if any("vpn-public-host-or-ip" in token.casefold() for token in tokens):
                raise ClientConfigReadError
            directive = tokens[0].removeprefix("--").casefold()
            if directive in FORBIDDEN_CREDENTIAL_DIRECTIVES:
                raise ClientConfigReadError
            if directive == "client":
                if len(tokens) != 1:
                    raise ClientConfigReadError
                has_client = True
            elif directive == "remote":
                if len(tokens) < 2:
                    raise ClientConfigReadError
                remote = tokens[1].casefold()
                if "<" in remote or ">" in remote or "vpn-public-host-or-ip" in remote:
                    raise ClientConfigReadError
                has_remote = True
    except ValueError as error:
        raise ClientConfigReadError from error

    if not has_client or not has_remote:
        raise ClientConfigReadError


def client_config_response(config_path: str) -> Response:
    """Read the exact configured profile and build a no-store response.

    Args:
        config_path: Trusted deployment-managed path; never request input.

    Returns:
        A binary attachment response containing the shared OpenVPN profile.

    Raises:
        ClientConfigNotFoundError: If no profile exists at the configured path.
        ClientConfigReadError: If the profile is unsafe, unusable, or unreadable.
    """
    path = Path(config_path)
    if not path.is_absolute():
        raise ClientConfigReadError

    try:
        with path.open("rb") as profile:
            content = profile.read(MAX_CLIENT_CONFIG_BYTES + 1)
    except FileNotFoundError as error:
        raise ClientConfigNotFoundError from error
    except OSError as error:
        raise ClientConfigReadError from error

    if not content or len(content) > MAX_CLIENT_CONFIG_BYTES:
        raise ClientConfigReadError
    _validate_client_config(content)

    return Response(
        content=content,
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": (
                f'attachment; filename="{CLIENT_CONFIG_FILE_NAME}"'
            ),
        },
        media_type=CLIENT_CONFIG_MEDIA_TYPE,
    )
