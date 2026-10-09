"""Safe download responses for the deployment-managed client profile."""

import fcntl
import ipaddress
import os
import re
import shlex
import stat
import tempfile
import unicodedata
from pathlib import Path
from typing import Any

from fastapi import Response

CLIENT_CONFIG_FILE_NAME = "rivet-client.ovpn"
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


class ClientConfigGenerationError(Exception):
    """Raised when a safe shared profile cannot be generated or installed."""


def _sync_directory(path: Path) -> None:
    """Make directory entry replacements durable before reporting success."""
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _prepare_directory(path: Path) -> None:
    """Create missing components without following any ancestor symlink."""
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                except FileExistsError:
                    pass
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise OSError
    finally:
        os.close(descriptor)


class ClientConfigReplacement:
    """Hold the profile writer fence through the caller's business transaction."""

    def __init__(
        self, target: Path, backup: Path | None, lock_descriptor: int | None = None
    ) -> None:
        self.target = target
        self.backup = backup
        self.lock_descriptor = lock_descriptor

    def _release(self) -> None:
        if self.lock_descriptor is not None:
            os.close(self.lock_descriptor)
            self.lock_descriptor = None

    def commit(self) -> None:
        """Finalize replacement durably and release the exclusive writer fence."""
        try:
            if self.backup is not None:
                self.backup.unlink(missing_ok=True)
                _sync_directory(self.target.parent)
                self.backup = None
        finally:
            self._release()

    def rollback(self) -> None:
        """Restore the previous profile without exposing partially written bytes."""
        try:
            if self.backup is not None:
                os.replace(self.backup, self.target)
                self.backup = None
            else:
                self.target.unlink(missing_ok=True)
            _sync_directory(self.target.parent)
        except OSError:
            raise ClientConfigGenerationError from None
        finally:
            self._release()


_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_CIPHER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def normalize_remote_host(value: str) -> str:
    """Validate and normalize a reachable VPN hostname or IP address."""
    candidate = value.strip()
    if not candidate or len(candidate) > 253 or not candidate.isascii():
        raise ValueError("invalid remote host")
    if "%" in candidate or any(character.isspace() for character in candidate):
        raise ValueError("invalid remote host")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        domain = candidate.removesuffix(".")
        if (
            not domain
            or len(domain) > 253
            or all(part.isdigit() for part in domain.split("."))
            or any(_DOMAIN_LABEL.fullmatch(part) is None for part in domain.split("."))
        ):
            raise ValueError("invalid remote host") from None
        if domain.casefold() == "localhost":
            raise ValueError("invalid remote host")
        return domain.lower()
    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_loopback
        or address.is_link_local
    ):
        raise ValueError("invalid remote host")
    return address.compressed


def _config_value(config: dict[str, Any], name: str) -> str:
    value = config.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ClientConfigGenerationError
    return value.strip()


def _cipher_list(value: str) -> str:
    ciphers = value.split(":")
    if not ciphers or any(_CIPHER.fullmatch(cipher) is None for cipher in ciphers):
        raise ClientConfigGenerationError
    return ":".join(ciphers)


def render_client_config(
    config: dict[str, Any],
    remote_host: str,
) -> bytes:
    """Render a credential-free client profile from parsed server options."""
    try:
        host = normalize_remote_host(remote_host)
        port = int(_config_value(config, "port"))
    except (TypeError, ValueError) as error:
        raise ClientConfigGenerationError from error
    if not 1 <= port <= 65535:
        raise ClientConfigGenerationError

    server_proto = _config_value(config, "proto").lower()
    protocols = {
        "udp": "udp",
        "udp4": "udp4",
        "udp6": "udp6",
        "tcp": "tcp-client",
        "tcp4": "tcp4-client",
        "tcp6": "tcp6-client",
        "tcp-server": "tcp-client",
        "tcp4-server": "tcp4-client",
        "tcp6-server": "tcp6-client",
    }
    if server_proto not in protocols:
        raise ClientConfigGenerationError
    proto = protocols[server_proto]

    server_dev = _config_value(config, "dev").lower()
    match = re.fullmatch(r"(tun|tap)[a-z0-9_-]*", server_dev)
    if match is None:
        raise ClientConfigGenerationError

    lines = [
        "# Generated by rivet from the active server configuration.",
        "# Add the CA, client certificate, and client key from your ZIP.",
        "client",
        f"dev {match.group(1)}",
        f"proto {proto}",
        f"remote {host} {port}",
        "resolv-retry infinite",
        "nobind",
    ]
    for option in ("persist_key", "persist_tun"):
        if config.get(option) is True:
            lines.append(option.replace("_", "-"))
    lines.append("remote-cert-tls server")

    data_ciphers = config.get("data_ciphers")
    if data_ciphers is not None:
        if not isinstance(data_ciphers, str):
            raise ClientConfigGenerationError
        lines.append(f"data-ciphers {_cipher_list(data_ciphers.strip())}")
    fallback = config.get("data_ciphers_fallback")
    if fallback is not None:
        if not isinstance(fallback, str) or _CIPHER.fullmatch(fallback.strip()) is None:
            raise ClientConfigGenerationError
        lines.append(f"data-ciphers-fallback {fallback.strip()}")
    verb = config.get("verb")
    if verb is not None:
        try:
            verb_number = int(str(verb))
        except ValueError as error:
            raise ClientConfigGenerationError from error
        if not 0 <= verb_number <= 11:
            raise ClientConfigGenerationError
        lines.append(f"verb {verb_number}")
    exit_notify = config.get("explicit_exit_notify")
    if exit_notify is not None:
        if not server_proto.startswith("udp"):
            raise ClientConfigGenerationError
        try:
            exit_notify_number = int(str(exit_notify))
        except ValueError as error:
            raise ClientConfigGenerationError from error
        if not 0 <= exit_notify_number <= 65535:
            raise ClientConfigGenerationError
        lines.append(f"explicit-exit-notify {exit_notify_number}")

    content = ("\n".join(lines) + "\n").encode()
    _validate_client_config(content)
    return content


def replace_client_config(
    config_path: str,
    content: bytes,
) -> ClientConfigReplacement:
    """Publish atomically with a bounded rollback copy and exclusive writer fence."""
    path = Path(config_path)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or not content
        or len(content) > MAX_CLIENT_CONFIG_BYTES
    ):
        raise ClientConfigGenerationError
    try:
        _validate_client_config(content)
    except ClientConfigReadError:
        raise ClientConfigGenerationError from None
    temp_path: Path | None = None
    backup_path: Path | None = None
    lock_descriptor: int | None = None
    installed = False
    try:
        _prepare_directory(path.parent)
        for parent in (path.parent, *path.parent.parents):
            if not stat.S_ISDIR(parent.lstat().st_mode):
                raise OSError
        parent_info = path.parent.stat()
        if parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o022:
            raise OSError
        lock_descriptor = os.open(
            path.parent / ".rivet-profile-lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
        )
        lock_info = os.fstat(lock_descriptor)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_nlink != 1
            or lock_info.st_uid != os.geteuid()
        ):
            raise OSError
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = None
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            pass
        else:
            with os.fdopen(descriptor, "rb") as stream:
                before = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_size > MAX_CLIENT_CONFIG_BYTES
                ):
                    raise OSError
                previous = stream.read(MAX_CLIENT_CONFIG_BYTES + 1)
                after = os.fstat(stream.fileno())
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ):
                    raise OSError
                if len(previous) > MAX_CLIENT_CONFIG_BYTES:
                    raise OSError
        descriptor, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent
        )
        temp_path = Path(temp_name)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if previous is not None:
            descriptor, backup_name = tempfile.mkstemp(
                prefix=f".{path.name}.backup.", dir=path.parent
            )
            backup_path = Path(backup_name)
            with os.fdopen(descriptor, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(previous)
                stream.flush()
                os.fsync(stream.fileno())
            _sync_directory(path.parent)
        os.replace(temp_path, path)
        installed = True
        temp_path = None
        _sync_directory(path.parent)
        replacement = ClientConfigReplacement(path, backup_path, lock_descriptor)
        lock_descriptor = None
        return replacement
    except OSError:
        try:
            if installed:
                if backup_path is not None:
                    os.replace(backup_path, path)
                    backup_path = None
                else:
                    path.unlink(missing_ok=True)
                _sync_directory(path.parent)
            if backup_path is not None:
                backup_path.unlink(missing_ok=True)
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
        except OSError:
            # Retain any private rollback evidence when restoration cannot finish.
            pass
        raise ClientConfigGenerationError from None
    finally:
        if lock_descriptor is not None:
            os.close(lock_descriptor)


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
