"""The shared, command-safe OpenVPN client identity domain."""

import re

CLIENT_NAME_PATTERN = r"^[A-Za-z0-9_-]{1,255}$"


def is_valid_name(value: object) -> bool:
    """Accept only bounded ASCII names safe for paths and VPN commands."""
    return (
        isinstance(value, str) and re.fullmatch(CLIENT_NAME_PATTERN, value) is not None
    )
