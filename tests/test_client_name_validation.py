"""Client identities agree across API, workflow, and host boundaries."""

import pytest
from pydantic import ValidationError

from sciaiot.ovpncp.application.vpn_control import schemas
from sciaiot.ovpncp.services import vpn
from sciaiot.ovpncp.utils import openvpn


@pytest.mark.parametrize(
    ("name", "valid"),
    [
        ("a", True),
        ("edge_1-2", True),
        ("a" * 255, True),
        ("", False),
        ("a" * 256, False),
        ("a\n", False),
        ("../secret", False),
        ("client;command", False),
        ("cliënt", False),
        (None, False),
    ],
)
def test_client_name_boundaries_agree(name: object, valid: bool) -> None:
    """Every entry point accepts the same constrained identity domain."""
    assert vpn.is_valid_name(name) is valid
    assert openvpn.is_valid_name(name) is valid
    if valid:
        assert schemas.GetClient.model_validate({"client": name}).client == name
    else:
        with pytest.raises(ValidationError):
            schemas.GetClient.model_validate({"client": name})
