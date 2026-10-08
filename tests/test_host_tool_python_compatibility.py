"""Host-side deployment tools retain their documented Python 3.12 syntax."""

import ast
from pathlib import Path

import pytest

HOST_TOOLS = (
    "deploy/containers/prepare_state.py",
    "tests/integration/vpn_container_rehearsal.py",
    "tests/integration/compose_phase6_rehearsal.py",
    "tests/integration/compose_phase6_host_rehearsal.py",
    "tests/integration/phase7_container_rehearsal.py",
)


@pytest.mark.parametrize("relative_path", HOST_TOOLS)
def test_host_tool_uses_python_312_syntax(relative_path: str) -> None:
    """Keep operator-run scripts parseable by supported host Python."""
    path = Path(__file__).resolve().parents[1] / relative_path
    ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 12))
