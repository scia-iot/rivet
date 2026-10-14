"""Derive container and Python artifact versions from one GitHub release tag."""

import argparse
import re
import tomllib
from pathlib import Path

NUMBER = r"(?:0|[1-9][0-9]*)"
RELEASE_TAG = re.compile(
    rf"v?(?P<base>{NUMBER}\.{NUMBER}\.{NUMBER})"
    rf"(?:-(?P<phase>alpha|beta|rc)[.-](?P<serial>{NUMBER}))?"
)


def release_versions(tag: str) -> tuple[str, str]:
    """Return Docker and normalized Python versions for a supported tag.

    Args:
        tag: Exact release tag, without whitespace normalization.

    Returns:
        Container tag and corresponding PEP 440 package version.

    Raises:
        ValueError: If the tag cannot safely identify both artifact types.
    """
    match = RELEASE_TAG.fullmatch(tag)
    if match is None or len(tag.removeprefix("v")) > 128:
        raise ValueError(
            "Release tag must be [v]MAJOR.MINOR.PATCH, optionally followed "
            "by -alpha.N, -beta.N or -rc.N (a hyphen may replace the dot). "
            "Use numbers without leading zeros and at most 128 characters "
            "after the optional v; build metadata is unsupported."
        )
    package = match["base"]
    if match["phase"] is not None:
        phase = {"alpha": "a", "beta": "b", "rc": "rc"}[match["phase"]]
        package += f"{phase}{match['serial']}"
    return tag.removeprefix("v"), package


def stamp_packages(root: Path, version: str) -> None:
    """Stamp both build manifests and the agent's exact core requirement.

    Args:
        root: Disposable checkout used to build release distributions.
        version: Validated, normalized Python release version.

    Raises:
        ValueError: If metadata no longer has the expected package layout.
        OSError: If build metadata cannot be read or written.
    """
    updates: list[tuple[Path, str]] = []
    for relative, name in (
        ("pyproject.toml", "sciaiot-rivet"),
        ("packages/agent/pyproject.toml", "sciaiot-rivet-agent"),
    ):
        path = root / relative
        content = path.read_text()
        project = tomllib.loads(content)["project"]
        old_version = project["version"]
        if project["name"] != name or not isinstance(old_version, str):
            raise ValueError("Unexpected release package metadata.")
        content, count = re.subn(
            rf'^version = "{re.escape(old_version)}"$',
            f'version = "{version}"',
            content,
            flags=re.MULTILINE,
        )
        if count != 1:
            raise ValueError("Expected one package version declaration.")
        if name == "sciaiot-rivet-agent":
            expected = f"sciaiot-rivet=={old_version}"
            if project["dependencies"] != [expected]:
                raise ValueError("Agent must require its matching core version.")
            content = content.replace(f'"{expected}"', f'"sciaiot-rivet=={version}"')
        updates.append((path, content))
    # Validate both manifests before changing either file.
    for path, content in updates:
        path.write_text(content)


def main() -> None:
    """Validate a release and optionally prepare manifests or CI outputs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--write", action="store_true")
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        image, package = release_versions(args.tag)
        if args.write:
            stamp_packages(args.root, package)
        output = f"version={image}\npython_version={package}\n"
        if args.github_output is not None:
            with args.github_output.open("a") as stream:
                stream.write(output)
        print(output, end="")
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f"Release version preparation failed: {error}\n")


if __name__ == "__main__":
    main()
