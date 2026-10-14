"""Validated provider selection for certificate archive storage."""

import dataclasses
import os
from collections.abc import Mapping


@dataclasses.dataclass(frozen=True)
class StorageSettings:
    """Selected storage provider and its private adapter configuration."""

    provider: str
    connection_string: str | None = dataclasses.field(default=None, repr=False)

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> StorageSettings:
        """Validate selection while ignoring unselected provider credentials."""
        values = os.environ if environment is None else environment
        selected = values.get("RIVET_STORAGE_PROVIDER")
        legacy = values.get("AZURE_STORAGE_CONNECTION_STRING")
        if selected is None:
            selected = "azure_blob" if legacy else "local"
        if selected not in {"local", "azure_blob"}:
            raise ValueError("RIVET_STORAGE_PROVIDER must be local or azure_blob.")
        if selected == "azure_blob":
            if legacy is None or not legacy.strip():
                raise ValueError("Azure Blob storage credentials are required.")
            return cls(selected, legacy)
        return cls(selected)
