"""Validated provider selection for archive storage and authentication."""

import dataclasses
import os
import uuid
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


@dataclasses.dataclass(frozen=True)
class AuthenticationSettings:
    """Validated provider selection and registration policy."""

    provider: str
    auto_register_users: bool
    tenant_id: str
    client_id: str
    user_role: str
    admin_role: str
    service_admin_role: str

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> AuthenticationSettings:
        """Validate Entra settings and strict registration aliases."""
        values = os.environ if environment is None else environment
        provider = values.get("RIVET_AUTH_PROVIDER", "entra")
        if provider != "entra":
            raise ValueError("RIVET_AUTH_PROVIDER must be entra.")

        names = (
            "AZURE_ENTRAID_TENANT_ID",
            "AZURE_ENTRAID_APP_CLIENT_ID",
            "AZURE_ENTRAID_USER_ROLE",
            "AZURE_ENTRAID_ADMIN_ROLE",
            "AZURE_ENTRAID_SERVICE_ADMIN_ROLE",
        )
        settings = tuple(values.get(name, "") for name in names)
        if any(not value or value != value.strip() for value in settings):
            raise ValueError("Entra authentication settings are incomplete.")
        try:
            if any(str(uuid.UUID(value)) != value.lower() for value in settings[:2]):
                raise ValueError
        except ValueError:
            raise ValueError("Entra tenant and client IDs must be UUIDs.") from None
        if len(set(settings[2:])) != 3:
            raise ValueError("Entra role mappings must be distinct.")

        def parse_bool(raw: str) -> bool:
            if raw.casefold() == "true":
                return True
            if raw.casefold() == "false":
                return False
            raise ValueError("Automatic user registration is misconfigured.")

        selected = values.get("RIVET_AUTH_AUTO_REGISTER_USERS")
        legacy = values.get("AZURE_ENTRAID_AUTO_REGISTER_USERS")
        if (
            selected is not None
            and legacy is not None
            and parse_bool(selected) != parse_bool(legacy)
        ):
            raise ValueError("Automatic user registration settings conflict.")
        registration = selected if selected is not None else legacy
        auto_register = True if registration is None else parse_bool(registration)
        return cls(provider, auto_register, *settings)
