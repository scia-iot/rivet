"""Provider-independent verified identities and authentication failures."""

from dataclasses import dataclass
from typing import Literal, Protocol

CanonicalRole = Literal["device_user", "sysadmin", "service_admin"]
IdentityKind = Literal["human", "service"]


@dataclass(frozen=True)
class VerifiedIdentity:
    """Identity facts established by a selected provider's token verifier."""

    issuer: str
    subject: str
    role: CanonicalRole
    kind: IdentityKind
    display_name: str


class IdentityProvider(Protocol):
    """Verify one access token without exposing provider-specific claims."""

    def authenticate(self, token: str) -> VerifiedIdentity:
        """Return a verified identity or raise a safe authentication error."""

    def close(self) -> None:
        """Release resources owned by the provider."""


class AuthenticationError(Exception):
    """A safe, caller-facing authentication or authorization failure."""

    def __init__(self, status_code: int, detail: str) -> None:
        """Keep only an HTTP status and a credential-free explanation."""
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
