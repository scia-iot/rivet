"""Authenticate through the selected identity provider."""

from sciaiot.rivet.application.authentication import (
    IdentityProvider,
    VerifiedIdentity,
)


class AuthenticationService:
    """Application boundary for provider-verified identities."""

    def __init__(self, provider: IdentityProvider) -> None:
        """Use the provider selected for this application lifecycle."""
        self.provider = provider

    def authenticate(self, token: str) -> VerifiedIdentity:
        """Verify a token and return only normalized identity facts."""
        return self.provider.authenticate(token)

    def close(self) -> None:
        """Close the selected provider on application shutdown."""
        self.provider.close()
