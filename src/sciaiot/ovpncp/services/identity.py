"""Business operations for users, devices, and access grants."""

from sqlmodel import Session, select

from sciaiot.ovpncp.data.identity import (
    AccessGrant,
    Device,
    DeviceBase,
    DeviceUpdate,
    User,
    UserBase,
    UserClient,
    UserUpdate,
)
from sciaiot.ovpncp.data.server import Client


class EntityNotFoundError(Exception):
    """Raised when a requested domain entity does not exist."""


class EntityConflictError(Exception):
    """Raised when a domain uniqueness rule would be violated."""


class DeviceService:
    """Manage stable device identities and their current VPN clients."""

    def __init__(self, session: Session) -> None:
        """Initialize the service.

        Args:
            session: Active database session.
        """
        self.session = session

    def create(self, request: DeviceBase) -> Device:
        """Register a device, optionally linked to a VPN client.

        Args:
            request: Device registration values.

        Returns:
            The persisted device.

        Raises:
            EntityNotFoundError: If the requested VPN client does not exist.
            EntityConflictError: If the name or VPN client is already used.
        """
        if self.session.exec(select(Device).where(Device.name == request.name)).first():
            raise EntityConflictError(f'Device "{request.name}" already exists.')

        if request.client_id is not None:
            if self.session.get(Client, request.client_id) is None:
                raise EntityNotFoundError(
                    f"Client with ID {request.client_id} not found."
                )
            if self.session.exec(
                select(Device).where(Device.client_id == request.client_id)
            ).first():
                raise EntityConflictError(
                    f"Client with ID {request.client_id} is already assigned."
                )

        device = Device.model_validate(request)
        self.session.add(device)
        self.session.commit()
        self.session.refresh(device)
        return device

    def get(self, device_id: int) -> Device:
        """Return a device by ID.

        Args:
            device_id: Device primary key.

        Returns:
            The matching device.

        Raises:
            EntityNotFoundError: If the device does not exist.
        """
        device = self.session.get(Device, device_id)
        if device is None:
            raise EntityNotFoundError(f"Device with ID {device_id} not found.")
        return device

    def list(self) -> list[Device]:
        """Return all registered devices."""
        return list(self.session.exec(select(Device)).all())

    def update(self, device_id: int, request: DeviceUpdate) -> Device:
        """Update a device's display name or current VPN client."""
        device = self.get(device_id)
        if request.name is not None and request.name != device.name:
            if self.session.exec(
                select(Device).where(Device.name == request.name)
            ).first():
                raise EntityConflictError(f'Device "{request.name}" already exists.')
            device.name = request.name
        if (
            "client_id" in request.model_fields_set
            and request.client_id != device.client_id
        ):
            if request.client_id is not None:
                if self.session.get(Client, request.client_id) is None:
                    raise EntityNotFoundError(
                        f"Client with ID {request.client_id} not found."
                    )
                assigned = self.session.exec(
                    select(Device).where(Device.client_id == request.client_id)
                ).first()
                if assigned is not None:
                    raise EntityConflictError(
                        f"Client with ID {request.client_id} is already assigned."
                    )
            device.client_id = request.client_id
        self.session.add(device)
        self.session.commit()
        self.session.refresh(device)
        return device

    def delete(self, device_id: int) -> None:
        """Delete a device without deleting its VPN client."""
        device = self.get(device_id)
        grants = self.session.exec(
            select(AccessGrant).where(AccessGrant.device_id == device_id)
        ).all()
        for grant in grants:
            self.session.delete(grant)
        self.session.delete(device)
        self.session.commit()


class UserService:
    """Manage local users backed by external OAuth identities."""

    def __init__(self, session: Session) -> None:
        """Initialize the service.

        Args:
            session: Active database session.
        """
        self.session = session

    def create(self, request: UserBase) -> User:
        """Create a local user.

        Args:
            request: External identity and display values.

        Returns:
            The persisted user.

        Raises:
            EntityConflictError: If the external identity already exists.
        """
        statement = select(User).where(
            User.issuer == request.issuer,
            User.subject == request.subject,
        )
        if self.session.exec(statement).first():
            raise EntityConflictError("External identity already exists.")

        user = User.model_validate(request)
        self.session.add(user)
        self.session.commit()
        self.session.refresh(user)
        return user

    def get(self, user_id: int) -> User:
        """Return a user by ID.

        Args:
            user_id: User primary key.

        Returns:
            The matching user.

        Raises:
            EntityNotFoundError: If the user does not exist.
        """
        user = self.session.get(User, user_id)
        if user is None:
            raise EntityNotFoundError(f"User with ID {user_id} not found.")
        return user

    def get_by_external_identity(self, issuer: str, subject: str) -> User:
        """Return the local user mapped to a validated external identity.

        Args:
            issuer: Validated token issuer.
            subject: Validated stable subject identifier.

        Returns:
            The uniquely mapped local user.

        Raises:
            EntityNotFoundError: If the identity is not registered locally.
        """
        statement = select(User).where(
            User.issuer == issuer,
            User.subject == subject,
        )
        user = self.session.exec(statement).first()
        if user is None:
            raise EntityNotFoundError(
                "The signed-in identity is not registered for this application."
            )
        return user

    def list(self) -> list[User]:
        """Return all local users."""
        return list(self.session.exec(select(User)).all())

    def update(self, user_id: int, request: UserUpdate) -> User:
        """Update a user's local display name."""
        user = self.get(user_id)
        user.display_name = request.display_name
        self.session.add(user)
        self.session.commit()
        self.session.refresh(user)
        return user

    def delete(self, user_id: int) -> None:
        """Delete a user and their access grants."""
        user = self.get(user_id)
        grants = self.session.exec(
            select(AccessGrant).where(AccessGrant.user_id == user_id)
        ).all()
        clients = self.session.exec(
            select(UserClient).where(UserClient.user_id == user_id)
        ).all()
        for grant in grants:
            self.session.delete(grant)
        for client in clients:
            self.session.delete(client)
        self.session.delete(user)
        self.session.commit()


class AccessService:
    """Manage individual user access to devices."""

    def __init__(self, session: Session) -> None:
        """Initialize the service.

        Args:
            session: Active database session.
        """
        self.session = session
        self.devices = DeviceService(session)
        self.users = UserService(session)

    def grant(self, user_id: int, device_id: int) -> tuple[AccessGrant, bool]:
        """Grant a user access to a device idempotently.

        Args:
            user_id: User primary key.
            device_id: Device primary key.

        Returns:
            The grant and whether it was newly created.

        Raises:
            EntityNotFoundError: If the user or device does not exist.
        """
        self.users.get(user_id)
        self.devices.get(device_id)
        statement = select(AccessGrant).where(
            AccessGrant.user_id == user_id,
            AccessGrant.device_id == device_id,
        )
        existing = self.session.exec(statement).first()
        if existing is not None:
            return existing, False

        grant = AccessGrant(user_id=user_id, device_id=device_id)
        self.session.add(grant)
        self.session.commit()
        self.session.refresh(grant)
        return grant, True

    def revoke(self, user_id: int, device_id: int) -> None:
        """Revoke a user's access to a device.

        Args:
            user_id: User primary key.
            device_id: Device primary key.

        Raises:
            EntityNotFoundError: If the grant does not exist.
        """
        statement = select(AccessGrant).where(
            AccessGrant.user_id == user_id,
            AccessGrant.device_id == device_id,
        )
        grant = self.session.exec(statement).first()
        if grant is None:
            raise EntityNotFoundError("Access grant not found.")
        self.session.delete(grant)
        self.session.commit()

    def list_devices(self, user_id: int) -> list[Device]:
        """Return devices accessible to a user.

        Args:
            user_id: User primary key.

        Returns:
            Devices with an explicit access grant.

        Raises:
            EntityNotFoundError: If the user does not exist.
        """
        self.users.get(user_id)
        statement = (
            select(Device).join(AccessGrant).where(AccessGrant.user_id == user_id)
        )
        return list(self.session.exec(statement).all())


class UserClientService:
    """Manage administrator-controlled VPN client ownership."""

    def __init__(self, session: Session) -> None:
        """Initialize the service with an active database session."""
        self.session = session
        self.users = UserService(session)

    def link(self, user_id: int, client_id: int) -> tuple[UserClient, bool]:
        """Assign a VPN client to a user idempotently.

        Args:
            user_id: Owning user primary key.
            client_id: VPN client primary key.

        Returns:
            The assignment and whether it was newly created.

        Raises:
            EntityNotFoundError: If the user or client does not exist.
            EntityConflictError: If another user owns the client.
        """
        self.users.get(user_id)
        if self.session.get(Client, client_id) is None:
            raise EntityNotFoundError(f"Client with ID {client_id} not found.")

        existing = self.session.exec(
            select(UserClient).where(UserClient.client_id == client_id)
        ).first()
        if existing is not None:
            if existing.user_id == user_id:
                return existing, False
            raise EntityConflictError(
                f"Client with ID {client_id} is assigned to another user."
            )

        assignment = UserClient(user_id=user_id, client_id=client_id)
        self.session.add(assignment)
        self.session.commit()
        self.session.refresh(assignment)
        return assignment, True

    def unlink(self, user_id: int, client_id: int) -> None:
        """Remove a VPN client assignment from a user.

        Args:
            user_id: Owning user primary key.
            client_id: VPN client primary key.

        Raises:
            EntityNotFoundError: If the assignment does not exist.
        """
        statement = select(UserClient).where(
            UserClient.user_id == user_id,
            UserClient.client_id == client_id,
        )
        assignment = self.session.exec(statement).first()
        if assignment is None:
            raise EntityNotFoundError("User client assignment not found.")
        self.session.delete(assignment)
        self.session.commit()

    def list_clients(self, user_id: int) -> list[Client]:
        """Return all VPN clients assigned to a user.

        Args:
            user_id: Owning user primary key.

        Returns:
            The user's assigned VPN clients.

        Raises:
            EntityNotFoundError: If the user does not exist.
        """
        self.users.get(user_id)
        statement = select(Client).join(UserClient).where(UserClient.user_id == user_id)
        return list(self.session.exec(statement).all())
