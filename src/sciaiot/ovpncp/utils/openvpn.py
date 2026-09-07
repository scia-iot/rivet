import contextlib
import logging
import os
import re
import subprocess
import zipfile
from dataclasses import dataclass
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

CLIENT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")
CLIENT_NAME_MAX_LENGTH = 255

status_pattern = re.compile(r"(.*?)Active: (.*?) since (.*?); (.*?) ago")
client_pattern = re.compile(r"(\w+),(\d+\.\d+\.\d+\.\d+)")
default = "N/A"
openvpn_dir = "/etc/openvpn"
openvpn_log_dir = "/var/log/openvpn"
easyrsa_dir = f"{openvpn_dir}/easy-rsa"


def is_valid_name(name: str) -> bool:
    """Return whether a name is safe and fits persisted entity limits."""
    return (
        0 < len(name) <= CLIENT_NAME_MAX_LENGTH
        and CLIENT_NAME_PATTERN.fullmatch(name) is not None
    )


def validate_name(name: str) -> None:
    """Reject names outside the safe OpenVPN client-name domain."""
    if not is_valid_name(name):
        logger.error(f"Invalid name '{name}' provided!")
        raise ValueError(f"Invalid name '{name}' provided!")


def get_server_config():
    """Get the status of the OpenVPN server."""

    logger.info("Reading OpenVPN server configuration...")
    config = {}

    with open(f"{openvpn_dir}/server.conf", "r") as file:
        for line in file:
            # Strip leading and trailing whitespace
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith(("#", ";")):
                continue

            # Split the line into key and value
            parts = line.split(None, 1)
            # replace all - with _
            key = parts[0].replace("-", "_")
            value = parts[1] if len(parts) > 1 else True
            config[key] = value

    logger.info("OpenVPN server configuration read successfully.")
    return config


def get_status():
    """Get the status of the OpenVPN server."""

    logger.info("Checking the status of OpenVPN server...")
    try:
        result = subprocess.run(
            ["systemctl", "status", "openvpn"],
            capture_output=True,
            text=True,
            check=True,
        )
        output = result.stdout
    except subprocess.CalledProcessError as e:
        output = e.stdout

    openvpn_service = {"status": default}
    match = status_pattern.search(output)
    if match:
        openvpn_service = {
            "status": match.group(2),
            "time": match.group(3),
            "period": match.group(4),
        }

        logger.info(f"OpenVPN server status: {openvpn_service['status']}")
    else:
        logger.error("Failed to parse the output of systemctl status openvpn!")

    return openvpn_service


def build_client(name: str):
    """Build a client with the given name."""

    validate_name(name)
    logger.info(f"Building client {name}...")
    result = subprocess.run(
        ["./easyrsa", "--batch", "build-client-full", name, "nopass"],
        cwd=easyrsa_dir,
        shell=False,
        check=True,
    )

    if result.returncode == 0:
        logger.info(f"Client {name} has been successfully built to OpenVPN server.")
        return True
    else:
        logger.error(f"Failed to build client {name} to OpenVPN server!")
        return False


def read_client_cert(name: str) -> dict:
    """Read the client certificate for the given client name and extract issued and expired times, issued_to, and issued_by."""

    validate_name(name)
    try:
        logger.info(f"Reading certificate for client {name}...")
        cert_path = os.path.join(easyrsa_dir, "pki", "issued", f"{name}.crt")

        with open(cert_path, "rb") as file:
            cert_content = file.read()
            cert = x509.load_pem_x509_certificate(cert_content, default_backend())
            issued_by = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            issued_to = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
                0
            ].value
            issued_on = cert.not_valid_before_utc
            expires_on = cert.not_valid_after_utc

            logger.info(f"Successfully read certificate for client {name}.")
            return {
                "issued_by": issued_by,
                "issued_to": issued_to,
                "issued_on": issued_on,
                "expires_on": expires_on,
            }
    except (IndexError, OSError, ValueError):
        logger.error(f"Failed to read certificate for client {name}.")
        return {}


def package_client_cert(name: str, output_dir: str):
    """Package the client certificate and key files into a tar archive."""

    validate_name(name)
    cert_dir = f"{easyrsa_dir}/pki"
    ca = f"{cert_dir}/ca.crt"
    pk = f"{cert_dir}/private/{name}.key"
    cert = f"{cert_dir}/issued/{name}.crt"
    archive = os.path.join(output_dir, f"{name}.zip")

    with contextlib.suppress(FileNotFoundError):
        os.remove(archive)

    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as file:
        file.write(ca, arcname=os.path.basename(ca))
        file.write(pk, arcname=os.path.basename(pk))
        file.write(cert, arcname=os.path.basename(cert))

    logger.info(f"Successfully packaged client {name} certificate.")
    return archive


def renew_client_cert(name: str) -> dict:
    """Renew the client certificate for the given client name and read the renewed certificate details."""

    validate_name(name)
    logger.info(f"Renewing client {name} certificate...")
    result = subprocess.run(
        ["./easyrsa", "--batch", "revoke-renewed", name],
        cwd=easyrsa_dir,
        shell=False,
        check=True,
    )

    if result.returncode == 0:
        logger.info(f"Client {name} certificate has been successfully renewed.")
        cert_details = read_client_cert(name)
        return cert_details
    else:
        logger.error(f"Failed to renew client {name} certificate!")
        return {}


def revoke_client(name: str):
    """Revoke the client certificate for the given client name and generate a new CRL to confirm the revocation."""

    validate_name(name)
    logger.info(f"Revoking client {name}...")
    result = subprocess.run(
        ["./easyrsa", "--batch", "revoke", name],
        cwd=easyrsa_dir,
        shell=False,
        check=True,
    )

    if result.returncode == 0:
        logger.info(f"Client {name} has been successfully revoked.")
        return True
    else:
        logger.error(f"Failed to revoke client {name}!")
        return False


def generate_crl() -> bool:
    """Generate a new CRL."""
    logger.info("Generating CRL...")
    result = subprocess.run(
        ["./easyrsa", "--batch", "gen-crl"],
        cwd=easyrsa_dir,
        shell=False,
        check=True,
    )

    if result.returncode == 0:
        logger.info("CRL generated successfully.")
        return True
    else:
        logger.error("Failed to generate CRL.")
        return False


def assign_client_ip(name: str, ip: str, subnet_mask: str):
    """Add a client with the given name and IP address to the OpenVPN server."""

    validate_name(name)
    logger.info(f"Adding a virtual address for client {name}...")

    config_path = os.path.join(openvpn_dir, "ccd", name)
    with open(config_path, "w") as file:
        file.write(f"ifconfig-push {ip} {subnet_mask}\n")

    logger.info(f"Virtual address for client {name} added successfully.")


def unassign_client_ip(name: str):
    """Remove a client with the given name and IP address from the OpenVPN server."""

    validate_name(name)
    logger.info(f'Removing client "{name}" IP from OpenVPN server...')

    config_path = os.path.join(openvpn_dir, "ccd", name)
    if os.path.exists(config_path):
        os.remove(config_path)

    logger.info(
        f'Client "{name}" IP has been successfully removed from OpenVPN server.'
    )


def read_client_ip(name: str) -> str | None:
    """Read the assigned IP address for the given client from its ccd file."""

    logger.info(f'Reading assigned IP for client "{name}" from ccd...')
    config_path = f"{openvpn_dir}/ccd/{name}"

    if not os.path.exists(config_path):
        logger.info(f'No ccd file found for client "{name}".')
        return None

    try:
        with open(config_path, "r") as file:
            for line in file:
                if line.startswith("ifconfig-push"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
    except OSError:
        logger.error(f'Failed to read ccd file for client "{name}".')

    return None


def add_iroute(name: str, rule: str):
    """Add a route to the OpenVPN server."""

    validate_name(name)
    logger.info(f"Adding route to OpenVPN server for client {name}...")
    config_path = os.path.join(openvpn_dir, "ccd", name)
    with open(config_path, "a") as file:
        file.write(f"iroute {rule}\n")
    logger.info(
        f"Route to OpenVPN server for client {name} has been successfully added."
    )


def remove_iroute(name: str, rule: str):
    """Remove a specific route from the OpenVPN server for a client."""

    validate_name(name)
    logger.info(f"Removing route from OpenVPN server for client {name}...")

    file_path = os.path.join(openvpn_dir, "ccd", name)
    with open(file_path, "r") as file:
        lines = file.readlines()

    updated_lines = [line for line in lines if not line.startswith(f"iroute {rule}\n")]
    with open(file_path, "w") as file:
        file.writelines(updated_lines)

    logger.info(
        f"Route from OpenVPN server for client {name} has been successfully removed."
    )


def push_client_routes(name: str, rules: list[str]):
    """Push a list of routes to the OpenVPN client."""

    validate_name(name)
    logger.info(f"Pushing route to OpenVPN client {name}...")
    config_path = os.path.join(openvpn_dir, "ccd", name)
    with open(config_path, "a") as file:
        file.writelines(f'push "route {rule}"\n' for rule in rules)
    logger.info(f"Pushed {len(rules)} routes to OpenVPN client {name}.")


def pull_client_routes(name: str):
    """Pull all routes from the OpenVPN client."""

    validate_name(name)
    logger.info(f"Pulling routes from OpenVPN client {name}...")

    file_path = os.path.join(openvpn_dir, "ccd", name)
    with open(file_path, "r") as file:
        lines = file.readlines()

    updated_lines = [line for line in lines if not line.startswith('push "route')]
    with open(file_path, "w") as file:
        file.writelines(updated_lines)

    logger.info(f"Pulled all routes from OpenVPN client {name}.")


def client_is_revoked(name: str) -> bool:
    """Return whether the durable Easy-RSA CA index revokes a client name.

    Args:
        name: Validated OpenVPN client name.

    Returns:
        True when an exact revoked common name exists in the CA index. Missing
        or unreadable index data returns False because certificate discovery
        still excludes deleted issued files.
    """
    validate_name(name)
    index_path = os.path.join(easyrsa_dir, "pki", "index.txt")
    try:
        with open(index_path, "r") as index:
            for line in index:
                fields = line.rstrip("\n").split("\t")
                if not fields or fields[0] != "R":
                    continue
                common_name = re.search(r"(?:^|/)CN=([^/]+)", fields[-1])
                if common_name is not None and common_name.group(1) == name:
                    return True
    except OSError:
        logger.error("Failed to read the Easy-RSA certificate index.")
    return False


@dataclass
class StagedClientFileRemoval:
    """Reversible set of client files moved out of operational locations."""

    paths: list[tuple[str, str]]

    def restore(self) -> None:
        """Restore staged files after a database or staging failure."""
        for original, staged in reversed(self.paths):
            if os.path.exists(staged):
                os.replace(staged, original)

    def discard(self) -> None:
        """Permanently remove staged files after the database commit."""
        first_error: OSError | None = None
        for _original, staged in self.paths:
            try:
                os.remove(staged)
            except FileNotFoundError:
                continue
            except OSError as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error


def stage_client_file_removal(
    name: str,
    archive_directory: str,
) -> StagedClientFileRemoval:
    """Move client artifacts aside without altering CA revocation evidence.

    The Easy-RSA index, serial records, CA material, and CRL are deliberately
    absent from the target set. A partial failure restores every file already
    moved before re-raising the system error.

    Args:
        name: Validated OpenVPN client name.
        archive_directory: Trusted local package directory.

    Returns:
        A staged removal that can be restored or permanently discarded.

    Raises:
        OSError: If an existing client file cannot be staged or restored.
        ValueError: If the client name is unsafe.
    """
    validate_name(name)
    pki_directory = os.path.join(easyrsa_dir, "pki")
    targets = [
        os.path.join(openvpn_dir, "ccd", name),
        os.path.join(pki_directory, "issued", f"{name}.crt"),
        os.path.join(pki_directory, "private", f"{name}.key"),
        os.path.join(pki_directory, "reqs", f"{name}.req"),
        os.path.join(pki_directory, "inline", f"{name}.inline"),
        os.path.join(archive_directory, f"{name}.zip"),
    ]
    token = uuid4().hex
    removal = StagedClientFileRemoval(paths=[])
    try:
        for original in targets:
            if not os.path.exists(original):
                continue
            staged = f"{original}.ovpncp-delete-{token}"
            os.replace(original, staged)
            removal.paths.append((original, staged))
    except OSError:
        removal.restore()
        raise
    return removal


def list_client_certs() -> list[str]:
    """List all client certificate names from the Easy-RSA issued directory."""

    logger.info("Listing all client certificates from Easy-RSA...")
    issued_dir = f"{easyrsa_dir}/pki/issued"
    try:
        files = os.listdir(issued_dir)
        # Extract the name without the .crt extension, excluding 'server'
        names = [
            os.path.splitext(f)[0]
            for f in files
            if f.endswith(".crt") and f != "server.crt"
        ]
        logger.info(f"Found {len(names)} client certificate(s).")
        return names
    except OSError:
        logger.error("Failed to list client certificates.")
        return []


def list_connections():
    """List the connections made by the clients to the OpenVPN server."""

    logger.info("Retrieving the list of connections from OpenVPN server...")
    with open(f"{openvpn_log_dir}/openvpn-status.log", "r") as file:
        lines = file.read().splitlines()
        client_list_start = lines.index("OpenVPN CLIENT LIST")
        routing_table_start = lines.index("ROUTING TABLE")
        global_stats_start = lines.index("GLOBAL STATS")

        connections = []
        for i in range(client_list_start + 3, routing_table_start):
            client_info = lines[i].split(",")
            client_name = client_info[0]
            remote_address = client_info[1]
            connected_time = client_info[4]
            virtual_address = None

            for j in range(routing_table_start + 2, global_stats_start):
                route_info = lines[j].split(",")
                if route_info[1] == client_name:
                    virtual_address = route_info[0]
                    break

            if virtual_address:
                connections.append(
                    {
                        "name": client_name,
                        "ip": virtual_address,
                        "remote_address": remote_address,
                        "connected_time": connected_time,
                    }
                )

        logger.info(f"Found {len(connections)} connection(s) from OpenVPN server.")
        return connections
