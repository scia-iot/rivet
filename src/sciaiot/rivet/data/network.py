from datetime import datetime

from sqlmodel import Field, SQLModel

BROADCAST_ADDRESS = "255.255.255.255"


class RestrictedNetwork(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    source_name: str
    source_virtual_address: str
    destination_name: str
    destination_virtual_address: str
    private_network_addresses: str
    start_time: datetime
    end_time: datetime | None = None

    def iptable_rules(self):
        return [
            f"-i tun0 -s {self.source_virtual_address} -d {self.destination_virtual_address} -j ACCEPT",
            f"-i tun0 -s {self.destination_virtual_address} -d {self.source_virtual_address} -j ACCEPT",
        ]

    def private_iptable_rules(self):
        rules = []
        for address in self.private_network_addresses.split(","):
            rules.append(
                f"-i tun0 -s {self.source_virtual_address} -d {address} -j ACCEPT"
            )
            rules.append(
                f"-i tun0 -s {address} -d {self.source_virtual_address} -j ACCEPT"
            )
        return rules

    def push_routes(self, gateway_ip: str):
        routes = []
        for address in self.private_network_addresses.split(","):
            routes.append(f"{address} {BROADCAST_ADDRESS} {gateway_ip}")
        return routes
