from dataclasses import dataclass

""" NodeID:

This class stores node information for a given node on the network.

Attributes:
    public_key: str
    ip_address: str
    port: int
    timestamp: int
    id: str
"""


@dataclass(frozen=True)
class NodeID:
    public_key: str
    ip_address: str
    port: int
    timestamp: int
    id: str
