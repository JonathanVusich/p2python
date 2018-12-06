from abc import ABC, abstractmethod
from ..node_id.node_id_interface import NodeIDInterface

""" IDGeneratorInterface:

This is the interface for the IDGenerator implementation in the network.

Extra helper methods can be added to your IDGenerator class
by substituting a custom IDGenerator class for the base IDGenerator class.
"""


class IDGeneratorInterface(ABC):
    hash_generator: object
    nonce = 0
    _public_key = None
    _ip_address = None
    _port = None

    @abstractmethod
    def add_public_key(self, public_key: str) -> None:
        pass

    @abstractmethod
    def add_ip_address(self, ip_address: str) -> None:
        pass

    @abstractmethod
    def add_port(self, port: int) -> None:
        pass

    @abstractmethod
    def generate_id(self) -> NodeIDInterface:
        pass
