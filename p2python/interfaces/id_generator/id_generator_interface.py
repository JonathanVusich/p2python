from abc import ABC, abstractmethod
from ..node_id.node_id_interface import NodeIDInterface

""" IDGeneratorInterface:

This is the interface for the IDGenerator implementation in the network.

Extra helper methods can be added to your IDGenerator class
by substituting a custom IDGenerator class for the base IDGenerator class.
"""


class IDGeneratorInterface(ABC):
    hash_generator: object
    _nonce = 0
    _public_key = None
    _public_key_bytes = None
    _ip_address = None
    _ip_address_bytes = None
    _port = None
    _port_bytes = None

    @property
    def public_key(self):
        return self._public_key

    @property
    def ip_address(self):
        return self._ip_address

    @property
    def port(self):
        return self._port

    @property
    def nonce(self):
        return self._nonce

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
    def ready(self) -> bool:
        pass

    @abstractmethod
    def generate_id(self) -> NodeIDInterface:
        pass
