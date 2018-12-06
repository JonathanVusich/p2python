from .node_id import NodeID
from ..interfaces.id_generator.id_generator_interface import IDGeneratorInterface
from .utils import verify_public_key, remove_0x_prefix, add_0x_prefix

from hashlib import shake_256
import logging

logger = logging.getLogger("p2python.crypto.id_generator")

""" IDGenerator:

This class is the base ID generator for the p2python stack. 


Functions:  add_public_key
            add_ip_address
            add_port
            generate_id -> NodeID
"""


class IDGenerator(IDGeneratorInterface):
    hash_generator = shake_256()

    def add_public_key(self, public_key: str):
        if verify_public_key(public_key):
            self._public_key = bytes.fromhex(remove_0x_prefix(public_key))
        else:
            logger.error("Invalid public key!")
            raise ValueError

    def add_ip_address(self, ip_address: str):
        if not isinstance(ip_address, str):
            logger.error("IP address is not of type 'str'!")
            raise ValueError
        self._ip_address = ip_address.encode()

    def add_port(self, port: int):
        if not isinstance(port, int):
            logger.error("Port is not of type 'int'!")
            raise ValueError
        self._port = str(port).encode()

    def generate_id(self):
        pass
