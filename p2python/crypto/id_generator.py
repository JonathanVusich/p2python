from .node_id import NodeID
from ..interfaces.id_generator.id_generator_interface import IDGeneratorInterface
from .utils import verify_public_key, remove_0x_prefix, add_0x_prefix, validate_id_digest

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
            self._public_key = public_key
            self._public_key_bytes = bytes.fromhex(remove_0x_prefix(public_key))
        else:
            logger.error("Invalid public key!")
            raise ValueError

    def add_ip_address(self, ip_address: str):
        if not isinstance(ip_address, str):
            logger.error("IP address is not of type 'str'!")
            raise ValueError
        self._ip_address = ip_address
        self._ip_address_bytes = ip_address.encode()

    def add_port(self, port: int):
        if not isinstance(port, int):
            logger.error("Port is not of type 'int'!")
            raise ValueError
        self._port = port
        self._port_bytes = str(port).encode()

    def ready(self):
        if not self._public_key_bytes:
            logger.warning("No public key set!")
            return False
        if not self._ip_address_bytes:
            logger.warning("No IP address set!")
            return False
        if not self._port_bytes:
            logger.warning("No port set!")
            return False
        return True

    def generate_id(self):
        """
        TODO: This method will eventually need to be rewritten in Cython.
        TODO: This method will need to incorporate some kind of node count history tracker to prove ID generation time.
        :return: NodeIDInterface
        """
        self._nonce = 0
        if not self.ready():
            logger.error("ID generator does not have all of the correct fields set!")
            raise ValueError
        base_hash_string = b"".join([self._public_key_bytes, self._ip_address_bytes, self._port_bytes])
        while True:
            hash_string = b"".join([base_hash_string, str(self._nonce).encode()])
            self.hash_generator.update(hash_string)
            digest = self.hash_generator.digest(256)
            if validate_id_digest(digest):
                break
            self._nonce += 1
        return NodeID(self.public_key, self.ip_address, self.port, self._nonce, digest)
