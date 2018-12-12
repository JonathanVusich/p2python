import logging
from .node_id import NodeID
from hashlib import shake_256

logger = logging.getLogger("p2python.crypto.utils")


def verify_public_key(public_key: str) -> bool:
    if len(public_key) == 66:
        if not public_key.startswith("0x"):
            logger.error("Public key does not have an '0x' prefix!")
            return False
    elif not len(public_key) == 64:
        logger.error("Public key should have a length of 64 characters! Is {} characters long.".format(len(public_key)))
        return False
    try:
        int(public_key, 16)
    except ValueError:
        logger.error("Public key is not a valid hex string!")
        return False
    return True


def remove_0x_prefix(public_key: str) -> str:
    if public_key.startswith("0x"):
        return public_key[2:]
    return public_key


def add_0x_prefix(public_key: str) -> str:
    if not public_key.startswith("0x"):
        return "0x{}".format(public_key)
    return public_key


def validate_id_digest(digest: bytes) -> bool:
    if not len(digest) == 256:
        logger.error("Digest should have a length of 256! Has length of {} instead!".format(len(digest)))
        raise ValueError
    mem_view = memoryview(digest)
    for mem in mem_view[:2]:
        if not mem == 0:
            return False
    if not mem_view[2] < 2:
        return False
    return True


def generate_id(public_key: str, ip_address: str, port: int):

    # Verify public key input
    if verify_public_key(public_key):
        public_key_bytes = bytes.fromhex(remove_0x_prefix(public_key))
    else:
        logger.error("Invalid public key!")
        raise ValueError

    # Verify IP address input
    if not isinstance(ip_address, str):
        logger.error("IP address is not of type 'str'!")
        raise ValueError
    ip_address_bytes = ip_address.encode()

    # Verify port input
    if not isinstance(port, int):
        logger.error("Port is not of type 'int'!")
        raise ValueError
    port_bytes = str(port).encode()

    # Begin ID generation process
    nonce = 0
    base_hash_string = b"".join([public_key_bytes, ip_address_bytes, port_bytes])
    while True:
        hash_generator = shake_256()
        hash_string = b"".join([base_hash_string, str(nonce).encode()])
        hash_generator.update(hash_string)
        digest = hash_generator.digest(256)
        if validate_id_digest(digest):
            break
        nonce += 1
    return NodeID(public_key, ip_address, port, nonce, hash_generator.hexdigest(32))


def validate_id(node_id: NodeID) -> bool:

    if not verify_public_key(node_id.public_key):
        return False
    if not isinstance(node_id.ip_address, str):
        return False
    if not isinstance(node_id.port, int):
        return False
    if not isinstance(node_id.nonce, int):
        return False
    if not isinstance(node_id.id, str):
        return False

    hash_generator = shake_256()
    base_hash_string = b"".join([bytes.fromhex(remove_0x_prefix(node_id.public_key)), node_id.ip_address.encode(),
                                str(node_id.port).encode(), str(node_id.nonce).encode()])
    hash_generator.update(base_hash_string)
    digest = hash_generator.digest(256)
    if not validate_id_digest(digest):
        return False
    else:
        digest = hash_generator.hexdigest(32)
        if not digest == node_id.id:
            return False
    return True



