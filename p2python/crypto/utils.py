import logging

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
