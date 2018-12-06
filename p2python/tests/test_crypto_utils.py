import pytest
from p2python.crypto.utils import *


def test_verify_public_key_well_formed():
    assert verify_public_key("0xc0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d54979")


def test_verify_public_key_too_long_67_bytes():
    assert not verify_public_key("0xc0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d549792")


def test_verify_public_key_too_short_63_bytes():
    assert not verify_public_key("0xc0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d54")


def test_verify_public_key_no_prefix_well_formed():
    assert verify_public_key("c0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d54979")


def test_verify_public_key_no_prefix_too_long_65_bytes():
    assert not verify_public_key("c0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d549791")


def test_verify_public_key_no_prefix_too_short_63_bytes():
    assert not verify_public_key("c0ffee2547292965a3885639AC7E10F9d5497945a3885639AC7E10F9d549791")


def test_verify_public_key_invalid_hex_string():
    assert not verify_public_key("c0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d5497p")


def test_remove_0x_prefix_has_prefix():
    public_key = remove_0x_prefix("0xc0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d54979")
    assert not public_key.startswith("0x")
    assert public_key == "c0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d54979"


def test_remove_0x_no_prefix():
    public_key = remove_0x_prefix("c0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d54979")
    assert not public_key.startswith("0x")
    assert public_key == "c0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d54979"


def test_add_0x_prefix_no_prefix():
    public_key = add_0x_prefix("c0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d54979")
    assert public_key.startswith("0x")
    assert public_key == "0xc0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d54979"


def test_add_0x_prefix_has_prefix():
    public_key = add_0x_prefix("0xc0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d54979")
    assert public_key.startswith("0x")
    assert public_key == "0xc0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d54979"
