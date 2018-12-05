import pytest
from p2python.crypto.id_generator import IDGenerator

def test_id_generator_init():
    id_gen = IDGenerator()
    assert not id_gen._public_key
    assert not id_gen._ip_address
    assert not id_gen._port


def test_id_generator_add_public_key_well_formed():
    public_key = "0xc0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d54979"
    id_gen = IDGenerator()
    id_gen.add_public_key(public_key)
    assert id_gen._public_key == b'\xc0\xff\xee%G))jE\xa3\x88V9\xac~\x10\xf9\xd5IyE\xa3\x88V9\xac~\x10\xf9\xd5Iy'


def test_id_generator_add_public_key_invalid_public_key():
    public_key = "0xc0ffee254729296a45a3885639AC7E10F9d54979t5a3885639AC7E10F9d54979"
    id_gen = IDGenerator()
    with pytest.raises(ValueError):
        id_gen.add_public_key(public_key)
    assert not id_gen._public_key


def test_id_generator_add_ip_address_well_formed():
    ip_address = "104.218.67.207"
    id_gen = IDGenerator()
    id_gen.add_ip_address(ip_address)
    assert id_gen._ip_address == b'104.218.67.207'


def test_id_generator_add_ip_address_poorly_formed_int():
    ip_address = 12345
    id_gen = IDGenerator()
    with pytest.raises(ValueError):
        id_gen.add_ip_address(ip_address)
    assert not id_gen._ip_address


def test_id_generator_add_port_well_formed():
    port = 65536
    id_gen = IDGenerator()
    id_gen.add_port(port)
    assert id_gen._port == b'65536'


def test_id_generator_add_port_invalid_port_as_string():
    port = "65536"
    id_gen = IDGenerator()
    with pytest.raises(ValueError):
        id_gen.add_port(port)
    assert not id_gen._port