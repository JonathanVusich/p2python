import pytest
from p2python.crypto.id_generator import IDGenerator

def test_id_generator_init():
    id_gen = IDGenerator()
    assert not id_gen._public_key
    assert not id_gen._ip_address
    assert not id_gen._port
    assert not id_gen._public_key_bytes
    assert not id_gen._ip_address_bytes
    assert not id_gen._port_bytes
    assert id_gen._nonce == 0


def test_id_generator_add_public_key_well_formed():
    public_key = "0xc0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d54979"
    id_gen = IDGenerator()
    id_gen.add_public_key(public_key)
    assert id_gen._public_key_bytes == b'\xc0\xff\xee%G))jE\xa3\x88V9\xac~\x10\xf9\xd5IyE\xa3\x88V9\xac~\x10\xf9\xd5Iy'
    assert id_gen.public_key == "0xc0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d54979"


def test_id_generator_add_public_key_invalid_public_key():
    public_key = "0xc0ffee254729296a45a3885639AC7E10F9d54979t5a3885639AC7E10F9d54979"
    id_gen = IDGenerator()
    with pytest.raises(ValueError):
        id_gen.add_public_key(public_key)
    assert not id_gen.public_key
    assert not id_gen._public_key_bytes


def test_id_generator_add_ip_address_well_formed():
    ip_address = "104.218.67.207"
    id_gen = IDGenerator()
    id_gen.add_ip_address(ip_address)
    assert id_gen._ip_address_bytes == b'104.218.67.207'
    assert id_gen.ip_address == "104.218.67.207"


def test_id_generator_add_ip_address_poorly_formed_int():
    ip_address = 12345
    id_gen = IDGenerator()
    with pytest.raises(ValueError):
        id_gen.add_ip_address(ip_address)
    assert not id_gen.ip_address
    assert not id_gen._ip_address_bytes


def test_id_generator_add_port_well_formed():
    port = 65536
    id_gen = IDGenerator()
    id_gen.add_port(port)
    assert id_gen._port_bytes == b'65536'
    assert id_gen.port == 65536


def test_id_generator_add_port_invalid_port_as_string():
    port = "65536"
    id_gen = IDGenerator()
    with pytest.raises(ValueError):
        id_gen.add_port(port)
    assert not id_gen._port_bytes
    assert not id_gen.port


def test_id_generator_ready_yes():
    id_gen = IDGenerator()
    id_gen.add_public_key("0xc0fffe254739296a45a2885639AC7E10F9d5497945a3875639AC7E10F9d54989")
    id_gen.add_ip_address("104.218.67.207")
    id_gen.add_port(65536)
    assert id_gen.ready()


def test_id_generator_ready_missing_public_key():
    id_gen = IDGenerator()
    id_gen.add_ip_address("104.218.67.207")
    id_gen.add_port(65536)
    assert not id_gen.ready()


def test_id_generator_ready_missing_ip_address():
    id_gen = IDGenerator()
    id_gen.add_public_key("0xc0fffe254739296a45a2885639AC7E10F9d5497945a3875639AC7E10F9d54989")
    id_gen.add_port(65536)
    assert not id_gen.ready()


def test_id_generator_ready_missing_port():
    id_gen = IDGenerator()
    id_gen.add_public_key("0xc0fffe254739296a45a2885639AC7E10F9d5497945a3875639AC7E10F9d54989")
    id_gen.add_ip_address("104.218.67.207")
    assert not id_gen.ready()


def test_id_generator_generate_id_missing_information():
    id_gen = IDGenerator()
    id_gen.add_public_key("0xc0fffe254739296a45a2885639AC7E10F9d5497945a3875639AC7E10F9d54989")
    id_gen.add_ip_address("104.218.67.207")
    with pytest.raises(ValueError):
        id = id_gen.generate_id()


def test_id_generator_generate_id_well_formed():
    gen = IDGenerator()
    gen.add_public_key("0xc0fffe254729295a45a2885639AC7E10F9d5497945a3875639AC7E10F9d54989")
    gen.add_ip_address("104.218.67.207")
    gen.add_port(65536)
    id = gen.generate_id()
    assert id.public_key == "0xc0fffe254729295a45a2885639AC7E10F9d5497945a3875639AC7E10F9d54989"
    assert id.ip_address == "104.218.67.207"
    assert id.port == 65536
    assert id.nonce == 682425
    assert id.id == b'\x00\x00\x01\x93\x96\xd8\t@\xe4\x9f\x9eC\xfc\r\x08\x16L)' \
                    b'\x95\x99\xe3\xcb\x1c\xa0\xaf\xdcc\xde\xff\x9ftq6\xcao\x94' \
                    b'\x01\xd1\xfd\xe1YT\x83\xd9$\xfb\x96]\xa5uq\xc6\xd2\xd1\xd2' \
                    b'\x8d=\x04\x05-v\x05$\xc5\xfd\xf8pp\x1c\xb8\xb5i\xed\x1d?\x94' \
                    b'\x0fHNVO\xffv\x0clC\x81\x1d\xdb\xd9\x91\xbc\x90\x0e\n2o\x977' \
                    b'\x00\x81\xdf\xac\xb1\xa6\xd1<\x0b\xdaMu\xb4o@\x80\xc2\xc3\xb7' \
                    b'\x96\x8e\xafx\xfc\x0c\xb2\x84\xae\xe7\x99U\xa3\x9c\x10\x7f\xe3' \
                    b'\xc2\xbc\xfd\xaf\nJ\xa5\x1e\xd9TEd\xf2\x06\x06pN\xae}\xe0\xaa' \
                    b'\xdf\xd5\xe1N|~s</%\xdfQ\xeb\xa6\xec]\xf4\x7f*\xde\xaf\x8a\x9b' \
                    b'\xae\xf2\xb0\x8be\xae\x00\x9a"%\x81\x99?\xf6\xb0\x89\x92\x85\xea' \
                    b'\xa3f\xf2\x82T\xa9\xd8\x8eC\xbc\xb1.?\xfe?,\x9c3\xbc\xf0\x8e\x85E6' \
                    b'\xce\xe8\xe2\xa9-\xd4\x14\xa8#\x9e\xad\xc5*\x881\x8c*\xcc\xe9H\xbd}' \
                    b'\x92\xec\xe4\xacl\xd38\xf1\xafu_B'
