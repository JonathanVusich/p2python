import pytest
from unittest.mock import Mock
from p2python.crypto.utils import *


def test_verify_public_key_well_formed():
    assert verify_public_key("0xc0ffee254729296a45a3885639AC7E10F9d5497945a3885639AC7E10F9d54979")


def test_verify_public_key_no_prefix_66_bytes():
    assert not verify_public_key("c0ffee254729296a45a38885639AC7E10F9d5497945a3885639AC7E10F9d549792")


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


def test_validate_id_digest_invalid_length():
    digest = b"1234"
    with pytest.raises(ValueError):
        validate_id_digest(digest)


def test_validate_id_digest_invalid_leading_bytes():
    digest = b'\x00\x01\x01\x93\x96\xd8\t@\xe4\x9f\x9eC\xfc\r\x08\x16L)' \
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
    assert not validate_id_digest(digest)


def test_validate_id_digest_invalid_third_byte():
    digest = b'\x00\x00\x02\x93\x96\xd8\t@\xe4\x9f\x9eC\xfc\r\x08\x16L)' \
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
    assert not validate_id_digest(digest)


def test_validate_id_digest_well_formed():
    digest = b'\x00\x00\x01\x93\x96\xd8\t@\xe4\x9f\x9eC\xfc\r\x08\x16L)' \
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
    assert validate_id_digest(digest)


def test_generate_id_well_formed():
    public_key = "0xc0fffe254729295a45a2885639AC7E10F8d5497945a3875639AC7E10F9d54989"
    ip_address = "104.218.67.207"
    port = 65536
    node_id = generate_id(public_key, ip_address, port)
    assert node_id.public_key == "0xc0fffe254729295a45a2885639AC7E10F8d5497945a3875639AC7E10F9d54989"
    assert node_id.ip_address == "104.218.67.207"
    assert node_id.port == 65536
    assert node_id.id == "0000013320276ec11fb237e6c3bed22be1f0a08e5c0a1a9b135a803a6835da35"


def test_generate_id_bad_public_key():
    public_key = "0xc0fffe254729295a45a2885639AC7E10F95497945a3875639AC7E10F9d54989"
    ip_address = "104.218.67.207"
    port = 65536
    with pytest.raises(ValueError):
        node_id = generate_id(public_key, ip_address, port)


def test_generate_id_bad_ip_address():
    public_key = "0xc0fffe254729295a45a2885639AC7E10F9d5497945a3875639AC7E10F9d54989"
    ip_address = 12345
    port = 65536
    with pytest.raises(ValueError):
        node_id = generate_id(public_key, ip_address, port)


def test_generate_id_bad_port():
    public_key = "0xc0fffe254729295a45a2885639AC7E10F9d5497945a3875639AC7E10F9d54989"
    ip_address = "104.218.67.207"
    port = "65536"
    with pytest.raises(ValueError):
        node_id = generate_id(public_key, ip_address, port)


def test_validate_id_well_formed():
    mock_id = Mock()
    mock_id.public_key = "0xc0fffe254729295a45a2885639AC7E10F8d5497945a3875639AC7E10F9d54989"
    mock_id.ip_address = "104.218.67.207"
    mock_id.port = 65536
    mock_id.nonce = 3476617
    mock_id.id = "0000013320276ec11fb237e6c3bed22be1f0a08e5c0a1a9b135a803a6835da35"
    assert validate_id(mock_id)


def test_validate_id_bad_public_key_input():
    mock_id = Mock()
    mock_id.public_key = "0xc0ffe254729295a45a2885639AC7E10F8d5497945a3875639AC7E10F9d54989"
    mock_id.ip_address = "104.218.67.207"
    mock_id.port = 65536
    mock_id.nonce = 3476617
    mock_id.id = "0000013320276ec11fb237e6c3bed22be1f0a08e5c0a1a9b135a803a6835da35"
    assert not validate_id(mock_id)


def test_validate_id_bad_ip_address_input():
    mock_id = Mock()
    mock_id.public_key = "0xc0fffe254729295a45a2885639AC7E10F8d5497945a3875639AC7E10F9d54989"
    mock_id.ip_address = 12345
    mock_id.port = 65536
    mock_id.nonce = 3476617
    mock_id.id = "0000013320276ec11fb237e6c3bed22be1f0a08e5c0a1a9b135a803a6835da35"
    assert not validate_id(mock_id)


def test_validate_id_bad_port_input():
    mock_id = Mock()
    mock_id.public_key = "0xc0fffe254729295a45a2885639AC7E10F8d5497945a3875639AC7E10F9d54989"
    mock_id.ip_address = "104.218.67.207"
    mock_id.port = "65536"
    mock_id.nonce = 3476617
    mock_id.id = "0000013320276ec11fb237e6c3bed22be1f0a08e5c0a1a9b135a803a6835da35"
    assert not validate_id(mock_id)


def test_validate_id_bad_nonce_input():
    mock_id = Mock()
    mock_id.public_key = "0xc0fffe254729295a45a2885639AC7E10F8d5497945a3875639AC7E10F9d54989"
    mock_id.ip_address = "104.218.67.207"
    mock_id.port = 65536
    mock_id.nonce = "3476617"
    mock_id.id = "0000013320276ec11fb237e6c3bed22be1f0a08e5c0a1a9b135a803a6835da35"
    assert not validate_id(mock_id)


def test_validate_id_bad_id_input():
    mock_id = Mock()
    mock_id.public_key = "0xc0fffe254729295a45a2885639AC7E10F8d5497945a3875639AC7E10F9d54989"
    mock_id.ip_address = "104.218.67.207"
    mock_id.port = 65536
    mock_id.nonce = 3476617
    mock_id.id = 13320276
    assert not validate_id(mock_id)


def test_validate_id_invalid_digest():
    mock_id = Mock()
    mock_id.public_key = "0xc0fffe254729295a45a2885639AC7E10F8d5497945a3875639AC7E10F9e54979"
    mock_id.ip_address = "154.218.67.207"
    mock_id.port = 65536
    mock_id.nonce = 1870510
    mock_id.id = "0000013320276ec11fb237e6c3bed22be1f0a08e5c0a1a9b135a803a6835da35"
    assert not validate_id(mock_id)


def test_validate_id_valid_parameters_but_not_matching_id():
    mock_id = Mock()
    mock_id.public_key = "0xc0fffe254729295a45a2885639AC7E10F8d5497945a3875639AC7E10F9e54989"
    mock_id.ip_address = "154.218.67.207"
    mock_id.port = 65536
    mock_id.nonce = 1870510
    mock_id.id = "0000013320276ec11fb237e6c3bed22be1f0a08e5c0a1a9b135a803a6835da35"
    assert not validate_id(mock_id)

