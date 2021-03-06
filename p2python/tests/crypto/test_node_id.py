import pytest
from dataclasses import FrozenInstanceError
from p2python.crypto.node_id import NodeID


def test_node_id_well_formed():
    node = NodeID("string", "string", 123, 123, "string")
    assert node.public_key == "string"
    assert node.ip_address == "string"
    assert node.port == 123
    assert node.nonce == 123
    assert node.id == "string"


def test_node_id_frozen():
    node = NodeID("string", "string", 123, 123, "string")
    with pytest.raises(FrozenInstanceError):
        node.public_key = "changed"
    with pytest.raises(FrozenInstanceError):
        node.ip_address = "changed"
    with pytest.raises(FrozenInstanceError):
        node.port = 234
    with pytest.raises(FrozenInstanceError):
        node.nonce = 234
    with pytest.raises(FrozenInstanceError):
        node.id = "changed"


def test_node_id_additional_parameters():
    with pytest.raises(TypeError):
        node = NodeID("string", "string", 123, 123, "string", "string")


def test_node_id_lacking_parameters():
    with pytest.raises(TypeError):
        node = NodeID("string", "string", 123, 123)