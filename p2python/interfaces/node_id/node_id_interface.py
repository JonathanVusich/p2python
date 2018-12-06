from dataclasses import dataclass
from abc import ABC

""" NodeIDInterface

This is the interface for each node ID in the network. 

For basic node id classes, NodeIDInterface should simply
be subclassed as follows:
    
    class NodeID(NodeIDInterface):
        pass
        
Extra helper methods can be added to your NodeID class
by substituting a custom NodeID class for the base NodeID class.
"""


@dataclass(frozen=True)
class NodeIDInterface(ABC):
    public_key: str
    ip_address: str
    port: int
    timestamp: int
    id: str
