import asyncio
import logging

from p2python.utils import load_config
from p2python.network.errors import ConfigError

logger = logging.getLogger(__name__)
cfg = load_config(__name__)


class DHT:

    def __init__(self):
        self.load_config()

    def generate_node_id(self):
        pass

    async def fill_kbuckets(self):
        pass
