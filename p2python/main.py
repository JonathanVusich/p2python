import logging
from datetime import datetime

logger = logging.getLogger("p2python")
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler("p2python_{}.log".format(datetime.now().strftime("%Y-%m-%d_%H:%M:%S")))
file_handler.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
