import logging


def init_logging():
    log_fmt = "[%(asctime)s][%(name)s][%(levelname)s]: %(message)s"
    logging.basicConfig(format=log_fmt)

def get_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    return logger
