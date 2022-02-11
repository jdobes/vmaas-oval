import logging


def init_logging(verbose: bool = False) -> None:
    log_fmt = "%(asctime)s|%(name)s|%(levelname)s: %(message)s"
    if verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(format=log_fmt, level=level)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    return logger
