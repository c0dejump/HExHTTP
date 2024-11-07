#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import logging.config
from time import strftime

# Custom logger configuration


# """configuring overal how the loggin is done"""
# logging.basicConfig(
#     filename=strftime("./logs/%Y%m%d_%H%M.log"),
#     format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
# )


def valid_log_level(level):
    """
    Validates and returns the corresponding logging level name.

    Args:
        level (str): The log level to validate (e.g., 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL').

    Returns:
        str: The corresponding logging level name if valid.

    Raises:
        ValueError: If the provided log level is invalid.
    """
    try:
        return logging.getLevelName(level.upper())
    except ValueError as exc:
        raise ValueError(f"Invalid log level: {level}") from exc


def configure_logger(
    module_name: str, handler: logging.Handler = logging.NullHandler()
) -> logging.Logger:
    """Provides a logger instance set to the module provided with a default handler"""

    logger = logging.getLogger(module_name)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def configure_logging(log_level: str):
    """
    Configures the logging level for the root logger.

    Args:
        log_level (str): The log level to set for the root logger (e.g., 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL').

    Raises:
        ValueError: If the provided log level is invalid.
    """
    custom_logger_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "customFormatter": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            }
        },
        "handlers": {
            "fileHandler": {
                "class": "logging.FileHandler",
                "formatter": "customFormatter",
                "level": log_level,
                "filename": strftime("./logs/%Y%m%d_%H%M.log"),
                "mode": "w",
            },
        },
        "loggers": {
            "": {"handlers": ["fileHandler"], "level": log_level, "propagate": False}
        },
    }
    logging.config.dictConfig(custom_logger_config)
