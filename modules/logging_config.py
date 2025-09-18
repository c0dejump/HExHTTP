#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This module provides functions to configure logging for a Python application.

Functions:
    valid_log_level(level: str) -> str:

    configure_logger(module_name: str) -> logging.Logger:

    configure_logging(verbose: int, log: int, log_file: str = "./logs/%Y%m%d_%H%M.log"):
        verbose (int): The verbosity level.
        log (int): The logging level to set (e.g., DEBUG, INFO, etc.).
        log_file (str): The file path pattern for the log file. Defaults "./logs/%Y%m%d_%H%M.log".
"""

import logging
import logging.config
from time import strftime


def valid_log_level(level: str) -> str:
    """
    Validates and returns the corresponding logging level name.

    Args:
        level (str): The log level to validate ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')

    Returns:
        str: The corresponding logging level name if valid.

    Raises:
        ValueError: If the provided log level is invalid.
    """
    try:
        return logging.getLevelName(level.upper())
    except ValueError as exc:
        raise ValueError(f"Invalid log level: {level}") from exc


def configure_logger(module_name: str) -> logging.Logger:
    """
    Configures and returns a logger instance for the specified module.

    This function sets up a logger for the given module name with a default logging level of DEBUG.

    Args:
        module_name (str): The name of the module for which the logger is being configured.

    Returns:
        logging.Logger: A logger instance configured for the specified module.
    """
    logger = logging.getLogger(module_name)
    logger.setLevel(logging.DEBUG)
    return logger


def configure_logging(verbose:int, log: int, log_file: str = "./logs/%Y%m%d_%H%M.log"):
    """
    Configures the logging level for the root logger.

    Args:
        verbose (int): The verbosity level.
        log (int): The logging level to set (e.g., DEBUG, INFO, etc.).
        log_file (str): The file path pattern for the log file. Defaults "./logs/%Y%m%d_%H%M.log".
    """
    log_level = log

    if verbose:
        log_level = max(logging.DEBUG, logging.WARNING - verbose * 10)
    else:
        log_level = log

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
                "filename": strftime(log_file),
                "mode": "w",
            },
        },
        "loggers": {
            "": {"handlers": ["fileHandler"], "level": log_level, "propagate": False}
        },
    }
    logging.config.dictConfig(custom_logger_config)
