"""
Logging configuration and utilities.

This module provides centralized logging configuration with support for
file and console output, log rotation, and sensitive data filtering.
"""

import logging
import sys
from pathlib import Path
from typing import Optional


class SensitiveDataFilter(logging.Filter):
    """
    Filter to remove sensitive data from log messages.

    Filters out common patterns that might contain sensitive information
    such as keys, passwords, and tokens.
    """

    SENSITIVE_PATTERNS = [
        "password",
        "secret_key",
        "access_key",
        "api_key",
        "private_key",
        "auth_token",
        "bearer_token",
        "credential",
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter log records to remove sensitive information.

        Args:
            record: Log record to filter

        Returns:
            True if record should be logged, False otherwise
        """
        message = str(record.getMessage()).lower()
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern in message:
                record.msg = "[FILTERED]"
                record.args = ()
        return True


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[Path] = None,
    enable_console: bool = True,
) -> logging.Logger:
    """
    Configure application-wide logging.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        enable_console: Whether to enable console output

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("provisioning_tool")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(SensitiveDataFilter())
        logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(SensitiveDataFilter())
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(f"provisioning_tool.{name}")





