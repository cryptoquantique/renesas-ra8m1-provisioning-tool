"""
Configuration validators.

This module provides validation functions for configuration values.
"""

from pathlib import Path
from typing import Any

from utils.exceptions import ConfigurationError


def validate_port(port: str) -> None:
    """
    Validate communication port format.

    Args:
        port: Port identifier (e.g., "COM3", "/dev/ttyUSB0")

    Raises:
        ConfigurationError: If port format is invalid
    """
    if not port or not isinstance(port, str):
        raise ConfigurationError("Port must be a non-empty string")


def validate_baudrate(baudrate: int) -> None:
    """
    Validate baud rate value.

    Args:
        baudrate: Baud rate value

    Raises:
        ConfigurationError: If baud rate is invalid
    """
    valid_baudrates = [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]
    if baudrate not in valid_baudrates:
        raise ConfigurationError(
            f"Invalid baud rate: {baudrate}. "
            f"Valid values: {', '.join(map(str, valid_baudrates))}"
        )


def validate_address(address: int, name: str = "address") -> None:
    """
    Validate memory address.

    Args:
        address: Memory address value
        name: Address name for error messages

    Raises:
        ConfigurationError: If address is invalid
    """
    if address < 0:
        raise ConfigurationError(f"{name} must be non-negative")
    if address % 4 != 0:
        raise ConfigurationError(f"{name} must be 4-byte aligned")


def validate_path(path: str, must_exist: bool = False) -> None:
    """
    Validate file or directory path.

    Args:
        path: Path to validate
        must_exist: Whether the path must exist

    Raises:
        ConfigurationError: If path is invalid
    """
    if not path or not isinstance(path, str):
        raise ConfigurationError("Path must be a non-empty string")

    if must_exist and not Path(path).exists():
        raise ConfigurationError(f"Path does not exist: {path}")


def validate_log_level(level: str) -> None:
    """
    Validate logging level.

    Args:
        level: Logging level string

    Raises:
        ConfigurationError: If log level is invalid
    """
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if level.upper() not in valid_levels:
        raise ConfigurationError(
            f"Invalid log level: {level}. Valid values: {', '.join(valid_levels)}"
        )


def validate_positive_integer(value: Any, name: str) -> None:
    """
    Validate that a value is a positive integer.

    Args:
        value: Value to validate
        name: Value name for error messages

    Raises:
        ConfigurationError: If value is not a positive integer
    """
    if not isinstance(value, int) or value <= 0:
        raise ConfigurationError(f"{name} must be a positive integer")

