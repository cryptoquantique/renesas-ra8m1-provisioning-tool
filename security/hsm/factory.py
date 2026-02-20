"""
HSM client factory.

This module provides a factory for creating HSM client instances
based on configuration.

RECOMMENDED: Use hsm_type="broker" to route all cryptographic operations
through the local broker service using native PKCS#11. This provides:
- Credential isolation (AWS credentials only in broker daemon)
- OS-level authentication via Unix socket credentials
- Standard PKCS#11 interface for all operations
- Centralized audit logging
"""

from typing import Optional
from pathlib import Path

from config.settings import HSMConfig, DEFAULT_AWS_REGION
from utils.exceptions import HSMError
from utils.logging import get_logger
from .base import HSMClient

logger = get_logger(__name__)


# Default HSM type - broker is recommended for production
DEFAULT_HSM_TYPE = "broker"


def is_broker_available(socket_path: Optional[str] = None) -> bool:
    """
    Check if the broker daemon is running and available.

    Works on both Windows (Named Pipes) and Unix (Unix sockets).

    Args:
        socket_path: Optional path to broker socket/pipe

    Returns:
        True if broker is available, False otherwise
    """
    import sys

    try:
        from security.broker.service.daemon import get_default_socket_path

        socket_path = socket_path or get_default_socket_path()

        if sys.platform == "win32":
            # Windows: Check if the service is running or pipe exists
            # First try to connect to the pipe
            try:
                import ctypes
                from ctypes import wintypes

                kernel32 = ctypes.windll.kernel32

                GENERIC_READ = 0x80000000
                GENERIC_WRITE = 0x40000000
                OPEN_EXISTING = 3
                # INVALID_HANDLE_VALUE is -1 (or 0xFFFFFFFF for 32-bit handles)
                INVALID_HANDLE_VALUE = -1

                # Try to open the pipe
                kernel32.CreateFileW.restype = wintypes.HANDLE
                handle = kernel32.CreateFileW(
                    socket_path,
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    None,
                    OPEN_EXISTING,
                    0,
                    None,
                )

                # Compare as signed integer to handle 32/64-bit issues
                if handle is not None and handle != INVALID_HANDLE_VALUE and handle != 0xFFFFFFFF:
                    kernel32.CloseHandle(handle)
                    return True

                # Pipe not found, check if service is running
                from security.broker.service.windows_service import get_service_status
                status = get_service_status()
                return status == "RUNNING"

            except Exception:
                return False
        else:
            # Unix: Check if socket file exists
            return Path(socket_path).exists()

    except Exception:
        return False


def create_hsm_client(config: HSMConfig) -> HSMClient:
    """
    Create HSM client based on configuration.

    The factory supports three backends:
    - "broker" (RECOMMENDED): Native PKCS#11 via local broker service → AWS KMS
    - "aws_kms": Direct AWS KMS access
    - "cloudhsm_pkcs11": AWS CloudHSM via PKCS#11 library

    Args:
        config: HSMConfig instance

    Returns:
        Initialized HSMClient instance

    Raises:
        HSMError: If HSM client creation fails
    """
    hsm_config_dict = {
        "key_prefix": config.key_label_prefix,
    }

    # Default to broker if not specified
    hsm_type = config.hsm_type.lower() if config.hsm_type else DEFAULT_HSM_TYPE

    if hsm_type == "broker":
        logger.info("Creating Broker HSM client (native PKCS#11)")
        from .broker_client import BrokerHSMClient

        # Broker client uses native PKCS#11 to communicate with daemon
        # The daemon handles AWS KMS authentication
        # Pass aws_region and credentials so auto-start and fallback work correctly
        hsm_config_dict.update({
            "socket_path": getattr(config, "socket_path", None),
            "timeout": getattr(config, "timeout", 30.0),
            "aws_region": config.aws_region,
            "aws_access_key_id": getattr(config, "aws_access_key_id", None),
            "aws_secret_access_key": getattr(config, "aws_secret_access_key", None),
        })
        return BrokerHSMClient(hsm_config_dict)

    elif hsm_type == "aws_kms":
        # Direct AWS KMS access - not recommended for production
        logger.info("Creating AWS KMS client (direct access)")
        logger.warning(
            "Direct AWS KMS access is not recommended. "
            "Consider using hsm_type='broker' for PKCS#11 interface."
        )
        from .aws_kms import AWSKMSClient
        from utils.aws_credentials import get_aws_credentials

        aws_creds = get_aws_credentials(fallback_to_env=True)
        hsm_config_dict.update({
            "aws_region": config.aws_region or aws_creds.get("aws_region", DEFAULT_AWS_REGION),
            "aws_access_key_id": config.aws_access_key_id or aws_creds.get("aws_access_key_id"),
            "aws_secret_access_key": config.aws_secret_access_key or aws_creds.get("aws_secret_access_key"),
        })
        return AWSKMSClient(hsm_config_dict)

    elif hsm_type == "cloudhsm" or hsm_type == "cloudhsm_pkcs11":
        logger.info("Creating CloudHSM PKCS#11 client")
        from .cloudhsm_pkcs11 import CloudHSMClient

        hsm_config_dict.update({
            "pkcs11_library": config.pkcs11_library,
            "slot_id": config.slot_id or 0,
            "pin": config.pin,
        })
        return CloudHSMClient(hsm_config_dict)

    raise HSMError(
        f"Unknown HSM type: {hsm_type}. "
        f"Supported: 'broker' (recommended), 'aws_kms', 'cloudhsm_pkcs11'"
    )
