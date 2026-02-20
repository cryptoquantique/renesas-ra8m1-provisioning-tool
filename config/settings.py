"""
Configuration settings and defaults.

This module defines configuration settings, default values,
and configuration validation rules.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

# Default AWS region for KMS/HSM. Override via project_config.json or AWS_DEFAULT_REGION.
DEFAULT_AWS_REGION: str = "eu-west-2"


@dataclass
class CommunicationConfig:
    """
    Communication interface configuration.

    Attributes:
        uart_port: Default UART port
        uart_baudrate: Default UART baud rate
        uart_timeout: UART communication timeout in seconds
        usb_vendor_id: USB vendor ID
        usb_product_id: USB product ID
        usb_timeout: USB communication timeout in seconds
    """

    uart_port: str = "COM3"
    uart_baudrate: int = 115200
    uart_timeout: float = 10.0
    usb_vendor_id: int = 0x045B
    usb_product_id: int = 0x0001
    usb_timeout: float = 10.0


@dataclass
class HSMConfig:
    """
    HSM configuration.

    Attributes:
        pkcs11_library: Path to PKCS#11 library (MANDATORY for CloudHSM!)
        slot_id: HSM slot ID
        pin: HSM PIN (should be loaded from environment or secure storage)
        aws_cloudhsm_cluster_id: AWS CloudHSM cluster ID (optional)
        aws_region: AWS region (for AWS KMS or CloudHSM)
        aws_access_key_id: AWS access key ID (optional, can use env vars)
        aws_secret_access_key: AWS secret access key (optional, can use env vars)
        key_label_prefix: Prefix for key labels in HSM
        hsm_type: HSM type to use: "cloudhsm_pkcs11" (MANDATORY!), "cloudhsm", or "aws_kms" (deprecated)
    """

    pkcs11_library: str = ""
    slot_id: int = 0
    pin: str = ""
    aws_cloudhsm_cluster_id: Optional[str] = None
    aws_region: str = DEFAULT_AWS_REGION
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    key_label_prefix: str = "renesas_"
    hsm_type: str = "broker"  # AWS KMS for key management and signing


@dataclass
class SKMTConfig:
    """
    Legacy configuration for certificate generation working directory.

    Note:
        SKMT executable is no longer used. All key operations (UFPK, RKEY)
        are handled natively in Python. This config is retained only for
        the working_directory used by CertificateGenerator.

    Attributes:
        skmt_path: Deprecated - no longer used
        working_directory: Working directory for certificate generation operations
        log_level: Log level for certificate operations
    """

    skmt_path: str = ""
    working_directory: str = "./skmt_work"
    log_level: str = "INFO"


@dataclass
class PGPConfig:
    """
    PGP configuration for UFPK encryption/decryption.

    Attributes:
        gpg_path: Path to GnuPG executable (default: "gpg" or "gpg.exe")
        customer_public_key: Path to customer PGP public key file (.asc)
        customer_private_key: Path to customer PGP private key file
        renesas_public_key: Path to Renesas PGP public key file (Keywrap-pub.key)
        keyring_dir: Directory for GPG keyring (optional)
    """

    gpg_path: str = "gpg"
    customer_public_key: str = ""
    customer_private_key: str = ""
    renesas_public_key: str = ""
    keyring_dir: Optional[str] = None


@dataclass
class DLMConfig:
    """
    DLM (Device Lifecycle Management) server configuration.

    Attributes:
        server_url: DLM server URL
        api_key: API key for DLM server authentication (legacy)
        api_secret: API secret for DLM server authentication (legacy)
        username: Username for DLM server authentication
        password: Password for DLM server authentication
        session_cookie: JSESSIONID cookie value (exported from browser after manual login)
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        device_id: Device ID for DLM operations
    """

    server_url: str = ""
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    session_cookie: Optional[str] = None
    timeout: float = 30.0
    verify_ssl: bool = True
    device_id: Optional[str] = None


@dataclass
class FirmwareConfig:
    """
    Firmware configuration.

    Attributes:
        bootloader_address: Bootloader start address
        primary_image_address: Primary image start address
        primary_image_size: Primary image size in bytes
        secondary_image_address: Secondary image start address
        secondary_image_size: Secondary image size in bytes
        flash_block_size: Flash block size in bytes
    """

    bootloader_address: int = 0x00000000
    primary_image_address: int = 0x02010000
    primary_image_size: int = 0x000F8000
    secondary_image_address: int = 0x02210000
    secondary_image_size: int = 0x000F8000
    flash_block_size: int = 32 * 1024


@dataclass
class LoggingConfig:
    """
    Logging configuration.

    Attributes:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        file_path: Path to log file (optional)
        enable_console: Whether to enable console output
        max_file_size: Maximum log file size in bytes
        backup_count: Number of backup log files
    """

    level: str = "INFO"
    file_path: Optional[Path] = None
    enable_console: bool = True
    max_file_size: int = 10 * 1024 * 1024
    backup_count: int = 5


@dataclass
class BrokerConfig:
    """
    Crypto broker service configuration.

    Attributes:
        socket_path: Path to Unix socket (Linux) or Named Pipe name (Windows)
        policies_file: Path to authorization policies JSON file
        session_timeout: Session timeout in seconds (0 for no timeout)
        max_sessions: Maximum concurrent client sessions
        pid_file: Path to PID file for daemon mode
        aws_region: AWS region for KMS backend
        aws_access_key_id: AWS access key (optional, can use env vars)
        aws_secret_access_key: AWS secret key (optional, can use env vars)
        key_prefix: Prefix for key aliases in KMS
    """

    socket_path: Optional[str] = None
    policies_file: Optional[str] = None
    session_timeout: float = 3600.0
    max_sessions: int = 100
    pid_file: Optional[str] = None
    aws_region: str = DEFAULT_AWS_REGION
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    key_prefix: str = "renesas_"


@dataclass
class ProvisioningToolConfig:
    """
    Main configuration class for the provisioning tool.

    Attributes:
        communication: Communication configuration
        hsm: HSM configuration
        skmt: SKMT configuration
        pgp: PGP configuration
        dlm: DLM server configuration
        firmware: Firmware configuration
        logging: Logging configuration
        broker: Crypto broker service configuration
        custom: Custom configuration parameters
    """

    communication: CommunicationConfig = field(default_factory=CommunicationConfig)
    hsm: HSMConfig = field(default_factory=HSMConfig)
    skmt: SKMTConfig = field(default_factory=SKMTConfig)
    pgp: PGPConfig = field(default_factory=PGPConfig)
    dlm: DLMConfig = field(default_factory=DLMConfig)
    firmware: FirmwareConfig = field(default_factory=FirmwareConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    broker: BrokerConfig = field(default_factory=BrokerConfig)
    custom: Dict[str, any] = field(default_factory=dict)



