"""
Configuration loader.

This module provides functionality to load configuration from files,
environment variables, and command-line arguments.
"""

import os
from pathlib import Path
from typing import Optional

import yaml

from config.settings import ProvisioningToolConfig
from utils.exceptions import ConfigurationError
from utils.logging import get_logger

logger = get_logger(__name__)


class ConfigLoader:
    """
    Configuration loader with support for multiple sources.

    Loads configuration from:
    1. Environment variables
    2. Configuration files (YAML, JSON)
    3. Default values
    """

    ENV_PREFIX = "RA8M1_PROV_"

    def __init__(self, config_file: Optional[Path] = None):
        """
        Initialize configuration loader.

        Args:
            config_file: Optional path to configuration file
        """
        self.config_file = config_file
        self.config = ProvisioningToolConfig()

    def load(self) -> ProvisioningToolConfig:
        """
        Load configuration from all available sources.

        Returns:
            Loaded configuration object

        Raises:
            ConfigurationError: If configuration loading fails
        """
        try:
            if self.config_file and self.config_file.exists():
                self._load_from_file(self.config_file)

            self._load_from_environment()
            self._validate_config()

            return self.config
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration: {str(e)}") from e

    def _load_from_file(self, config_file: Path) -> None:
        """
        Load configuration from YAML file.

        Args:
            config_file: Path to configuration file
        """
        logger.info(f"Loading configuration from {config_file}")

        with open(config_file, "r") as f:
            data = yaml.safe_load(f)

        if not data:
            return

        if "communication" in data:
            self._update_communication_config(data["communication"])

        if "hsm" in data:
            self._update_hsm_config(data["hsm"])

        if "pgp" in data:
            self._update_pgp_config(data["pgp"])

        if "dlm" in data:
            self._update_dlm_config(data["dlm"])

        if "firmware" in data:
            self._update_firmware_config(data["firmware"])

        if "logging" in data:
            self._update_logging_config(data["logging"])

    def _load_from_environment(self) -> None:
        """Load configuration from environment variables."""
        logger.debug("Loading configuration from environment variables")

        hsm_pin = os.getenv(f"{self.ENV_PREFIX}HSM_PIN")
        if hsm_pin:
            self.config.hsm.pin = hsm_pin

        pkcs11_lib = os.getenv(f"{self.ENV_PREFIX}PKCS11_LIBRARY")
        if pkcs11_lib:
            self.config.hsm.pkcs11_library = pkcs11_lib

        aws_cluster_id = os.getenv(f"{self.ENV_PREFIX}AWS_CLUSTER_ID")
        if aws_cluster_id:
            self.config.hsm.aws_cloudhsm_cluster_id = aws_cluster_id

        aws_region = os.getenv(f"{self.ENV_PREFIX}AWS_REGION")
        if aws_region:
            self.config.hsm.aws_region = aws_region

        # Load AWS credentials from JSON file if not set
        if not self.config.hsm.aws_access_key_id or not self.config.hsm.aws_secret_access_key:
            try:
                from utils.aws_credentials import load_aws_credentials
                aws_creds = load_aws_credentials(fallback_to_env=False)
                if aws_creds.is_complete():
                    if not self.config.hsm.aws_access_key_id:
                        self.config.hsm.aws_access_key_id = aws_creds.access_key_id
                    if not self.config.hsm.aws_secret_access_key:
                        self.config.hsm.aws_secret_access_key = aws_creds.secret_access_key
                    if not self.config.hsm.aws_region or self.config.hsm.aws_region == "us-east-1":
                        self.config.hsm.aws_region = aws_creds.region or self.config.hsm.aws_region
            except Exception as e:
                logger.debug(f"Could not load AWS credentials from JSON: {str(e)}")

        dlm_url = os.getenv(f"{self.ENV_PREFIX}DLM_SERVER_URL")
        if dlm_url:
            self.config.dlm.server_url = dlm_url

        dlm_api_key = os.getenv(f"{self.ENV_PREFIX}DLM_API_KEY")
        if dlm_api_key:
            self.config.dlm.api_key = dlm_api_key

        dlm_api_secret = os.getenv(f"{self.ENV_PREFIX}DLM_API_SECRET")
        if dlm_api_secret:
            self.config.dlm.api_secret = dlm_api_secret

        dlm_device_id = os.getenv(f"{self.ENV_PREFIX}DLM_DEVICE_ID")
        if dlm_device_id:
            self.config.dlm.device_id = dlm_device_id
        
        # Load DLM credentials from JSON file if not set
        if not self.config.dlm.username or not self.config.dlm.password or not self.config.dlm.server_url:
            try:
                from utils.dlm_credentials import load_dlm_credentials
                dlm_creds = load_dlm_credentials()
                if dlm_creds:
                    if dlm_creds.email and dlm_creds.password:
                        if not self.config.dlm.username:
                            self.config.dlm.username = dlm_creds.email
                        if not self.config.dlm.password:
                            self.config.dlm.password = dlm_creds.password
                    if dlm_creds.session_cookie and not self.config.dlm.session_cookie:
                        self.config.dlm.session_cookie = dlm_creds.session_cookie
                    if dlm_creds.server_url and not self.config.dlm.server_url:
                        self.config.dlm.server_url = dlm_creds.server_url
            except Exception as e:
                logger.debug(f"Could not load DLM credentials from JSON: {str(e)}")
        
        # Load DLM server URL from default if not set
        if not self.config.dlm.server_url:
            # Default DLM server URL (based on test files)
            self.config.dlm.server_url = "https://dlm.renesas.com"
            logger.debug("Using default DLM server URL: https://dlm.renesas.com")

        pgp_gpg_path = os.getenv(f"{self.ENV_PREFIX}PGP_GPG_PATH")
        if pgp_gpg_path:
            self.config.pgp.gpg_path = pgp_gpg_path
        else:
            # Auto-detect GnuPG if not configured
            import shutil
            gpg_path = shutil.which("gpg") or shutil.which("gpg.exe")
            if not gpg_path:
                # Try common Windows locations
                common_paths = [
                    r"C:\Program Files (x86)\GnuPG\bin\gpg.exe",
                    r"C:\Program Files\GnuPG\bin\gpg.exe",
                    r"C:\Program Files\Git\usr\bin\gpg.exe",
                ]
                for path in common_paths:
                    if Path(path).exists():
                        gpg_path = path
                        break
            if gpg_path:
                self.config.pgp.gpg_path = gpg_path
                logger.debug(f"Auto-detected GnuPG path: {gpg_path}")

        pgp_customer_pub = os.getenv(f"{self.ENV_PREFIX}PGP_CUSTOMER_PUBLIC_KEY")
        if pgp_customer_pub:
            self.config.pgp.customer_public_key = pgp_customer_pub

        pgp_customer_priv = os.getenv(f"{self.ENV_PREFIX}PGP_CUSTOMER_PRIVATE_KEY")
        if pgp_customer_priv:
            self.config.pgp.customer_private_key = pgp_customer_priv

        pgp_renesas_pub = os.getenv(f"{self.ENV_PREFIX}PGP_RENESAS_PUBLIC_KEY")
        if pgp_renesas_pub:
            self.config.pgp.renesas_public_key = pgp_renesas_pub

        log_level = os.getenv(f"{self.ENV_PREFIX}LOG_LEVEL")
        if log_level:
            self.config.logging.level = log_level

    def _update_communication_config(self, data: dict) -> None:
        """Update communication configuration from dictionary."""
        if "uart_port" in data:
            self.config.communication.uart_port = data["uart_port"]
        if "uart_baudrate" in data:
            self.config.communication.uart_baudrate = data["uart_baudrate"]
        if "uart_timeout" in data:
            self.config.communication.uart_timeout = data["uart_timeout"]

    def _update_hsm_config(self, data: dict) -> None:
        """Update HSM configuration from dictionary."""
        if "pkcs11_library" in data:
            self.config.hsm.pkcs11_library = data["pkcs11_library"]
        if "slot_id" in data:
            self.config.hsm.slot_id = data["slot_id"]
        if "aws_cloudhsm_cluster_id" in data:
            self.config.hsm.aws_cloudhsm_cluster_id = data["aws_cloudhsm_cluster_id"]
        if "aws_region" in data:
            self.config.hsm.aws_region = data["aws_region"]

    def _update_pgp_config(self, data: dict) -> None:
        """Update PGP configuration from dictionary."""
        if "gpg_path" in data:
            self.config.pgp.gpg_path = data["gpg_path"]
        if "customer_public_key" in data:
            self.config.pgp.customer_public_key = data["customer_public_key"]
        if "customer_private_key" in data:
            self.config.pgp.customer_private_key = data["customer_private_key"]
        if "renesas_public_key" in data:
            self.config.pgp.renesas_public_key = data["renesas_public_key"]
        if "keyring_dir" in data:
            self.config.pgp.keyring_dir = data["keyring_dir"]

    def _update_dlm_config(self, data: dict) -> None:
        """Update DLM configuration from dictionary."""
        if "server_url" in data:
            self.config.dlm.server_url = data["server_url"]
        if "api_key" in data:
            self.config.dlm.api_key = data["api_key"]
        if "api_secret" in data:
            self.config.dlm.api_secret = data["api_secret"]
        if "username" in data:
            self.config.dlm.username = data["username"]
        if "password" in data:
            self.config.dlm.password = data["password"]
        if "session_cookie" in data or "jsessionid" in data:
            self.config.dlm.session_cookie = data.get("session_cookie") or data.get("jsessionid")
        if "timeout" in data:
            self.config.dlm.timeout = float(data["timeout"])
        if "verify_ssl" in data:
            self.config.dlm.verify_ssl = bool(data["verify_ssl"])
        if "device_id" in data:
            self.config.dlm.device_id = data["device_id"]

    def _update_firmware_config(self, data: dict) -> None:
        """Update firmware configuration from dictionary."""
        if "bootloader_address" in data:
            self.config.firmware.bootloader_address = int(data["bootloader_address"], 0)
        if "primary_image_address" in data:
            self.config.firmware.primary_image_address = int(
                data["primary_image_address"], 0
            )
        if "secondary_image_address" in data:
            self.config.firmware.secondary_image_address = int(
                data["secondary_image_address"], 0
            )

    def _update_logging_config(self, data: dict) -> None:
        """Update logging configuration from dictionary."""
        if "level" in data:
            self.config.logging.level = data["level"]
        if "file_path" in data:
            self.config.logging.file_path = Path(data["file_path"])
        if "enable_console" in data:
            self.config.logging.enable_console = data["enable_console"]

    def _validate_config(self) -> None:
        """
        Validate loaded configuration.

        Only validates if values are provided, doesn't require all fields.
        This allows the tool to start without complete configuration.

        Raises:
            ConfigurationError: If provided configuration is invalid
        """
        # Only validate if values are provided, don't require all fields
        if self.config.hsm.pkcs11_library and not Path(self.config.hsm.pkcs11_library).exists():
            logger.warning(f"PKCS#11 library path does not exist: {self.config.hsm.pkcs11_library}")



