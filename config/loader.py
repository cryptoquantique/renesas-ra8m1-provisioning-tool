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

        if "skmt" in data:
            self._update_skmt_config(data["skmt"])

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
                        self.config.hsm.aws_region = aws_creds.region or "eu-central-1"
            except Exception as e:
                logger.debug(f"Could not load AWS credentials from JSON: {str(e)}")

        skmt_path = os.getenv(f"{self.ENV_PREFIX}SKMT_PATH")
        if skmt_path:
            self.config.skmt.skmt_path = skmt_path
        elif not self.config.skmt.skmt_path:
            # Auto-detect SKMT in app folder
            auto_skmt_path = self._auto_detect_skmt()
            if auto_skmt_path:
                self.config.skmt.skmt_path = auto_skmt_path
                logger.info(f"Auto-detected SKMT path: {auto_skmt_path}")

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

    def _update_skmt_config(self, data: dict) -> None:
        """Update SKMT configuration from dictionary."""
        if "skmt_path" in data:
            self.config.skmt.skmt_path = data["skmt_path"]
        if "working_directory" in data:
            self.config.skmt.working_directory = data["working_directory"]

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
        This allows GUI to start without complete configuration.

        Raises:
            ConfigurationError: If provided configuration is invalid
        """
        # Only validate if values are provided, don't require all fields
        if self.config.hsm.pkcs11_library and not Path(self.config.hsm.pkcs11_library).exists():
            logger.warning(f"PKCS#11 library path does not exist: {self.config.hsm.pkcs11_library}")

        if self.config.skmt.skmt_path and not Path(self.config.skmt.skmt_path).exists():
            logger.warning(f"SKMT path does not exist: {self.config.skmt.skmt_path}")
    
    def _auto_detect_skmt(self) -> Optional[str]:
        """
        Auto-detect SKMT executable in multiple locations.
        
        Searches for common SKMT executable names in:
        1. provisioning_tool/security/skmt/app/ (repo folder)
        2. C:\\Renesas\\SecurityKeyManagementTool\\ (default installation path)
        3. Common subdirectories (bin, cli, etc.)
        
        Returns:
            Path to SKMT executable if found, None otherwise
        """
        # Common SKMT executable names (prioritize CLI over GUI)
        # Prioritize skmt.exe (CLI) over SecurityKeyManagementTool.exe (GUI)
        possible_names = [
            "skmt.exe",  # CLI - highest priority
            "skmt",  # CLI without extension
            "SKMT.exe",
            "SKMT",
            "SecurityKeyManagementTool.exe",  # GUI - lower priority
            "SecurityKeyManagementTool",
        ]
        
        # Common subdirectories to search in (prioritize cli folder)
        # Search CLI subfolder first, then root, then others
        subdirs = ["cli", "", "bin", "tools", "executable"]
        
        # Search locations (in order of priority)
        search_locations = []
        
        # 1. Repo app folder
        current_file = Path(__file__).resolve()
        # config/loader.py -> config/ -> root/ -> security/skmt/app
        skmt_app_dir = current_file.parent.parent / "security" / "skmt" / "app"
        if skmt_app_dir.exists():
            search_locations.append(skmt_app_dir)
        
        # 2. Default installation path
        default_install_path = Path("C:/Renesas/SecurityKeyManagementTool")
        if default_install_path.exists():
            search_locations.append(default_install_path)
        
        # 3. Alternative common installation paths
        alt_paths = [
            Path("C:/Program Files/Renesas/SecurityKeyManagementTool"),
            Path("C:/Program Files (x86)/Renesas/SecurityKeyManagementTool"),
        ]
        for alt_path in alt_paths:
            if alt_path.exists():
                search_locations.append(alt_path)
        
        # Search in each location
        for search_dir in search_locations:
            logger.debug(f"Searching for SKMT in: {search_dir}")
            
            # First, try subdirectories (prioritize cli folder for CLI executable)
            for subdir in subdirs:
                if subdir:
                    subdir_path = search_dir / subdir
                    if not subdir_path.exists() or not subdir_path.is_dir():
                        continue
                else:
                    subdir_path = search_dir
                
                for name in possible_names:
                    candidate = subdir_path / name
                    if candidate.exists() and candidate.is_file():
                        if name.endswith(".exe") or os.access(candidate, os.X_OK):
                            logger.info(f"Found SKMT executable in {'subdirectory' if subdir else 'root'}: {candidate}")
                            return str(candidate)
        
        logger.debug("SKMT executable not found in any search location")
        return None


