"""
Project Configuration Loader.

Loads configuration from project_config.json in the root of provisioning_tool.
All CLI commands read their inputs from this config file.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass

from utils.exceptions import ConfigError
from utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ProjectConfig:
    """Project configuration data structure."""

    project_name: str
    project_version: str

    dlm_email: str
    dlm_username: str
    dlm_password: str
    dlm_server_url: str

    aws_access_key_id: str
    aws_secret_access_key: str
    aws_region: str

    oem_root_key_id: str
    oem_bootloader_key_id: str
    mcuboot_app_key_id: str

    bootloader_srec: Path
    application_bin: Path
    output_dir: Path
    srec_cat_exe: Path
    skmt_path: Optional[Path]

    app_offset: str
    mcuboot_pubkey_addr: str

    imgtool_header_size: int
    imgtool_align: int
    imgtool_max_align: int
    imgtool_slot_size: int
    imgtool_max_sectors: int
    imgtool_version: str
    imgtool_pad_header: bool
    imgtool_pad: bool
    imgtool_confirm: bool

    cert_load_addr: str
    cert_dest_addr: str
    cert_cfsize: str
    cert_oembl_size: str
    cert_initial_version: int
    cert_mode: str
    cert_build_number: int

    device_type: str
    device_interface: str
    device_com_port: Optional[str]
    device_lock_after_provisioning: bool

    certificate_version: int
    application_version: str

    _raw_config: Dict[str, Any]
    
    @property
    def raw_config(self) -> Dict[str, Any]:
        """Access raw config dict."""
        return self._raw_config
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get arbitrary config value using dot notation (e.g., 'aws.kms.oem_root_key_id')."""
        keys = key.split('.')
        value = self._raw_config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        return value


class ProjectConfigLoader:
    """Loads and validates project configuration."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize config loader.
        
        Args:
            config_path: Path to project_config.json. If None, searches in standard locations.
        """
        self.config_path = config_path or self._find_config_file()
        self._config_data: Optional[Dict[str, Any]] = None
    
    def _find_config_file(self) -> Path:
        """Find project_config.json in standard locations."""
        candidates = [
            Path("project_config.json"),
            Path("provisioning_tool/project_config.json"),
            Path(__file__).parent.parent / "project_config.json",
        ]
        
        for candidate in candidates:
            if candidate.exists():
                logger.info(f"Found config file: {candidate}")
                return candidate
        
        # If not found, return default location
        default_path = Path(__file__).parent.parent / "project_config.json"
        logger.warning(f"Config file not found, using default path: {default_path}")
        return default_path
    
    def load(self) -> ProjectConfig:
        """
        Load and parse project configuration.
        
        Returns:
            ProjectConfig object with all settings
            
        Raises:
            ConfigError: If config file is missing or invalid
        """
        if not self.config_path.exists():
            raise ConfigError(
                f"Configuration file not found: {self.config_path}\n"
                f"Please create project_config.json from project_config.json.example"
            )
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self._config_data = json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in config file: {e}")
        except Exception as e:
            raise ConfigError(f"Failed to read config file: {e}")
        
        return self._parse_config()
    
    def _parse_config(self) -> ProjectConfig:
        """Parse raw config data into ProjectConfig object.
        
        NO FALLBACKS! All values MUST be in project_config.json.
        If a value is missing, an error is raised.
        """
        if not self._config_data:
            raise ConfigError("No config data loaded")
        
        def require(section: dict, key: str, section_name: str):
            """Get required value or raise error."""
            if key not in section:
                raise ConfigError(f"Missing REQUIRED config: {section_name}.{key}")
            return section[key]
        
        def parse_hex_int(value, key_name: str) -> int:
            """Parse hex string or int to int."""
            if isinstance(value, str):
                try:
                    return int(value, 16)
                except ValueError:
                    raise ConfigError(f"Invalid hex value for {key_name}: {value}")
            return int(value)
        
        try:
            base_path = self.config_path.parent
            
            # Get required sections
            if 'project' not in self._config_data:
                raise ConfigError("Missing REQUIRED section: project")
            if 'aws' not in self._config_data:
                raise ConfigError("Missing REQUIRED section: aws")
            if 'paths' not in self._config_data:
                raise ConfigError("Missing REQUIRED section: paths")
            if 'firmware' not in self._config_data:
                raise ConfigError("Missing REQUIRED section: firmware")
            if 'imgtool' not in self._config_data:
                raise ConfigError("Missing REQUIRED section: imgtool")
            if 'certificates' not in self._config_data:
                raise ConfigError("Missing REQUIRED section: certificates")
            
            project = self._config_data['project']
            dlm = self._config_data.get('dlm', {})
            aws = self._config_data['aws']
            kms = require(aws, 'kms', 'aws')
            paths = self._config_data['paths']
            firmware = self._config_data['firmware']
            imgtool = self._config_data['imgtool']
            certs = self._config_data['certificates']
            device = self._config_data.get('device', {})
            
            return ProjectConfig(
                # Project
                project_name=require(project, 'name', 'project'),
                project_version=require(project, 'version', 'project'),
                
                # DLM (optional section)
                dlm_email=dlm.get('email', ''),
                dlm_username=dlm.get('username', ''),
                dlm_password=dlm.get('password', ''),
                dlm_server_url=dlm.get('server_url', ''),
                
                # AWS (REQUIRED)
                aws_access_key_id=require(aws, 'access_key_id', 'aws'),
                aws_secret_access_key=require(aws, 'secret_access_key', 'aws'),
                aws_region=require(aws, 'region', 'aws'),
                
                # KMS (REQUIRED)
                oem_root_key_id=require(kms, 'oem_root_key_id', 'aws.kms'),
                oem_bootloader_key_id=kms.get('oem_bootloader_key_id', kms.get('oem_bl_key_id', '')),
                mcuboot_app_key_id=require(kms, 'mcuboot_app_key_id', 'aws.kms'),
                
                # Paths (REQUIRED)
                bootloader_srec=base_path / require(paths, 'bootloader_srec', 'paths'),
                application_bin=base_path / require(paths, 'application_bin', 'paths'),
                output_dir=base_path / require(paths, 'output_dir', 'paths'),
                srec_cat_exe=base_path / require(paths, 'srec_cat_exe', 'paths'),
                skmt_path=base_path / Path(paths.get('skmt_path', '')) if paths.get('skmt_path') else None,
                
                # Firmware (REQUIRED)
                app_offset=require(firmware, 'app_offset', 'firmware'),
                mcuboot_pubkey_addr=require(firmware, 'mcuboot_pubkey_addr', 'firmware'),
                
                # imgtool parameters (REQUIRED - SINGLE SOURCE OF TRUTH, NO FALLBACKS!)
                imgtool_header_size=parse_hex_int(require(imgtool, 'header_size', 'imgtool'), 'imgtool.header_size'),
                imgtool_align=require(imgtool, 'align', 'imgtool'),
                imgtool_max_align=require(imgtool, 'max_align', 'imgtool'),
                imgtool_slot_size=parse_hex_int(require(imgtool, 'slot_size', 'imgtool'), 'imgtool.slot_size'),
                imgtool_max_sectors=require(imgtool, 'max_sectors', 'imgtool'),
                imgtool_version=require(imgtool, 'version', 'imgtool'),
                imgtool_pad_header=require(imgtool, 'pad_header', 'imgtool'),
                imgtool_pad=require(imgtool, 'pad', 'imgtool'),
                imgtool_confirm=require(imgtool, 'confirm', 'imgtool'),
                
                # Certificates (REQUIRED) - ALL from project_config.json!
                cert_load_addr=require(certs, 'load_addr', 'certificates'),
                cert_dest_addr=require(certs, 'dest_addr', 'certificates'),
                cert_cfsize=require(certs, 'cfsize', 'certificates'),
                cert_oembl_size=require(certs, 'oembl_size', 'certificates'),
                cert_initial_version=certs.get('initial_version', 1),
                cert_mode=require(certs, 'mode', 'certificates'),
                cert_build_number=certs.get('build_number', 0),
                
                # Device (optional)
                device_type=device.get('type', 'ra8m1'),
                device_interface=device.get('interface', 'rfp'),
                device_com_port=device.get('com_port'),
                device_lock_after_provisioning=device.get('lock_after_provisioning', False),
                
                # Versioning (REQUIRED)
                certificate_version=require(certs, 'version', 'certificates'),
                application_version=require(certs, 'application_version', 'certificates'),
                
                # Raw config
                _raw_config=self._config_data
            )
            
        except KeyError as e:
            raise ConfigError(f"Missing required config key: {e}")
        except Exception as e:
            raise ConfigError(f"Failed to parse config: {e}")
    
    def validate(self, config: ProjectConfig) -> bool:
        """
        Validate configuration.
        
        Args:
            config: Configuration to validate
            
        Returns:
            True if valid
            
        Raises:
            ConfigError: If validation fails
        """
        # Check required AWS KMS keys
        if not config.oem_root_key_id or config.oem_root_key_id.startswith('xxxx'):
            raise ConfigError("oem_root_key_id not configured in project_config.json")
        
        if not config.oem_bootloader_key_id or config.oem_bootloader_key_id.startswith('xxxx'):
            raise ConfigError("oem_bootloader_key_id not configured in project_config.json")
        
        if not config.mcuboot_app_key_id or config.mcuboot_app_key_id.startswith('xxxx'):
            raise ConfigError("mcuboot_app_key_id not configured in project_config.json")
        
        # Check paths exist
        if not config.bootloader_srec.exists():
            logger.warning(f"Bootloader SREC not found: {config.bootloader_srec}")
        
        if not config.application_bin.exists():
            logger.warning(f"Application binary not found: {config.application_bin}")
        
        if not config.srec_cat_exe.exists():
            raise ConfigError(f"srec_cat.exe not found: {config.srec_cat_exe}")
        
        return True


# Global config loader instance
_config_loader: Optional[ProjectConfigLoader] = None
_loaded_config: Optional[ProjectConfig] = None


def get_project_config(config_path: Optional[Path] = None, reload: bool = False) -> ProjectConfig:
    """
    Get project configuration (singleton).
    
    Args:
        config_path: Optional path to config file
        reload: Force reload config
        
    Returns:
        ProjectConfig object
        
    Raises:
        ConfigError: If config cannot be loaded
    """
    global _config_loader, _loaded_config
    
    if reload or _loaded_config is None:
        _config_loader = ProjectConfigLoader(config_path)
        _loaded_config = _config_loader.load()
        _config_loader.validate(_loaded_config)
    
    return _loaded_config
