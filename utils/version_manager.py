"""
Certificate version manager with auto-increment support.

This module manages certificate versioning for anti-rollback protection.
The version counter starts at 50 (clean start after chip erase)
and auto-increments with each certificate generation.
"""

import json
from pathlib import Path
from typing import Optional
from threading import Lock

from utils.logging import get_logger

logger = get_logger(__name__)

# Thread-safe lock for version file access
_version_lock = Lock()


def get_credentials_file() -> Path:
    """Get path to aws_credentials.json file."""
    # Try multiple locations
    candidates = [
        Path(__file__).parent.parent / "aws_credentials.json",  # provisioning_tool/
        Path.cwd() / "aws_credentials.json",  # Current directory
        Path.cwd() / "provisioning_tool" / "aws_credentials.json",  # From project root
    ]
    
    for candidate in candidates:
        if candidate.exists():
            return candidate
    
    # Return first candidate as default (will be created if needed)
    return candidates[0]


def get_current_certificate_version() -> int:
    """
    Get current certificate version.
    
    Priority:
        1. aws_credentials.json (versioning.certificate_version) - runtime state
        2. project_config.json (certificates.version) - configured value
        3. Default: 1
    
    Returns:
        Current certificate version
    """
    # 1. Try aws_credentials.json (runtime state, auto-incremented)
    creds_file = get_credentials_file()
    if creds_file.exists():
        try:
            with open(creds_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            versioning = data.get("versioning", {})
            if "certificate_version" in versioning:
                version = versioning["certificate_version"]
                logger.debug(f"Certificate version from aws_credentials.json: {version}")
                return version
        except Exception as e:
            logger.warning(f"Failed to read aws_credentials.json: {e}")
    
    # 2. Try project_config.json (configured value - SINGLE SOURCE OF TRUTH)
    try:
        from utils.project_config import get_project_config
        proj_config = get_project_config()
        version = proj_config.certificate_version
        logger.debug(f"Certificate version from project_config.json: {version}")
        return version
    except Exception as e:
        logger.warning(f"Failed to read project_config.json: {e}")
    
    # 3. Default
    logger.warning("No certificate version found in any config, using default: 1")
    return 1


def increment_certificate_version() -> int:
    """
    Increment certificate version in aws_credentials.json.
    
    This is thread-safe and will create the versioning section if it doesn't exist.
    
    Returns:
        New certificate version after increment
        
    Raises:
        IOError: If file cannot be read or written
    """
    with _version_lock:
        creds_file = get_credentials_file()
        
        if not creds_file.exists():
            raise IOError(f"Credentials file not found: {creds_file}")
        
        try:
            # Read current data
            with open(creds_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Get current version
            if "versioning" not in data:
                data["versioning"] = {
                    "certificate_version": 50,
                    "application_version": "1.0.0",
                    "comment": "Certificate version starts at 50 for clean provisioning after chip erase. Anti-rollback counter (ARC_OEMBL) prevents downgrade."
                }
            
            current_version = data["versioning"].get("certificate_version", 50)
            new_version = current_version + 1
            
            # Check for overflow (max 64 versions due to ARC_OEMBL 64-bit counter)
            if new_version > 64:
                logger.warning(
                    f"Certificate version {new_version} exceeds maximum (64). "
                    "Anti-rollback counter (ARC_OEMBL) only supports 64 versions. "
                    "Device may need to be re-initialized or use a different key."
                )
            
            # Update version
            data["versioning"]["certificate_version"] = new_version
            
            # Write back
            with open(creds_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Certificate version incremented: {current_version} -> {new_version}")
            return new_version
        
        except Exception as e:
            logger.error(f"Failed to increment certificate version: {e}")
            raise IOError(f"Failed to increment certificate version: {e}") from e


def set_certificate_version(version: int) -> None:
    """
    Set certificate version to a specific value.
    
    Args:
        version: New certificate version (1-64)
        
    Raises:
        ValueError: If version is out of range
        IOError: If file cannot be written
    """
    if not (1 <= version <= 64):
        raise ValueError(f"Certificate version must be between 1 and 64, got: {version}")
    
    with _version_lock:
        creds_file = get_credentials_file()
        
        if not creds_file.exists():
            raise IOError(f"Credentials file not found: {creds_file}")
        
        try:
            # Read current data
            with open(creds_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Ensure versioning section exists
            if "versioning" not in data:
                data["versioning"] = {
                    "application_version": "1.0.0",
                    "comment": "Certificate version for anti-rollback protection (ARC_OEMBL)."
                }
            
            # Set version
            data["versioning"]["certificate_version"] = version
            
            # Write back
            with open(creds_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Certificate version set to: {version}")
        
        except Exception as e:
            logger.error(f"Failed to set certificate version: {e}")
            raise IOError(f"Failed to set certificate version: {e}") from e


def get_and_increment_version() -> tuple[int, int]:
    """
    Get current version and increment it atomically.
    
    This is the primary function to use for certificate generation.
    
    Returns:
        Tuple of (current_version, next_version)
        
    Example:
        >>> current, next = get_and_increment_version()
        >>> print(f"Using version {current} for this certificate")
        >>> print(f"Next certificate will use version {next}")
    """
    with _version_lock:
        current = get_current_certificate_version()
        next_version = increment_certificate_version()
        return current, next_version


def check_version_overflow() -> tuple[int, int, bool]:
    """
    Check if certificate version is approaching the 64-bit limit.
    
    Returns:
        Tuple of (current_version, remaining_versions, is_critical)
        
    Example:
        >>> current, remaining, critical = check_version_overflow()
        >>> if critical:
        >>>     print(f"WARNING: Only {remaining} versions left!")
    """
    current = get_current_certificate_version()
    remaining = 64 - current
    is_critical = remaining <= 5
    
    return current, remaining, is_critical
