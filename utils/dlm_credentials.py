"""
DLM credentials loader.

This module provides centralized loading of DLM credentials from a JSON file.
"""

import json
import os
from pathlib import Path
from typing import Optional, Dict

from utils.exceptions import ConfigurationError
from utils.logging import get_logger

logger = get_logger(__name__)

# Default credentials file path
DEFAULT_CREDENTIALS_FILE = Path("project_config.json")


class DLMCredentials:
    """
    DLM credentials container.

    Loads credentials from JSON file with fallback to environment variables.
    """

    def __init__(
        self,
        email: Optional[str] = None,
        password: Optional[str] = None,
        username: Optional[str] = None,
        session_cookie: Optional[str] = None,
        server_url: Optional[str] = None,
    ):
        """
        Initialize DLM credentials.

        Args:
            email: DLM email/username
            password: DLM password
            username: DLM username (alias for email)
            session_cookie: JSESSIONID cookie value (exported from browser)
            server_url: DLM server URL
        """
        self.email = email or username
        self.username = username or email
        self.password = password
        self.session_cookie = session_cookie
        self.server_url = server_url

    def is_complete(self) -> bool:
        """
        Check if credentials are complete.

        Returns:
            True if both username/email and password are set
        """
        return bool((self.username or self.email) and self.password)
    
    def has_session_cookie(self) -> bool:
        """
        Check if session cookie is available.

        Returns:
            True if session cookie is set
        """
        return bool(self.session_cookie)


def load_dlm_credentials(
    credentials_file: Optional[Path] = None,
    fallback_to_env: bool = True,
) -> DLMCredentials:
    """
    Load DLM credentials from JSON file.

    Priority order:
    1. JSON file (if provided and exists)
    2. Environment variables (if fallback_to_env is True)
    3. Default credentials file (aws_credentials.json in current directory)

    Args:
        credentials_file: Path to credentials JSON file (optional)
        fallback_to_env: If True, fall back to environment variables if file not found

    Returns:
        DLMCredentials object with loaded credentials

    Raises:
        ConfigurationError: If credentials cannot be loaded and fallback is disabled
    """
    credentials = DLMCredentials()

    # Try to load from provided file
    if credentials_file and credentials_file.exists():
        try:
            logger.info(f"Loading DLM credentials from {credentials_file}")
            with open(credentials_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Support nested format with "dlm" key
            if "dlm" in data:
                dlm_data = data["dlm"]
                credentials.email = dlm_data.get("email")
                credentials.username = dlm_data.get("username") or dlm_data.get("email")
                credentials.password = dlm_data.get("password")
                credentials.session_cookie = dlm_data.get("session_cookie") or dlm_data.get("jsessionid")
                credentials.server_url = dlm_data.get("server_url")
            else:
                # Old format (flat structure) - not supported for DLM
                logger.warning("DLM credentials not found in file (expected 'dlm' key)")

            if credentials.is_complete():
                logger.info("DLM credentials loaded from file")
                return credentials
            else:
                logger.warning("Incomplete DLM credentials in file, falling back to environment variables")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in credentials file: {str(e)}")
            if not fallback_to_env:
                raise ConfigurationError(f"Invalid JSON in credentials file: {str(e)}") from e
        except Exception as e:
            logger.error(f"Error loading credentials file: {str(e)}")
            if not fallback_to_env:
                raise ConfigurationError(f"Error loading credentials file: {str(e)}") from e

    # Try default credentials file
    if not credentials.is_complete() and DEFAULT_CREDENTIALS_FILE.exists():
        try:
            logger.info(f"Loading DLM credentials from default file: {DEFAULT_CREDENTIALS_FILE}")
            with open(DEFAULT_CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Support nested format with "dlm" key
            if "dlm" in data:
                dlm_data = data["dlm"]
                credentials.email = dlm_data.get("email")
                credentials.username = dlm_data.get("username") or dlm_data.get("email")
                credentials.password = dlm_data.get("password")
                credentials.session_cookie = dlm_data.get("session_cookie") or dlm_data.get("jsessionid")
                credentials.server_url = dlm_data.get("server_url")

            if credentials.is_complete():
                logger.info("DLM credentials loaded from default file")
                if credentials.has_session_cookie():
                    logger.info("DLM session cookie found in file")
                return credentials

        except Exception as e:
            logger.warning(f"Could not load default credentials file: {str(e)}")

    # Fall back to environment variables
    if fallback_to_env:
        logger.info("Loading DLM credentials from environment variables")
        credentials.email = os.getenv("DLM_EMAIL") or os.getenv("DLM_USERNAME")
        credentials.username = os.getenv("DLM_USERNAME") or os.getenv("DLM_EMAIL")
        credentials.password = os.getenv("DLM_PASSWORD")
        credentials.session_cookie = os.getenv("DLM_SESSION_COOKIE") or os.getenv("DLM_JSESSIONID")

        if credentials.is_complete():
            logger.info("DLM credentials loaded from environment variables")
            if credentials.has_session_cookie():
                logger.info("DLM session cookie found in environment")
            return credentials

    # No credentials found
    if not credentials.is_complete():
        error_msg = (
            "DLM credentials not found. "
            "Please provide credentials via:\n"
            "1. JSON file: project_config.json (with 'dlm' key)\n"
            "2. Environment variables: DLM_EMAIL/DLM_USERNAME, DLM_PASSWORD"
        )
        logger.error(error_msg)
        raise ConfigurationError(error_msg)

    return credentials


def get_dlm_credentials(
    credentials_file: Optional[Path] = None,
    fallback_to_env: bool = True,
) -> Dict[str, Optional[str]]:
    """
    Get DLM credentials as dictionary.

    Args:
        credentials_file: Path to credentials JSON file (optional)
        fallback_to_env: If True, fall back to environment variables

    Returns:
        Dictionary with username, password, email, and session_cookie
    """
    credentials = load_dlm_credentials(credentials_file, fallback_to_env)
    return {
        "username": credentials.username or credentials.email,
        "password": credentials.password,
        "email": credentials.email,
        "session_cookie": credentials.session_cookie,
    }


def save_dlm_session_cookie(
    session_cookie: str,
    credentials_file: Optional[Path] = None,
) -> None:
    """
    Save DLM session cookie to credentials file.

    Args:
        session_cookie: JSESSIONID cookie value
        credentials_file: Path to credentials JSON file (defaults to project_config.json)

    Raises:
        ConfigurationError: If file cannot be written
    """
    if not credentials_file:
        credentials_file = DEFAULT_CREDENTIALS_FILE
    
    try:
        # Load existing file or create new structure
        if credentials_file.exists():
            with open(credentials_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = {}
        
        # Ensure "dlm" key exists
        if "dlm" not in data:
            data["dlm"] = {}
        
        # Update session cookie
        data["dlm"]["session_cookie"] = session_cookie
        data["dlm"]["jsessionid"] = session_cookie  # Also save as jsessionid for compatibility
        
        # Write back to file
        with open(credentials_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"DLM session cookie saved to {credentials_file}")
        
    except Exception as e:
        error_msg = f"Failed to save DLM session cookie: {str(e)}"
        logger.error(error_msg)
        raise ConfigurationError(error_msg) from e

