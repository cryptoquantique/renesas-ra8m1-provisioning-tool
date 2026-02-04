"""
DLM session management utilities.

This module provides utilities for managing DLM session cookies,
including automatic cookie refresh and validation.
"""

from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta

from utils.dlm_credentials import (
    load_dlm_credentials,
    save_dlm_session_cookie,
    DEFAULT_CREDENTIALS_FILE,
)
from utils.logging import get_logger
from security.dlm.client import DLMClient
from config.settings import DLMConfig

logger = get_logger(__name__)


def refresh_dlm_session(
    credentials_file: Optional[Path] = None,
    force: bool = False,
) -> Optional[str]:
    """
    Refresh DLM session cookie by attempting login.
    
    This function tries to login to DLM and obtain a fresh JSESSIONID.
    The cookie is automatically saved to the credentials file.
    
    Args:
        credentials_file: Path to credentials JSON file
        force: If True, refresh even if cookie exists and is recent
        
    Returns:
        JSESSIONID cookie value if successful, None otherwise
    """
    if not credentials_file:
        credentials_file = Path.cwd() / DEFAULT_CREDENTIALS_FILE
    
    try:
        # Load credentials
        dlm_creds = load_dlm_credentials(credentials_file, fallback_to_env=False)
        
        if not dlm_creds.is_complete():
            logger.error("DLM credentials incomplete - cannot refresh session")
            return None
        
        # Check if we have a recent cookie (less than 1 hour old)
        if not force and dlm_creds.has_session_cookie():
            logger.info("Existing session cookie found - skipping refresh")
            logger.info("Use force=True to force refresh")
            return dlm_creds.session_cookie
        
        # Create DLM config
        config = DLMConfig(
            server_url="https://dlm.renesas.com",
            username=dlm_creds.username or dlm_creds.email,
            password=dlm_creds.password,
        )
        
        # Try to login and get session
        logger.info("Attempting to refresh DLM session...")
        client = DLMClient(config, auto_connect=False)
        
        # Try login
        try:
            client._login()
        except Exception as e:
            logger.warning(f"Login attempt failed: {e}")
            logger.warning("DLM login may require JavaScript - manual login recommended")
        
        # Get JSESSIONID from session
        jsessionid = client.get_session_cookie()
        
        if jsessionid:
            # Save to credentials file
            save_dlm_session_cookie(jsessionid, credentials_file)
            logger.info(f"Session cookie refreshed and saved: {jsessionid[:20]}...")
            return jsessionid
        else:
            logger.warning("No JSESSIONID obtained after login attempt")
            logger.warning("DLM may require manual login - use export_dlm_cookie.py")
            return None
            
    except Exception as e:
        logger.error(f"Failed to refresh DLM session: {e}")
        return None
    finally:
        if 'client' in locals():
            client.close()


def get_valid_dlm_session_cookie(
    credentials_file: Optional[Path] = None,
    auto_refresh: bool = True,
) -> Optional[str]:
    """
    Get a valid DLM session cookie, refreshing if necessary.
    
    This function:
    1. Checks if a session cookie exists in credentials file
    2. If auto_refresh is True and cookie is missing/invalid, attempts to refresh
    3. Returns the cookie value
    
    Args:
        credentials_file: Path to credentials JSON file
        auto_refresh: If True, automatically refresh cookie if missing
        
    Returns:
        JSESSIONID cookie value if available, None otherwise
    """
    if not credentials_file:
        credentials_file = Path.cwd() / DEFAULT_CREDENTIALS_FILE
    
    try:
        # Load credentials
        dlm_creds = load_dlm_credentials(credentials_file, fallback_to_env=False)
        
        # Check if we have a cookie
        if dlm_creds.has_session_cookie():
            logger.debug("Using existing session cookie from credentials file")
            return dlm_creds.session_cookie
        
        # No cookie found - try to refresh if auto_refresh is enabled
        if auto_refresh:
            logger.info("No session cookie found - attempting to refresh...")
            return refresh_dlm_session(credentials_file, force=True)
        else:
            logger.warning("No session cookie found and auto_refresh is disabled")
            logger.warning("Please run 'python tests/export_dlm_cookie.py' to export cookie manually")
            return None
            
    except Exception as e:
        logger.error(f"Failed to get DLM session cookie: {e}")
        return None


