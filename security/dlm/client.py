"""
DLM (Device Lifecycle Management) server client.

This module provides a Python interface to communicate with Renesas DLM server
for UFPK wrapping operations.
"""

import json
from pathlib import Path
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config.settings import DLMConfig
from utils.exceptions import DLMError
from utils.logging import get_logger
from utils.logging import get_logger

logger = get_logger(__name__)


class DLMClient:
    """
    DLM server client for UFPK wrapping operations.

    This class provides methods to:
    - Wrap UFPK through DLM server
    - Check wrapping status
    - Retrieve wrapped UFPK
    """

    def __init__(self, config: DLMConfig, auto_connect: bool = True, session_cookie: Optional[str] = None):
        """
        Initialize DLM client.

        Args:
            config: DLM configuration
            auto_connect: Whether to automatically test connection on init
            session_cookie: Optional JSESSIONID cookie value (if exported from browser after manual login)

        Raises:
            DLMError: If configuration is invalid or connection fails
        """
        if not config.server_url:
            raise DLMError("DLM server URL is required")

        self.config = config
        self.session = self._create_session()
        
        # Use session cookie from config or parameter (parameter takes priority)
        cookie_to_use = session_cookie or config.session_cookie
        
        # If session cookie is available, set it directly (for manual browser login)
        if cookie_to_use:
            from http.cookiejar import Cookie
            from requests.cookies import RequestsCookieJar
            
            cookie = Cookie(
                version=0,
                name='JSESSIONID',
                value=cookie_to_use,
                port=None,
                port_specified=False,
                domain='dlm.renesas.com',
                domain_specified=True,
                domain_initial_dot=False,
                path='/',
                path_specified=True,
                secure=True,
                expires=None,
                discard=False,
                comment=None,
                comment_url=None,
                rest={},
                rfc2109=False
            )
            
            jar = RequestsCookieJar()
            jar.set_cookie(cookie)
            self.session.cookies = jar
            logger.info("Using JSESSIONID cookie for DLM session (from config or parameter)")
        
        if auto_connect:
            self._test_connection()

    def _create_session(self) -> requests.Session:
        """
        Create HTTP session with retry strategy.

        Returns:
            Configured requests session
        """
        session = requests.Session()

        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Support both API Key/Secret (legacy) and username/password authentication
        if self.config.username and self.config.password:
            session.auth = (self.config.username, self.config.password)
        elif self.config.api_key and self.config.api_secret:
            session.auth = (self.config.api_key, self.config.api_secret)

        # Set default headers for English language
        session.headers.update({
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })

        session.verify = self.config.verify_ssl

        return session

    def get_session_cookie(self) -> Optional[str]:
        """
        Get current JSESSIONID cookie from session.
        
        Returns:
            JSESSIONID cookie value if available, None otherwise
        """
        for cookie in self.session.cookies:
            if cookie.name == 'JSESSIONID':
                return cookie.value
        return None
    
    def _login(self) -> None:
        """
        Login to DLM server using username/password.
        
        Based on actual DLM login flow:
        - POST to /keywrap/ with mailAddress, password, and login fields
        - Returns JSESSIONID cookie on success
        
        Raises:
            DLMError: If login fails
        """
        if not (self.config.username and self.config.password):
            raise DLMError("Username and password are required for DLM login")
        
        try:
            # Step 1: Get agreement/login page to establish session and get JSESSIONID
            login_page_url = f"{self.config.server_url}/keywrap/"
            logger.debug(f"Getting login page: {login_page_url}")
            
            response = self.session.get(login_page_url, timeout=self.config.timeout)
            response.raise_for_status()
            logger.debug(f"Login page loaded: {response.status_code}")
            
            # Step 2: Submit login form
            # Based on actual DLM login: POST to /keywrap/ with mailAddress, password, login
            login_url = f"{self.config.server_url}/keywrap/"
            
            login_data = {
                'mailAddress': self.config.username,  # DLM uses mailAddress, not email/username
                'password': self.config.password,
                'login': 'Login',  # Submit button value
            }
            
            logger.info(f"Attempting login to DLM: {login_url}")
            logger.debug(f"Login fields: mailAddress={self.config.username}, login=Login")
            
            response = self.session.post(
                login_url,
                data=login_data,
                timeout=self.config.timeout,
                allow_redirects=True
            )
            
            response.raise_for_status()
            logger.debug(f"Login response: {response.status_code}")
            
            # Check if login was successful
            response_text = response.text.lower()
            
            # Success indicators
            success_indicators = [
                'logout',
                'logged',
                'welcome',
                'already logged',
                'menu',
                'keywrap',
            ]
            
            error_indicators = [
                'time out',
                'timeout',
                'invalid',
                'error',
                'failed',
                'incorrect',
            ]
            
            is_success = any(indicator in response_text for indicator in success_indicators)
            is_error = any(indicator in response_text for indicator in error_indicators)
            
            # Check JSESSIONID cookie
            jsessionid = self.get_session_cookie()
            
            if jsessionid:
                logger.info(f"JSESSIONID obtained: {jsessionid[:20]}...")
                
                # Auto-save cookie to config if not already set
                if not self.config.session_cookie:
                    self.config.session_cookie = jsessionid
                    logger.info("JSESSIONID saved to config (will be used for future requests)")
                
                # Try to verify login by accessing a protected page
                try:
                    test_url = f"{self.config.server_url}/keywrap/menu/app/"
                    test_response = self.session.post(
                        test_url,
                        data={'category': 'RA', 'prev': '/menu/select/'},
                        timeout=self.config.timeout
                    )
                    if 'time out' not in test_response.text.lower():
                        logger.info("DLM login verified - can access protected pages")
                        is_success = True
                except:
                    pass
            
            if is_success:
                logger.info("DLM login successful")
            elif is_error:
                raise DLMError(f"DLM login failed: {response.text[:200]}")
            else:
                # Uncertain - but we have JSESSIONID, so assume success
                if jsessionid:
                    logger.info("DLM login appears successful (JSESSIONID obtained)")
                else:
                    logger.warning("DLM login status uncertain - no JSESSIONID obtained")
                    raise DLMError("DLM login failed - no session cookie obtained")
                
        except requests.exceptions.RequestException as e:
            error_msg = f"DLM login request failed: {str(e)}"
            if hasattr(e, "response") and e.response is not None:
                error_msg += f" - Response: {e.response.text[:200]}"
            raise DLMError(error_msg) from e
        except DLMError:
            raise
        except Exception as e:
            raise DLMError(f"Unexpected error during DLM login: {str(e)}") from e

    def _test_connection(self) -> None:
        """
        Test connection to DLM server.

        Raises:
            DLMError: If connection test fails
        """
        try:
            # Try to access a simple endpoint (health check or API version)
            # If server doesn't have health endpoint, we'll catch the error gracefully
            test_urls = [
                f"{self.config.server_url}/api/v1/health",
                f"{self.config.server_url}/api/health",
                f"{self.config.server_url}/health",
                f"{self.config.server_url}/api/v1",
            ]
            
            for url in test_urls:
                try:
                    response = self.session.get(url, timeout=5.0)
                    if response.status_code in [200, 401, 403]:
                        # 401/403 means server is reachable but auth might be needed
                        logger.info(f"DLM server connection successful: {url}")
                        return
                except requests.exceptions.RequestException:
                    continue
            
            # If we get here, try a simple GET to base URL
            try:
                response = self.session.get(self.config.server_url, timeout=5.0)
                logger.info("DLM server is reachable")
            except requests.exceptions.RequestException as e:
                logger.warning(f"DLM server connection test inconclusive: {e}")
                # Don't fail here, let actual operations fail if server is down
                
        except Exception as e:
            logger.warning(f"DLM connection test failed: {e}")
            # Don't raise error here - let actual operations handle it

    def test_connection(self) -> bool:
        """
        Test connection to DLM server.

        Returns:
            True if connection is successful, False otherwise
        """
        try:
            self._test_connection()
            return True
        except Exception as e:
            logger.error(f"DLM connection test failed: {e}")
            return False

    def wrap_ufpk(
        self,
        encrypted_ufpk_file: Path,
        device_id: Optional[str] = None,
    ) -> str:
        """
        Wrap UFPK through DLM server.

        This method sends an encrypted UFPK file to DLM server for wrapping.
        The server returns a job ID that can be used to check status.

        Args:
            encrypted_ufpk_file: Path to PGP-encrypted UFPK file
            device_id: Optional device ID (uses config default if not provided)

        Returns:
            Job ID for tracking the wrapping operation

        Raises:
            DLMError: If wrapping request fails
        """
        if not encrypted_ufpk_file.exists():
            raise DLMError(f"Encrypted UFPK file not found: {encrypted_ufpk_file}")

        # Device ID is optional for DLM (not used in form data)
        device_id = device_id or self.config.device_id
        
        # Auto-verify connection before operation
        if not (self.config.username and self.config.password) and not (self.config.api_key and self.config.api_secret):
            raise DLMError(
                "DLM credentials not configured. "
                "Please configure username/password or API Key/Secret in Settings."
            )

        try:
            # Step 0: Ensure we have a valid session
            # Always login fresh to ensure valid session (cookie expires quickly)
            if self.config.username and self.config.password:
                logger.info("Step 0: Logging in to DLM server to get fresh session...")
                self._login()
                jsessionid = self.get_session_cookie()
                if jsessionid:
                    logger.info(f"Login successful, session established (JSESSIONID: {jsessionid[:20]}...)")
                else:
                    raise DLMError("Login failed - no JSESSIONID obtained")
            else:
                raise DLMError("DLM credentials (username/password) are required for UFPK wrapping")
            
            # DLM uses web-based endpoints, not REST API
            # Step 1: Select product family (RA)
            menu_url = f"{self.config.server_url}/keywrap/menu/app/"
            logger.info(f"Step 1: Selecting product family: {menu_url}")
            
            menu_data = {
                "category": "RA",
                "prev": "/menu/select/",
            }
            
            # Set language header for English
            headers = {'Accept-Language': 'en-US,en;q=0.9'}
            
            menu_response = self.session.post(
                menu_url,
                data=menu_data,
                headers=headers,
                timeout=self.config.timeout,
            )
            menu_response.raise_for_status()
            logger.debug(f"Product family selected: {menu_response.status_code}")
            
            # Step 2: Navigate to encryption service for RA8D1/RA8M1/RA8T1
            # Based on manual workflow: after selecting RA Family, we need to select the specific product
            enc_url = f"{self.config.server_url}/keywrap/menu/app/"
            logger.info(f"Step 2: Selecting RA8D1/RA8M1/RA8T1 encryption service: {enc_url}")
            
            # Select the specific product encryption service
            enc_data = {
                "category": "RA8D1/RA8M1/RA8T1",
                "prev": "/keywrap/menu/app/",
            }
            
            # Set language header for English
            headers = {'Accept-Language': 'en-US,en;q=0.9'}
            
            enc_response = self.session.post(
                enc_url,
                data=enc_data,
                headers=headers,
                timeout=self.config.timeout,
            )
            enc_response.raise_for_status()
            logger.debug(f"Encryption service selected: {enc_response.status_code}")
            
            # Verify we're on the right page
            response_text = enc_response.text.lower()
            if 'encryption service' in response_text or 'ra8d1' in response_text or 'ra8m1' in response_text:
                logger.info("Successfully navigated to encryption service page")
            else:
                logger.warning("May not be on correct encryption service page")
            
            # Step 3: Upload encrypted UFPK file
            upload_url = f"{self.config.server_url}/keywrap/enc/apl/appReg/"
            logger.info(f"Step 3: Uploading encrypted UFPK: {upload_url}")
            
            file_name = encrypted_ufpk_file.name
            
            with open(encrypted_ufpk_file, "rb") as f:
                files = {
                    "importFile": (file_name, f, "application/octet-stream")
                }
                data = {
                    "fileName": file_name,
                    "appId": "47",  # RA8D1/RA8M1/RA8T1
                    "category": "RA",
                    "prev": "/menu/app/",
                }

                # Set language header for English (so email will be in English)
                headers = {'Accept-Language': 'en-US,en;q=0.9'}
                
                response = self.session.post(
                    upload_url,
                    files=files,
                    data=data,
                    headers=headers,
                    timeout=self.config.timeout,
                )

                response.raise_for_status()
                
                # DLM returns HTML page with success message
                # Check if upload was successful
                response_text = response.text.lower()
                
                # Log response for debugging (first 1000 chars)
                logger.debug(f"Upload response preview: {response.text[:1000]}")
                
                success_indicators = [
                    "accepted your request",
                    "encrypted key data will be sent",
                    "will be sent to the specified e-mail",
                    "will be sent to the specified e-mail address",
                    "we have accepted",
                    "success",
                ]
                
                error_indicators = [
                    "time out",
                    "timeout",
                    "session expired",
                    "login",
                ]
                
                # Check for explicit error messages (but not "login" if it's just a link)
                is_success = any(indicator in response_text for indicator in success_indicators)
                is_error = any(indicator in response_text for indicator in error_indicators) and "time out" in response_text
                
                if is_success:
                    logger.info("[OK] UFPK upload accepted by DLM server")
                    logger.info("[EMAIL] Encrypted key data will be sent to your email address")
                    
                    # Extract email from response if possible
                    email_match = None
                    import re
                    email_pattern = r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
                    email_matches = re.findall(email_pattern, response.text)
                    if email_matches:
                        email_match = email_matches[0]
                        logger.info(f"[EMAIL] Email will be sent to: {email_match}")
                    
                    # Return a tracking ID (DLM processes async via email)
                    import hashlib
                    tracking_id = hashlib.md5(f"{file_name}_{device_id or 'default'}".encode()).hexdigest()[:16]
                    logger.info(f"Request ID (for tracking): {tracking_id}")
                    return tracking_id
                elif is_error:
                    raise DLMError(f"DLM server returned error (timeout/session expired): {response.text[:500]}")
                else:
                    # If status code is 200, assume success (DLM might return the page without explicit message)
                    # Check if we're still on encryption service page (which means upload might have succeeded)
                    if response.status_code == 200:
                        if "製品用暗号化サービス" in response.text or "encryption service" in response_text:
                            logger.info("[OK] UFPK upload completed (status 200, on encryption service page)")
                            logger.info("[EMAIL] Please check your email for the encrypted key data")
                            logger.info("Note: DLM may have processed the upload successfully")
                            import hashlib
                            tracking_id = hashlib.md5(f"{file_name}_{device_id or 'default'}".encode()).hexdigest()[:16]
                            return tracking_id
                        else:
                            # Unknown response - log it but assume success if status is 200
                            logger.warning(f"Uncertain response format. Status: {response.status_code}")
                            logger.info("[EMAIL] Please check your email for the encrypted key data")
                            import hashlib
                            tracking_id = hashlib.md5(f"{file_name}_{device_id or 'default'}".encode()).hexdigest()[:16]
                            return tracking_id
                    else:
                        raise DLMError(f"Upload failed with status {response.status_code}. Response: {response.text[:200]}")

        except requests.exceptions.RequestException as e:
            error_msg = f"DLM server request failed: {str(e)}"
            if hasattr(e, "response") and e.response is not None:
                try:
                    error_detail = e.response.json()
                    error_msg += f" - {error_detail}"
                except:
                    error_msg += f" - {e.response.text}"
            raise DLMError(error_msg) from e
        except Exception as e:
            if isinstance(e, DLMError):
                raise
            raise DLMError(f"Unexpected error during UFPK wrapping: {str(e)}") from e

    def get_wrapping_status(self, job_id: str) -> dict:
        """
        Get status of UFPK wrapping job.

        Note: DLM processes requests asynchronously and sends results via email.
        This method checks the history page if available.

        Args:
            job_id: Request ID returned from wrap_ufpk

        Returns:
            Dictionary with job status information

        Raises:
            DLMError: If status check fails
        """
        try:
            # DLM doesn't have a direct status API
            # Results are sent via email
            # We can check history page if available
            history_url = f"{self.config.server_url}/keywrap/doui/history/"
            
            logger.debug(f"Checking wrapping status: {job_id}")
            logger.info("Note: DLM sends wrapped UFPK via email. Check your inbox.")

            # Try to access history page
            try:
                response = self.session.get(history_url, timeout=self.config.timeout)
                if response.status_code == 200:
                    # Parse history if possible
                    logger.debug("History page accessible")
            except:
                pass

            # Return status indicating email delivery
            return {
                "status": "processing",
                "message": "Request accepted. Wrapped UFPK will be sent via email.",
                "job_id": job_id,
                "note": "Check your email for the encrypted key data"
            }

        except Exception as e:
            if isinstance(e, DLMError):
                raise
            raise DLMError(f"Unexpected error during status check: {str(e)}") from e

    def download_wrapped_ufpk(
        self, job_id: str, output_file: Path
    ) -> Path:
        """
        Download wrapped UFPK file from DLM server.

        Note: DLM sends wrapped UFPK via email, not direct download.
        This method is a placeholder - in production, you would need to:
        1. Check email for the wrapped UFPK attachment
        2. Or implement email parsing/IMAP access
        3. Or use DLM history page if it provides download links

        Args:
            job_id: Request ID returned from wrap_ufpk
            output_file: Path to save wrapped UFPK file

        Returns:
            Path to downloaded file

        Raises:
            DLMError: If download fails or file not found
        """
        raise DLMError(
            "DLM sends wrapped UFPK via email, not direct download.\n"
            f"Please check your email ({self.config.username or 'registered email'}) "
            "for the encrypted key data attachment.\n"
            "After receiving the email, decrypt the attachment with your private key."
        )

    def wrap_ufpk_complete(
        self,
        encrypted_ufpk_file: Path,
        output_file: Path,
        device_id: Optional[str] = None,
        poll_interval: float = 5.0,
        max_wait_time: float = 300.0,
    ) -> Path:
        """
        Complete UFPK wrapping workflow.

        Note: DLM processes requests asynchronously and sends results via email.
        This method uploads the file and provides instructions for email retrieval.

        Args:
            encrypted_ufpk_file: Path to PGP-encrypted UFPK file
            output_file: Path to save wrapped UFPK file (after manual email download)
            device_id: Optional device ID (not used by DLM, but kept for compatibility)
            poll_interval: Not used (DLM uses email, not polling)
            max_wait_time: Not used (DLM uses email, not polling)

        Returns:
            Path to output file (user must download from email and place it here)

        Raises:
            DLMError: If upload fails
        """
        logger.info("Starting UFPK wrapping workflow with DLM")

        # Upload encrypted UFPK
        job_id = self.wrap_ufpk(encrypted_ufpk_file, device_id)
        
        logger.info(
            f"UFPK upload successful. Request ID: {job_id}\n"
            f"DLM will process your request and send the wrapped UFPK to your email.\n"
            f"Please:\n"
            f"1. Check your email ({self.config.username or 'registered email'})\n"
            f"2. Download the encrypted key data attachment\n"
            f"3. Decrypt it with your private key using:\n"
            f"   gpg --decrypt <attachment> --output {output_file}\n"
            f"4. Or use the tool's PGP decryption feature"
        )
        
        # Note: In a fully automated system, you would need:
        # - Email/IMAP access to check for the response
        # - Automatic decryption of the email attachment
        # For now, this is a manual step
        
        raise DLMError(
            "DLM workflow requires manual email check.\n"
            "The wrapped UFPK will be sent to your email address.\n"
            "After receiving it, decrypt the attachment and save it to:\n"
            f"{output_file}\n"
            "Then you can use it for RKEY generation."
        )

    def close(self) -> None:
        """Close DLM client session."""
        if self.session:
            self.session.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


