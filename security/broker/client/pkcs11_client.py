"""
PKCS#11-like client interface for the crypto broker.

.. deprecated::
    This module is DEPRECATED. Use the native PKCS#11 interface instead:

    - For HSM operations: security.hsm.broker_client.BrokerHSMClient
    - For direct PKCS#11: security.broker.pkcs11.BrokerPKCS11Lib

    The native PKCS#11 implementation provides:
    - Standard PKCS#11 v2.40 compliant interface
    - Proper CK_* types and return codes
    - Better integration with the broker service

This module provides a high-level client API that mimics PKCS#11
function names for familiarity, while communicating with the
broker service over IPC using JSON-RPC.
"""

import warnings
import base64
from typing import Optional, Dict, Any, List

from security.broker.protocol import (
    BrokerMethod,
    BrokerRequest,
    BrokerResponse,
    BrokerErrorCode,
)
from security.broker.exceptions import BrokerError, AuthorizationError, SessionError
from .transport import IPCTransport, create_transport
from utils.logging import get_logger

logger = get_logger(__name__)


class BrokerPKCS11Client:
    """
    PKCS#11-like client for the crypto broker.

    Provides methods that map conceptually to PKCS#11 functions:
    - C_Initialize / C_Finalize
    - C_OpenSession / C_CloseSession
    - C_Login / C_Logout
    - C_Sign / C_Verify
    - C_GetAttributeValue (for public key retrieval)

    Usage:
        with BrokerPKCS11Client() as client:
            client.C_OpenSession()
            client.C_Login()
            signature = client.C_Sign(key_arn, data)
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        timeout: float = 30.0,
        auto_connect: bool = True,
    ):
        """
        Initialize broker client.

        .. deprecated::
            Use security.broker.pkcs11.BrokerPKCS11Lib or
            security.hsm.broker_client.BrokerHSMClient instead.

        Args:
            socket_path: Broker socket/pipe path (uses default if not specified)
            timeout: Request timeout in seconds
            auto_connect: If True, connect on first operation
        """
        warnings.warn(
            "BrokerPKCS11Client is deprecated. Use BrokerPKCS11Lib from "
            "security.broker.pkcs11 or BrokerHSMClient from security.hsm.broker_client "
            "for native PKCS#11 support.",
            DeprecationWarning,
            stacklevel=2
        )
        self._transport: Optional[IPCTransport] = None
        self._socket_path = socket_path
        self._timeout = timeout
        self._auto_connect = auto_connect

        self._session_id: Optional[str] = None
        self._logged_in = False
        self._request_id = 0

    def _get_transport(self) -> IPCTransport:
        """Get or create transport."""
        if self._transport is None:
            self._transport = create_transport(self._socket_path, self._timeout)
        return self._transport

    def _ensure_connected(self) -> None:
        """Ensure transport is connected."""
        transport = self._get_transport()
        if not transport.is_connected:
            if self._auto_connect:
                transport.connect()
            else:
                raise BrokerError("Not connected to broker")

    def _send_request(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """
        Send request and wait for response.

        Args:
            method: Method name
            params: Method parameters

        Returns:
            Result from response

        Raises:
            BrokerError: If request fails
        """
        self._ensure_connected()

        # Generate request ID
        self._request_id += 1
        request_id = self._request_id

        # Build request
        request = BrokerRequest(
            method=method,
            params=params,
            id=request_id,
        )

        # Send request
        transport = self._get_transport()
        transport.send(request.to_json().encode("utf-8"))

        # Receive response
        response_data = transport.receive()
        response = BrokerResponse.from_json(response_data.decode("utf-8"))

        # Check for errors
        if response.error:
            error = response.error
            if error.code == BrokerErrorCode.AUTHORIZATION_ERROR:
                raise AuthorizationError(
                    error.message,
                    details=error.data,
                )
            elif error.code == BrokerErrorCode.SESSION_ERROR:
                raise SessionError(
                    error.message,
                    details=error.data,
                )
            else:
                raise BrokerError(
                    error.message,
                    details=error.data,
                    error_code=error.code,
                )

        return response.result

    # --- PKCS#11-like Methods ---

    def C_Initialize(self) -> Dict[str, Any]:
        """
        Initialize the crypto broker connection (PKCS#11 C_Initialize).

        Returns:
            Initialization info including version and client ID
        """
        result = self._send_request(BrokerMethod.INITIALIZE.value)
        logger.debug(f"Initialized: {result}")
        return result

    def C_Finalize(self) -> None:
        """
        Finalize the crypto broker connection (PKCS#11 C_Finalize).

        Closes any open session and disconnects.
        """
        try:
            self._send_request(BrokerMethod.FINALIZE.value)
        except Exception:
            pass
        finally:
            self._session_id = None
            self._logged_in = False
            if self._transport:
                self._transport.disconnect()
                self._transport = None

    def C_OpenSession(self) -> str:
        """
        Open a session with the broker (PKCS#11 C_OpenSession).

        Returns:
            Session ID

        Raises:
            SessionError: If session creation fails
        """
        result = self._send_request(BrokerMethod.OPEN_SESSION.value)
        self._session_id = result["session_id"]
        logger.debug(f"Opened session: {self._session_id}")
        return self._session_id

    def C_CloseSession(self, session_id: Optional[str] = None) -> None:
        """
        Close a session (PKCS#11 C_CloseSession).

        Args:
            session_id: Session to close (uses current if not specified)
        """
        sid = session_id or self._session_id
        if sid:
            self._send_request(
                BrokerMethod.CLOSE_SESSION.value,
                {"session_id": sid},
            )
            if sid == self._session_id:
                self._session_id = None
                self._logged_in = False
            logger.debug(f"Closed session: {sid}")

    def C_Login(self, session_id: Optional[str] = None) -> None:
        """
        Log in to a session (PKCS#11 C_Login).

        This performs authorization checks and enables
        cryptographic operations for the session.

        Args:
            session_id: Session to log into (uses current if not specified)

        Raises:
            AuthorizationError: If login fails
        """
        sid = session_id or self._session_id
        if not sid:
            raise SessionError("No session - call C_OpenSession first")

        result = self._send_request(
            BrokerMethod.LOGIN.value,
            {"session_id": sid},
        )
        self._logged_in = True
        logger.debug(f"Logged in to session: {sid}")

    def C_Logout(self) -> None:
        """
        Log out from current session (PKCS#11 C_Logout).
        """
        if self._session_id:
            self._send_request(BrokerMethod.LOGOUT.value)
            self._logged_in = False
            logger.debug("Logged out")

    def C_Sign(
        self,
        key_arn: str,
        data: bytes,
    ) -> bytes:
        """
        Sign data with a key (PKCS#11 C_Sign).

        The data will be hashed before signing.

        Args:
            key_arn: KMS key ARN or alias
            data: Data to sign

        Returns:
            Signature bytes (DER-encoded for ECDSA)

        Raises:
            AuthorizationError: If not authorized
            BrokerError: If signing fails
        """
        result = self._send_request(
            BrokerMethod.SIGN.value,
            {
                "key_arn": key_arn,
                "data": base64.b64encode(data).decode("ascii"),
            },
        )
        return base64.b64decode(result["signature"])

    def C_SignDigest(
        self,
        key_arn: str,
        digest: bytes,
    ) -> bytes:
        """
        Sign a pre-computed digest (extension to C_Sign).

        Use this for MCUboot signing to avoid double-hashing.

        Args:
            key_arn: KMS key ARN or alias
            digest: Pre-computed hash digest

        Returns:
            Signature bytes (DER-encoded for ECDSA)

        Raises:
            AuthorizationError: If not authorized
            BrokerError: If signing fails
        """
        result = self._send_request(
            BrokerMethod.SIGN_DIGEST.value,
            {
                "key_arn": key_arn,
                "digest": base64.b64encode(digest).decode("ascii"),
            },
        )
        return base64.b64decode(result["signature"])

    def C_Verify(
        self,
        key_arn: str,
        data: bytes,
        signature: bytes,
    ) -> bool:
        """
        Verify a signature (PKCS#11 C_Verify).

        Args:
            key_arn: KMS key ARN or alias
            data: Original data
            signature: Signature to verify

        Returns:
            True if signature is valid

        Raises:
            AuthorizationError: If not authorized
            BrokerError: If verification fails
        """
        result = self._send_request(
            BrokerMethod.VERIFY.value,
            {
                "key_arn": key_arn,
                "data": base64.b64encode(data).decode("ascii"),
                "signature": base64.b64encode(signature).decode("ascii"),
            },
        )
        return result["valid"]

    def C_DigestData(
        self,
        data: bytes,
        algorithm: str = "SHA256",
    ) -> bytes:
        """
        Compute hash of data (maps to C_Digest).

        Args:
            data: Data to hash
            algorithm: Hash algorithm (SHA256, SHA384, SHA512)

        Returns:
            Hash digest bytes
        """
        result = self._send_request(
            BrokerMethod.HASH.value,
            {
                "data": base64.b64encode(data).decode("ascii"),
                "algorithm": algorithm,
            },
        )
        return base64.b64decode(result["digest"])

    def C_GetPublicKey(self, key_arn: str) -> bytes:
        """
        Get public key (maps to C_GetAttributeValue for public key).

        Args:
            key_arn: KMS key ARN or alias

        Returns:
            Public key bytes in DER format

        Raises:
            AuthorizationError: If not authorized
            BrokerError: If retrieval fails
        """
        result = self._send_request(
            BrokerMethod.GET_PUBLIC_KEY.value,
            {"key_arn": key_arn},
        )
        return base64.b64decode(result["public_key"])

    def C_ListKeys(self) -> List[Dict[str, Any]]:
        """
        List available keys.

        Returns:
            List of key info dictionaries
        """
        result = self._send_request(BrokerMethod.LIST_KEYS.value)
        return result["keys"]

    # --- Utility Methods ---

    def ping(self) -> Dict[str, Any]:
        """
        Ping the broker service.

        Returns:
            Ping response with timestamp
        """
        return self._send_request(BrokerMethod.PING.value)

    def get_info(self) -> Dict[str, Any]:
        """
        Get broker service information.

        Returns:
            Info dictionary with version, backend, sessions
        """
        return self._send_request(BrokerMethod.GET_INFO.value)

    @property
    def is_connected(self) -> bool:
        """Check if connected to broker."""
        return self._transport is not None and self._transport.is_connected

    @property
    def is_logged_in(self) -> bool:
        """Check if logged in to a session."""
        return self._logged_in

    @property
    def session_id(self) -> Optional[str]:
        """Get current session ID."""
        return self._session_id

    # --- Context Manager ---

    def __enter__(self):
        """Context manager entry - connect to broker."""
        self._get_transport().connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - finalize and disconnect."""
        try:
            self.C_Finalize()
        except Exception:
            pass
