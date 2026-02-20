"""
Request handler for the crypto broker service.

This module dispatches JSON-RPC requests to the appropriate
backend operations and manages session state.
"""

import base64
import time
from typing import Any, Dict, Optional, Callable

from security.broker.protocol import (
    BrokerMethod,
    BrokerRequest,
    BrokerResponse,
    BrokerErrorCode,
)
from security.broker.auth import ClientIdentity
from security.broker.exceptions import BrokerError, AuthorizationError
from .kms_backend import KMSBackend
from .session import ClientSession, SessionManager, SessionState
from utils.logging import get_logger

logger = get_logger(__name__)


class RequestHandler:
    """
    Handles JSON-RPC requests from broker clients.

    Dispatches requests to the KMS backend and manages
    session lifecycle and authorization.
    """

    def __init__(
        self,
        kms_backend: KMSBackend,
        session_manager: SessionManager,
        authorization_manager: Optional[Any] = None,
    ):
        """
        Initialize request handler.

        Args:
            kms_backend: KMS backend for crypto operations
            session_manager: Session manager for client sessions
            authorization_manager: Optional authorization manager for policy checks
        """
        self.kms_backend = kms_backend
        self.session_manager = session_manager
        self.authorization_manager = authorization_manager

        # Method dispatch table
        self._methods: Dict[str, Callable] = {
            BrokerMethod.INITIALIZE.value: self._handle_initialize,
            BrokerMethod.FINALIZE.value: self._handle_finalize,
            BrokerMethod.OPEN_SESSION.value: self._handle_open_session,
            BrokerMethod.CLOSE_SESSION.value: self._handle_close_session,
            BrokerMethod.LOGIN.value: self._handle_login,
            BrokerMethod.LOGOUT.value: self._handle_logout,
            BrokerMethod.SIGN.value: self._handle_sign,
            BrokerMethod.SIGN_DIGEST.value: self._handle_sign_digest,
            BrokerMethod.VERIFY.value: self._handle_verify,
            BrokerMethod.HASH.value: self._handle_hash,
            BrokerMethod.GET_PUBLIC_KEY.value: self._handle_get_public_key,
            BrokerMethod.LIST_KEYS.value: self._handle_list_keys,
            BrokerMethod.GENERATE_KEY_PAIR.value: self._handle_generate_key_pair,
            BrokerMethod.PING.value: self._handle_ping,
            BrokerMethod.GET_INFO.value: self._handle_get_info,
        }

    def handle_request(
        self,
        request: BrokerRequest,
        client_identity: ClientIdentity,
        session: Optional[ClientSession] = None,
    ) -> BrokerResponse:
        """
        Handle a JSON-RPC request.

        Args:
            request: Parsed JSON-RPC request
            client_identity: Authenticated client identity
            session: Optional existing session

        Returns:
            JSON-RPC response
        """
        try:
            # Validate request
            if request.jsonrpc != "2.0":
                return BrokerResponse.failure(
                    request.id,
                    BrokerErrorCode.INVALID_REQUEST,
                    "Invalid JSON-RPC version",
                )

            # Get method handler
            handler = self._methods.get(request.method)
            if handler is None:
                return BrokerResponse.failure(
                    request.id,
                    BrokerErrorCode.METHOD_NOT_FOUND,
                    f"Method not found: {request.method}",
                )

            # Execute handler
            params = request.params or {}
            result = handler(params, client_identity, session)

            return BrokerResponse.success(request.id, result)

        except AuthorizationError as e:
            logger.warning(
                f"Authorization error for client {client_identity.client_id}: {e}"
            )
            return BrokerResponse.failure(
                request.id,
                BrokerErrorCode.AUTHORIZATION_ERROR,
                str(e),
                e.details,
            )

        except BrokerError as e:
            logger.error(f"Broker error: {e}")
            return BrokerResponse.failure(
                request.id,
                e.error_code or BrokerErrorCode.INTERNAL_ERROR,
                str(e),
                e.details,
            )

        except Exception as e:
            logger.exception(f"Unexpected error handling request: {e}")
            return BrokerResponse.failure(
                request.id,
                BrokerErrorCode.INTERNAL_ERROR,
                f"Internal error: {str(e)}",
            )

    def _check_authorization(
        self,
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
        operation: str,
        key_arn: Optional[str] = None,
    ) -> None:
        """
        Check if client is authorized for operation.

        Args:
            client_identity: Client identity
            session: Client session (must be logged in)
            operation: Operation name
            key_arn: Optional key ARN for key-specific operations

        Raises:
            AuthorizationError: If not authorized
        """
        # Require logged-in session for crypto operations
        if operation in ("sign", "sign_digest", "verify", "hash", "get_public_key", "generate_key_pair"):
            if session is None or not session.is_logged_in:
                raise AuthorizationError(
                    "Session not logged in",
                    client_id=client_identity.client_id,
                    operation=operation,
                )

        # Check authorization policy if manager is configured
        if self.authorization_manager:
            self.authorization_manager.check_authorization(
                client_identity, operation, key_arn
            )

    # --- Session Management Methods ---

    def _handle_initialize(
        self,
        params: Dict[str, Any],
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
    ) -> Dict[str, Any]:
        """Handle initialize (handshake) request."""
        return {
            "status": "ok",
            "version": "1.0",
            "client_id": client_identity.client_id,
            "server_time": time.time(),
        }

    def _handle_finalize(
        self,
        params: Dict[str, Any],
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
    ) -> Dict[str, Any]:
        """Handle finalize request."""
        # Close session if exists
        if session:
            self.session_manager.close_session(session.session_id)

        return {"status": "ok"}

    def _handle_open_session(
        self,
        params: Dict[str, Any],
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
    ) -> Dict[str, Any]:
        """Handle open_session request."""
        new_session = self.session_manager.create_session(client_identity)
        new_session.authenticate()

        return {
            "session_id": new_session.session_id,
            "state": new_session.state.value,
        }

    def _handle_close_session(
        self,
        params: Dict[str, Any],
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
    ) -> Dict[str, Any]:
        """Handle close_session request."""
        session_id = params.get("session_id")
        if not session_id:
            if session:
                session_id = session.session_id
            else:
                raise BrokerError("No session_id provided")

        closed = self.session_manager.close_session(session_id)
        return {"status": "ok" if closed else "not_found"}

    def _handle_login(
        self,
        params: Dict[str, Any],
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
    ) -> Dict[str, Any]:
        """Handle login request (authorization check)."""
        session_id = params.get("session_id")

        if session_id:
            session = self.session_manager.get_session(session_id)

        if session is None:
            raise BrokerError("Invalid or expired session")

        # Verify session belongs to this client
        if session.client_identity.client_id != client_identity.client_id:
            raise AuthorizationError(
                "Session does not belong to this client",
                client_id=client_identity.client_id,
            )

        # Check authorization if manager configured
        if self.authorization_manager:
            self.authorization_manager.check_client_allowed(client_identity)

        # Mark session as logged in
        session.login()

        return {
            "status": "ok",
            "session_id": session.session_id,
            "state": session.state.value,
        }

    def _handle_logout(
        self,
        params: Dict[str, Any],
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
    ) -> Dict[str, Any]:
        """Handle logout request."""
        if session:
            session.logout()
            return {
                "status": "ok",
                "session_id": session.session_id,
                "state": session.state.value,
            }
        return {"status": "no_session"}

    # --- Cryptographic Operations ---

    def _handle_sign(
        self,
        params: Dict[str, Any],
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
    ) -> Dict[str, Any]:
        """Handle sign request (data will be hashed then signed)."""
        key_arn = params.get("key_arn")
        data_b64 = params.get("data")

        if not key_arn:
            raise BrokerError("Missing key_arn parameter")
        if not data_b64:
            raise BrokerError("Missing data parameter")

        # Authorization check
        self._check_authorization(client_identity, session, "sign", key_arn)

        # Decode data
        data = base64.b64decode(data_b64)

        # Sign
        signature = self.kms_backend.sign(key_arn, data)

        # Update session activity
        if session:
            session.touch()

        return {
            "signature": base64.b64encode(signature).decode("ascii"),
            "key_arn": key_arn,
        }

    def _handle_sign_digest(
        self,
        params: Dict[str, Any],
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
    ) -> Dict[str, Any]:
        """Handle sign_digest request (pre-hashed data signed directly)."""
        key_arn = params.get("key_arn")
        digest_b64 = params.get("digest")

        if not key_arn:
            raise BrokerError("Missing key_arn parameter")
        if not digest_b64:
            raise BrokerError("Missing digest parameter")

        # Authorization check
        self._check_authorization(client_identity, session, "sign_digest", key_arn)

        # Decode digest
        digest = base64.b64decode(digest_b64)

        # Sign digest
        signature = self.kms_backend.sign_digest(key_arn, digest)

        # Update session activity
        if session:
            session.touch()

        return {
            "signature": base64.b64encode(signature).decode("ascii"),
            "key_arn": key_arn,
        }

    def _handle_verify(
        self,
        params: Dict[str, Any],
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
    ) -> Dict[str, Any]:
        """Handle verify request."""
        key_arn = params.get("key_arn")
        data_b64 = params.get("data")
        signature_b64 = params.get("signature")

        if not key_arn:
            raise BrokerError("Missing key_arn parameter")
        if not data_b64:
            raise BrokerError("Missing data parameter")
        if not signature_b64:
            raise BrokerError("Missing signature parameter")

        # Authorization check
        self._check_authorization(client_identity, session, "verify", key_arn)

        # Decode data and signature
        data = base64.b64decode(data_b64)
        signature = base64.b64decode(signature_b64)

        # Verify
        is_valid = self.kms_backend.verify(key_arn, data, signature)

        # Update session activity
        if session:
            session.touch()

        return {
            "valid": is_valid,
            "key_arn": key_arn,
        }

    def _handle_hash(
        self,
        params: Dict[str, Any],
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
    ) -> Dict[str, Any]:
        """Handle hash request."""
        data_b64 = params.get("data")
        algorithm = params.get("algorithm", "SHA256")

        if not data_b64:
            raise BrokerError("Missing data parameter")

        # Authorization check (less strict - no key involved)
        self._check_authorization(client_identity, session, "hash")

        # Decode data
        data = base64.b64decode(data_b64)

        # Hash
        digest = self.kms_backend.hash_data(data, algorithm)

        # Update session activity
        if session:
            session.touch()

        return {
            "digest": base64.b64encode(digest).decode("ascii"),
            "algorithm": algorithm,
        }

    def _handle_get_public_key(
        self,
        params: Dict[str, Any],
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
    ) -> Dict[str, Any]:
        """Handle get_public_key request."""
        key_arn = params.get("key_arn")

        if not key_arn:
            raise BrokerError("Missing key_arn parameter")

        # Authorization check
        self._check_authorization(client_identity, session, "get_public_key", key_arn)

        # Get public key
        public_key = self.kms_backend.get_public_key(key_arn)

        # Update session activity
        if session:
            session.touch()

        return {
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "key_arn": key_arn,
            "format": "DER",
        }

    def _handle_list_keys(
        self,
        params: Dict[str, Any],
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
    ) -> Dict[str, Any]:
        """Handle list_keys request."""
        # Authorization check (no specific key)
        self._check_authorization(client_identity, session, "list_keys")

        # List keys
        keys = self.kms_backend.list_keys()

        # Update session activity
        if session:
            session.touch()

        return {"keys": keys}

    def _handle_generate_key_pair(
        self,
        params: Dict[str, Any],
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
    ) -> Dict[str, Any]:
        """Handle generate_key_pair request."""
        key_type = params.get("key_type")
        curve = params.get("curve", "secp256r1")
        label = params.get("label")

        if not key_type:
            raise BrokerError("Missing key_type parameter")

        # Authorization check
        self._check_authorization(client_identity, session, "generate_key_pair")

        # Generate key pair
        result = self.kms_backend.generate_key_pair(
            key_type=key_type,
            curve=curve,
            label=label,
        )

        # Update session activity
        if session:
            session.touch()

        return result

    # --- Service Management ---

    def _handle_ping(
        self,
        params: Dict[str, Any],
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
    ) -> Dict[str, Any]:
        """Handle ping request."""
        return {
            "pong": True,
            "timestamp": time.time(),
        }

    def _handle_get_info(
        self,
        params: Dict[str, Any],
        client_identity: ClientIdentity,
        session: Optional[ClientSession],
    ) -> Dict[str, Any]:
        """Handle get_info request."""
        return {
            "version": "1.0",
            "backend": self.kms_backend.get_info(),
            "sessions": {
                "count": self.session_manager.session_count,
                "max": self.session_manager.max_sessions,
            },
            "client": {
                "id": client_identity.client_id,
                "platform": client_identity.platform,
            },
        }
