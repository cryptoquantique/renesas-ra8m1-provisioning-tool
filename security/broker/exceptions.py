"""
Broker-specific exception classes.

This module defines exceptions for the crypto broker service,
extending the base SecurityError hierarchy.
"""

from utils.exceptions import SecurityError


class BrokerError(SecurityError):
    """
    Base exception for crypto broker operations.

    Raised when broker service operations fail, including:
    - Connection failures
    - Protocol errors
    - Backend (KMS) communication errors
    - Session management errors
    """

    def __init__(self, message: str, details: dict = None, error_code: int = None):
        """
        Initialize BrokerError.

        Args:
            message: Human-readable error message
            details: Optional dictionary with additional error details
            error_code: Optional JSON-RPC error code
        """
        super().__init__(message, details)
        self.error_code = error_code


class AuthorizationError(BrokerError):
    """
    Raised when client authorization fails.

    This includes:
    - Client identity verification failures
    - Policy violations (unauthorized operations)
    - Key ARN access denials
    - Session authentication failures
    """

    def __init__(
        self,
        message: str,
        client_id: str = None,
        operation: str = None,
        resource: str = None,
        details: dict = None,
    ):
        """
        Initialize AuthorizationError.

        Args:
            message: Human-readable error message
            client_id: Identifier of the client that was denied
            operation: The operation that was denied
            resource: The resource (e.g., key ARN) that was denied
            details: Optional dictionary with additional error details
        """
        error_details = details or {}
        if client_id:
            error_details["client_id"] = client_id
        if operation:
            error_details["operation"] = operation
        if resource:
            error_details["resource"] = resource

        super().__init__(message, error_details, error_code=-32001)
        self.client_id = client_id
        self.operation = operation
        self.resource = resource


class ConnectionError(BrokerError):
    """Raised when IPC connection fails."""

    def __init__(self, message: str, details: dict = None):
        super().__init__(message, details, error_code=-32002)


class SessionError(BrokerError):
    """Raised when session operations fail."""

    def __init__(self, message: str, session_id: str = None, details: dict = None):
        error_details = details or {}
        if session_id:
            error_details["session_id"] = session_id
        super().__init__(message, error_details, error_code=-32003)
        self.session_id = session_id


class ProtocolError(BrokerError):
    """Raised when JSON-RPC protocol errors occur."""

    def __init__(self, message: str, details: dict = None):
        super().__init__(message, details, error_code=-32600)
