"""
Crypto Broker Service.

This module provides a local authenticated crypto broker service that mediates
between Python clients and AWS KMS, exposing a PKCS#11-like API over platform-specific
IPC (Unix sockets on Linux, Named Pipes on Windows) with OS-level client authentication.
"""

from .exceptions import BrokerError, AuthorizationError
from .protocol import (
    BrokerMethod,
    BrokerRequest,
    BrokerResponse,
    BrokerErrorCode,
)
from .auth import ClientIdentity, get_peer_credentials

__all__ = [
    "BrokerError",
    "AuthorizationError",
    "BrokerMethod",
    "BrokerRequest",
    "BrokerResponse",
    "BrokerErrorCode",
    "ClientIdentity",
    "get_peer_credentials",
]
