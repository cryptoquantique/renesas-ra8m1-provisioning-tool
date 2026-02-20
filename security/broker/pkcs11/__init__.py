"""
Native PKCS#11 implementation for the crypto broker.

This package provides a standards-compliant PKCS#11 interface that
routes cryptographic operations through the broker to AWS KMS.

Implements PKCS#11 v2.40 (OASIS Standard).
"""

from .types import *
from .session import Session
from .token import Token, Slot
from .lib import BrokerPKCS11Lib

__all__ = [
    # Library
    "BrokerPKCS11Lib",
    # Core classes
    "Session",
    "Token",
    "Slot",
    # Types and constants are exported via types module
]
