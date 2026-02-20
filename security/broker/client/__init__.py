"""
Crypto Broker Client components.

This package contains the client-side implementation for connecting
to the crypto broker service, including:
- IPC transport abstraction (Unix sockets, Named Pipes)
- Native PKCS#11 interface (recommended)
- Legacy PKCS#11-like client (deprecated)

RECOMMENDED: Use the native PKCS#11 interface from security.broker.pkcs11:

    from security.broker.pkcs11 import BrokerPKCS11Lib

Or use BrokerHSMClient for a higher-level interface:

    from security.hsm.broker_client import BrokerHSMClient
"""

from .transport import IPCTransport, UnixSocketTransport, create_transport

# Deprecated - use security.broker.pkcs11.BrokerPKCS11Lib instead
from .pkcs11_client import BrokerPKCS11Client

__all__ = [
    # Transport (still used by native PKCS#11)
    "IPCTransport",
    "UnixSocketTransport",
    "create_transport",
    # Deprecated client
    "BrokerPKCS11Client",
]
