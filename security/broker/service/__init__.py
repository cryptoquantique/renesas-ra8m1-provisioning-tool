"""
Crypto Broker Service components.

This package contains the server-side implementation of the
crypto broker service, including:
- KMS backend wrapper
- Session management
- Request handling
- Daemon process management (Unix and Windows)
- Windows Named Pipe security (ACLs)
- Windows Service (SCM) integration
"""

import sys

from .kms_backend import KMSBackend
from .session import ClientSession, SessionManager
from .handler import RequestHandler

__all__ = [
    "KMSBackend",
    "ClientSession",
    "SessionManager",
    "RequestHandler",
]

# Windows-specific exports
if sys.platform == "win32":
    from .pipe_security import create_secure_named_pipe, verify_pipe_security
    from .windows_service import (
        CryptoBrokerService,
        install_service,
        uninstall_service,
        start_service,
        stop_service,
        get_service_status,
    )

    __all__.extend([
        "create_secure_named_pipe",
        "verify_pipe_security",
        "CryptoBrokerService",
        "install_service",
        "uninstall_service",
        "start_service",
        "stop_service",
        "get_service_status",
    ])
