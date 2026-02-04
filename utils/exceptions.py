"""
Custom exception classes for the provisioning tool.

This module defines a hierarchy of custom exceptions used throughout
the application for better error handling and debugging.
"""


class ProvisioningToolError(Exception):
    """Base exception for all provisioning tool errors."""

    def __init__(self, message: str, details: dict = None):
        """
        Initialize the exception.

        Args:
            message: Human-readable error message
            details: Optional dictionary with additional error details
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}


class CommunicationError(ProvisioningToolError):
    """Raised when device communication fails."""

    pass


class ProtocolError(CommunicationError):
    """Raised when protocol-level errors occur."""

    pass


class TimeoutError(CommunicationError):
    """Raised when communication timeouts occur."""

    pass


class FirmwareError(ProvisioningToolError):
    """Raised when firmware operations fail."""

    pass


class FlashError(FirmwareError):
    """Raised when flash memory operations fail."""

    pass


class VerificationError(FirmwareError):
    """Raised when firmware verification fails."""

    pass


class SecurityError(ProvisioningToolError):
    """Raised when security-related operations fail."""

    pass


class HSMError(SecurityError):
    """Raised when HSM operations fail."""

    pass


class PKCS11Error(HSMError):
    """Raised when PKCS#11 operations fail."""

    pass


class KeyError(SecurityError):
    """Raised when key operations fail."""

    pass


class SigningError(SecurityError):
    """Raised when signing operations fail."""

    pass


class CertificateError(SecurityError):
    """Raised when certificate operations fail."""

    pass


class ConfigurationError(ProvisioningToolError):
    """Raised when configuration errors occur."""

    pass


# Alias for backward compatibility
ConfigError = ConfigurationError


class SKMTError(ProvisioningToolError):
    """Raised when SKMT tool operations fail."""

    pass


class PGPError(SecurityError):
    """Raised when PGP operations fail."""

    pass


class DLMError(ProvisioningToolError):
    """Raised when DLM server operations fail."""

    pass


class DeviceError(CommunicationError):
    """Raised when device operations fail."""

    pass



