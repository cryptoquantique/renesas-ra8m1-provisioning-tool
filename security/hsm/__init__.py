"""
HSM (Hardware Security Module) integration.

This package provides interfaces and implementations for HSM operations
via PKCS#11, AWS CloudHSM, and AWS KMS.
"""

from .factory import create_hsm_client

__all__ = ["create_hsm_client"]


