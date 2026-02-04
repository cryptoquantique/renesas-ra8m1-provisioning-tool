"""
Key management models.

This module defines data structures for cryptographic keys,
key pairs, and key-related operations for RA8M1 secure boot.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class KeyType(Enum):
    """Cryptographic key types."""

    OEM_ROOT = "oem_root"
    OEM_BOOTLOADER = "oem_bootloader"
    CUSTOMER = "customer"
    UFPK = "ufpk"


class KeyCurve(Enum):
    """Elliptic curve types for ECC keys."""

    SECP256R1 = "secp256r1"
    SECP384R1 = "secp384r1"
    SECP521R1 = "secp521r1"


@dataclass
class KeyPair:
    """
    Cryptographic key pair structure.

    Attributes:
        key_type: Type of key pair (OEM_ROOT, OEM_BOOTLOADER, CUSTOMER)
        curve: Elliptic curve used
        public_key: Public key data
        private_key_handle: HSM handle for private key (never exported)
        public_key_pem: Public key in PEM format
        label: Key label in HSM
    """

    key_type: KeyType
    curve: KeyCurve
    public_key: bytes
    private_key_handle: Optional[str] = None
    public_key_pem: Optional[str] = None
    label: Optional[str] = None

    def __str__(self) -> str:
        """String representation of key pair."""
        return (
            f"KeyPair(type={self.key_type.value}, curve={self.curve.value}, "
            f"label={self.label})"
        )


@dataclass
class WrappedKey:
    """
    Wrapped key structure for secure key injection.

    Attributes:
        key_type: Type of wrapped key
        wrapped_data: Wrapped key data (binary)
        file_path: Path to .rkey file
        ufpk_used: UFPK used for wrapping
    """

    key_type: KeyType
    wrapped_data: bytes
    file_path: Optional[str] = None
    ufpk_used: Optional[str] = None

    def __str__(self) -> str:
        """String representation of wrapped key."""
        return (
            f"WrappedKey(type={self.key_type.value}, "
            f"file={self.file_path})"
        )


@dataclass
class KeyProvisioningData:
    """
    Complete key provisioning data for a device.

    Attributes:
        oem_root_key_pair: OEM Root key pair
        oem_bl_key_pair: OEM Bootloader key pair
        customer_key_pair: Customer key pair (for application signing)
        wrapped_oem_root_pk: Wrapped OEM Root Public Key (.rkey file)
        oem_root_pk_hash: Hash of OEM Root Public Key (for device storage)
    """

    oem_root_key_pair: KeyPair
    oem_bl_key_pair: KeyPair
    customer_key_pair: KeyPair
    wrapped_oem_root_pk: WrappedKey
    oem_root_pk_hash: bytes





