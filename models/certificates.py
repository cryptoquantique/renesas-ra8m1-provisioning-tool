"""
Certificate data models.

This module defines data structures for certificates,
certificate chains, and certificate-related operations.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


class CertificateType(Enum):
    """Certificate types."""

    KEY_CERTIFICATE = "key_certificate"
    CODE_CERTIFICATE = "code_certificate"
    DEVICE_CERTIFICATE = "device_certificate"
    CA_CERTIFICATE = "ca_certificate"


class CertificateFormat(Enum):
    """Certificate formats."""

    HMAC = "hmac"
    CRC = "crc"
    X509 = "x509"


@dataclass
class Certificate:
    """
    Certificate information.

    Attributes:
        certificate_type: Type of certificate
        subject: Certificate subject (DN)
        issuer: Certificate issuer (DN)
        serial_number: Certificate serial number
        not_before: Certificate validity start date
        not_after: Certificate validity end date
        public_key: Public key in PEM format
        certificate_data: Certificate data in PEM format
        format: Certificate format (HMAC, CRC, X509)
        file_path: Path to certificate file
    """

    certificate_type: CertificateType
    subject: str
    issuer: str
    serial_number: str
    not_before: str
    not_after: str
    public_key: str
    certificate_data: str
    format: CertificateFormat = CertificateFormat.HMAC
    file_path: Optional[str] = None

    def __str__(self) -> str:
        """String representation of certificate."""
        return (
            f"Certificate(type={self.certificate_type.value}, "
            f"format={self.format.value}, subject={self.subject}, "
            f"serial={self.serial_number})"
        )


@dataclass
class KeyCertificate:
    """
    Key Certificate structure for RA8M1 secure boot.

    The Key Certificate authenticates the OEM Bootloader Public Key (OEM_BL_PK)
    using the OEM Root Secret Key (OEM_ROOT_SK).

    Attributes:
        header: Certificate header
        tlv_length: TLV length field
        oem_root_pk: OEM Root Public Key
        oem_bl_pk_hash: Hash of OEM Bootloader Public Key
        expected_signature: Signature created using OEM_ROOT_SK
        file_path: Path to certificate binary file
    """

    header: bytes
    tlv_length: int
    oem_root_pk: bytes
    oem_bl_pk_hash: bytes
    expected_signature: bytes
    file_path: Optional[str] = None


@dataclass
class CodeCertificate:
    """
    Code Certificate structure for RA8M1 secure boot.

    The Code Certificate authenticates the OEM Bootloader (OEM_BL)
    using the OEM Bootloader Secret Key (OEM_BL_SK).

    Attributes:
        header: Certificate header
        tlv_length: TLV length field
        oem_bl_pk: OEM Bootloader Public Key (64 bytes Qx||Qy)
        oem_bl_crc: CRC32 of OEM Bootloader binary
        signer_id: SHA256(OEM_BL_PK) - MUST match KEYHASH in Key Certificate
        expected_signature: Signature created using OEM_BL_SK
        file_path: Path to certificate binary file
        oem_bl_hash: DEPRECATED - use oem_bl_crc for CRC, signer_id for hash
    """

    header: bytes
    tlv_length: int
    oem_bl_pk: bytes
    oem_bl_crc: bytes
    signer_id: bytes
    expected_signature: bytes
    file_path: Optional[str] = None
    oem_bl_hash: Optional[bytes] = None  # Deprecated, for backward compatibility


@dataclass
class CertificateChain:
    """
    Certificate chain structure.

    Attributes:
        device_certificate: Device certificate
        intermediate_certificates: List of intermediate CA certificates
        root_certificate: Root CA certificate
    """

    device_certificate: Certificate
    intermediate_certificates: List[Certificate]
    root_certificate: Certificate

    def __str__(self) -> str:
        """String representation of certificate chain."""
        return (
            f"CertificateChain(device={self.device_certificate.subject}, "
            f"intermediates={len(self.intermediate_certificates)}, "
            f"root={self.root_certificate.subject})"
        )


@dataclass
class CertificateSigningRequest:
    """
    Certificate Signing Request (CSR) information.

    Attributes:
        subject: CSR subject (DN)
        public_key: Public key in PEM format
        csr_data: CSR data in PEM format
        private_key_handle: HSM handle for private key (if applicable)
    """

    subject: str
    public_key: str
    csr_data: str
    private_key_handle: Optional[str] = None

