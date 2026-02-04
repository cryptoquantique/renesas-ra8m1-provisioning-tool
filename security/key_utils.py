"""
Key utility functions.

This module provides utilities for key generation, export, and conversion.
"""

from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from models.keys import KeyCurve, KeyPair, KeyType
from utils.exceptions import HSMError
from utils.logging import get_logger

logger = get_logger(__name__)


def convert_public_key_to_pem(public_key_der: bytes, curve: KeyCurve) -> str:
    """
    Convert public key from DER format to PEM format.

    Args:
        public_key_der: Public key in DER format
        curve: Elliptic curve type

    Returns:
        Public key in PEM format as string

    Raises:
        HSMError: If conversion fails
    """
    try:
        public_key = serialization.load_der_public_key(
            public_key_der, backend=default_backend()
        )

        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise HSMError("Public key is not an ECC key")

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return pem.decode("utf-8")

    except Exception as e:
        raise HSMError(f"Failed to convert public key to PEM: {str(e)}") from e


def save_public_key_pem(
    public_key_der: bytes, output_file: Path, curve: KeyCurve
) -> None:
    """
    Save public key to PEM file.

    Args:
        public_key_der: Public key in DER format
        output_file: Path to output PEM file
        curve: Elliptic curve type

    Raises:
        HSMError: If save fails
    """
    try:
        pem_content = convert_public_key_to_pem(public_key_der, curve)

        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(pem_content, encoding="utf-8")

        logger.info(f"Public key saved to {output_file}")

    except Exception as e:
        raise HSMError(f"Failed to save public key: {str(e)}") from e


def generate_local_key_pair(
    key_type: KeyType, curve: KeyCurve, output_dir: Optional[Path] = None
) -> tuple[KeyPair, Path, Path]:
    """
    Generate a key pair locally (not in HSM).

    This creates both private and public keys as files.
    Use only for development/testing. Production keys should be in HSM.

    Args:
        key_type: Type of key pair
        curve: Elliptic curve to use
        output_dir: Directory to save keys (default: current directory)

    Returns:
        Tuple of (KeyPair, private_key_path, public_key_path)

    Raises:
        HSMError: If key generation fails
    """
    if output_dir is None:
        output_dir = Path(".")

    try:
        curve_map = {
            KeyCurve.SECP256R1: ec.SECP256R1(),
            KeyCurve.SECP384R1: ec.SECP384R1(),
            KeyCurve.SECP521R1: ec.SECP521R1(),
        }

        if curve not in curve_map:
            raise HSMError(f"Unsupported curve: {curve.value}")

        private_key = ec.generate_private_key(
            curve_map[curve], backend=default_backend()
        )
        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        private_key_path = output_dir / f"{key_type.value}_private_key.pem"
        public_key_path = output_dir / f"{key_type.value}_public_key.pem"

        output_dir.mkdir(parents=True, exist_ok=True)
        private_key_path.write_bytes(private_key_pem)
        public_key_path.write_bytes(public_key_pem)

        logger.info(
            f"Generated local key pair: {private_key_path} and {public_key_path}"
        )

        key_pair = KeyPair(
            key_type=key_type,
            curve=curve,
            public_key=public_key_der,
            public_key_pem=public_key_pem.decode("utf-8"),
            private_key_handle=str(private_key_path),
            label=f"{key_type.value}_local",
        )

        return key_pair, private_key_path, public_key_path

    except Exception as e:
        raise HSMError(f"Failed to generate local key pair: {str(e)}") from e



