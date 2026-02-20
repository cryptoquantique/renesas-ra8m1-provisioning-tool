"""
KMS Backend wrapper for the crypto broker service.

This module wraps the existing AWSKMSClient to provide a simplified
interface for cryptographic operations needed by the broker.
"""

import base64
from typing import Optional, Dict, Any, List

from config.settings import DEFAULT_AWS_REGION
from security.hsm.aws_kms import AWSKMSClient
from security.broker.exceptions import BrokerError
from utils.logging import get_logger

logger = get_logger(__name__)


class KMSBackend:
    """
    KMS backend providing cryptographic operations for the broker.

    Wraps AWSKMSClient to expose sign, verify, and key retrieval
    operations in a format suitable for JSON-RPC communication.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize KMS backend.

        Args:
            config: Configuration dictionary with AWS credentials and settings.
                Expected keys:
                - aws_region: AWS region (default: config.settings.DEFAULT_AWS_REGION)
                - aws_access_key_id: AWS access key (optional)
                - aws_secret_access_key: AWS secret key (optional)
                - key_prefix: Prefix for key aliases (default: "renesas_")
        """
        self.config = config
        self._kms_client: Optional[AWSKMSClient] = None
        self._connected = False

    def connect(self) -> None:
        """
        Initialize connection to AWS KMS.

        Raises:
            BrokerError: If connection fails
        """
        if self._connected:
            return

        try:
            active_region = self.config.get("aws_region", DEFAULT_AWS_REGION)
            kms_config = {
                "aws_region": active_region,
                "key_prefix": self.config.get("key_prefix", "renesas_"),
            }

            # Add credentials if provided
            if self.config.get("aws_access_key_id"):
                kms_config["aws_access_key_id"] = self.config["aws_access_key_id"]
            if self.config.get("aws_secret_access_key"):
                kms_config["aws_secret_access_key"] = self.config["aws_secret_access_key"]

            logger.info(f"KMS backend connecting to AWS region: {active_region}")

            self._kms_client = AWSKMSClient(kms_config)
            self._kms_client.connect()
            self._connected = True

            logger.info(f"KMS backend connected (region={active_region})")

        except Exception as e:
            raise BrokerError(f"Failed to connect to KMS: {str(e)}") from e

    def disconnect(self) -> None:
        """Disconnect from AWS KMS."""
        if self._kms_client:
            self._kms_client.disconnect()
            self._connected = False
            logger.info("KMS backend disconnected")

    @property
    def is_connected(self) -> bool:
        """Check if backend is connected."""
        return self._connected

    def _ensure_connected(self) -> None:
        """Ensure backend is connected, raise if not."""
        if not self._connected or not self._kms_client:
            raise BrokerError("KMS backend not connected")

    def sign(self, key_arn: str, data: bytes) -> bytes:
        """
        Sign data using a KMS key.

        This method hashes the data before signing.

        Args:
            key_arn: KMS Key ARN or ID
            data: Data to sign

        Returns:
            Signature bytes (DER-encoded for ECDSA)

        Raises:
            BrokerError: If signing fails
        """
        self._ensure_connected()

        try:
            signature = self._kms_client.sign_data(key_arn, data)
            logger.debug(f"Signed {len(data)} bytes with key {key_arn}")
            return signature

        except Exception as e:
            raise BrokerError(f"Sign operation failed: {str(e)}") from e

    def sign_digest(self, key_arn: str, digest: bytes) -> bytes:
        """
        Sign a pre-computed digest using a KMS key.

        This method signs the digest directly without additional hashing.
        Use this for MCUboot signing to avoid double-hashing.

        Args:
            key_arn: KMS Key ARN or ID
            digest: Pre-computed hash digest (e.g., SHA256 = 32 bytes)

        Returns:
            Signature bytes (DER-encoded for ECDSA)

        Raises:
            BrokerError: If signing fails
        """
        self._ensure_connected()

        try:
            signature = self._kms_client.sign_digest(key_arn, digest)
            logger.debug(f"Signed digest ({len(digest)} bytes) with key {key_arn}")
            return signature

        except Exception as e:
            raise BrokerError(f"Sign digest operation failed: {str(e)}") from e

    def verify(
        self,
        key_arn: str,
        data: bytes,
        signature: bytes,
    ) -> bool:
        """
        Verify a signature using a KMS key.

        Args:
            key_arn: KMS Key ARN or ID
            data: Original data that was signed
            signature: Signature to verify

        Returns:
            True if signature is valid, False otherwise

        Raises:
            BrokerError: If verification fails unexpectedly
        """
        self._ensure_connected()

        try:
            # Get public key first for local verification or use KMS verify
            public_key = self._kms_client.get_public_key(key_arn)
            is_valid = self._kms_client.verify_signature(
                public_key, data, signature, key_handle=key_arn
            )
            logger.debug(f"Verified signature with key {key_arn}: {is_valid}")
            return is_valid

        except Exception as e:
            raise BrokerError(f"Verify operation failed: {str(e)}") from e

    def get_public_key(self, key_arn: str) -> bytes:
        """
        Retrieve public key from KMS.

        Args:
            key_arn: KMS Key ARN or ID

        Returns:
            Public key bytes in DER format

        Raises:
            BrokerError: If retrieval fails
        """
        self._ensure_connected()

        try:
            public_key = self._kms_client.get_public_key(key_arn)
            logger.debug(f"Retrieved public key for {key_arn}: {len(public_key)} bytes")
            return public_key

        except Exception as e:
            raise BrokerError(f"Get public key failed: {str(e)}") from e

    def hash_data(self, data: bytes, algorithm: str = "SHA256") -> bytes:
        """
        Compute hash of data.

        Args:
            data: Data to hash
            algorithm: Hash algorithm (SHA256, SHA384, SHA512)

        Returns:
            Hash digest bytes

        Raises:
            BrokerError: If hashing fails
        """
        self._ensure_connected()

        try:
            digest = self._kms_client.hash_data(data, algorithm)
            logger.debug(f"Hashed {len(data)} bytes with {algorithm}: {len(digest)} bytes")
            return digest

        except Exception as e:
            raise BrokerError(f"Hash operation failed: {str(e)}") from e

    def generate_key_pair(
        self,
        key_type: str,
        curve: str,
        label: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a new ECC key pair in AWS KMS.

        Args:
            key_type: Type of key (e.g., "oem_root", "oem_bootloader", "customer")
            curve: Elliptic curve (e.g., "secp256r1", "secp384r1", "secp521r1")
            label: Optional alias label for the key

        Returns:
            Dictionary with key metadata:
                - key_id: KMS key ID
                - arn: KMS key ARN
                - public_key: Base64-encoded public key (DER format)
                - key_spec: KMS key specification
                - label: Key alias (if created)

        Raises:
            BrokerError: If key generation fails
        """
        self._ensure_connected()

        # Map curve names to AWS KMS key specs
        curve_map = {
            "secp256r1": "ECC_NIST_P256",
            "p-256": "ECC_NIST_P256",
            "secp384r1": "ECC_NIST_P384",
            "p-384": "ECC_NIST_P384",
            "secp521r1": "ECC_NIST_P521",
            "p-521": "ECC_NIST_P521",
        }

        key_spec = curve_map.get(curve.lower())
        if not key_spec:
            raise BrokerError(f"Unsupported curve: {curve}")

        try:
            # Use AWSKMSClient's generate_key_pair method
            from models.keys import KeyCurve, KeyType

            # Map string key_type to KeyType enum
            key_type_map = {
                "oem_root": KeyType.OEM_ROOT,
                "oem_bootloader": KeyType.OEM_BOOTLOADER,
                "customer": KeyType.CUSTOMER,
            }
            kt = key_type_map.get(key_type.lower())
            if not kt:
                raise BrokerError(f"Unknown key type: {key_type}")

            # Map string curve to KeyCurve enum
            curve_enum_map = {
                "secp256r1": KeyCurve.SECP256R1,
                "p-256": KeyCurve.SECP256R1,
                "secp384r1": KeyCurve.SECP384R1,
                "p-384": KeyCurve.SECP384R1,
                "secp521r1": KeyCurve.SECP521R1,
                "p-521": KeyCurve.SECP521R1,
            }
            kc = curve_enum_map.get(curve.lower(), KeyCurve.SECP256R1)

            # Generate key via AWSKMSClient
            key_pair = self._kms_client.generate_key_pair(
                key_type=kt,
                curve=kc,
                label=label,
            )

            logger.info(f"Generated {key_type} key: {key_pair.private_key_handle}")

            return {
                "key_id": key_pair.private_key_handle,
                "arn": key_pair.private_key_handle,  # KMS uses key_id as handle
                "public_key": base64.b64encode(key_pair.public_key).decode("ascii"),
                "key_spec": key_spec,
                "label": key_pair.label,
                "key_type": key_type,
                "curve": curve,
            }

        except Exception as e:
            raise BrokerError(f"Key generation failed: {str(e)}") from e

    def list_keys(self) -> List[Dict[str, Any]]:
        """
        List available KMS keys.

        Returns:
            List of key metadata dictionaries

        Raises:
            BrokerError: If listing fails
        """
        self._ensure_connected()

        try:
            keys = self._kms_client.list_keys()
            logger.debug(f"Listed {len(keys)} KMS keys")

            # Simplify the key metadata for JSON response
            result = []
            for key in keys:
                result.append({
                    "key_id": key.get("KeyId"),
                    "arn": key.get("Arn"),
                    "state": key.get("KeyState"),
                    "key_spec": key.get("KeySpec"),
                    "key_usage": key.get("KeyUsage"),
                })
            return result

        except Exception as e:
            raise BrokerError(f"List keys failed: {str(e)}") from e

    def get_info(self) -> Dict[str, Any]:
        """
        Get backend information.

        Returns:
            Dictionary with backend info
        """
        return {
            "type": "aws_kms",
            "region": self.config.get("aws_region", DEFAULT_AWS_REGION),
            "connected": self._connected,
        }
