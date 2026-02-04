"""
AWS KMS (Key Management Service) client implementation.

This module provides AWS KMS integration for cryptographic operations
including key generation, signing, and verification using AWS KMS keys.
"""

from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.backends import default_backend

from models.keys import KeyCurve, KeyPair, KeyType
from utils.exceptions import HSMError
from utils.logging import get_logger
from .base import HSMClient

logger = get_logger(__name__)


class AWSKMSClient(HSMClient):
    """
    AWS KMS client implementation.

    This class provides cryptographic operations using AWS KMS keys.
    Keys are managed in AWS KMS and never exported from the service.
    """

    def __init__(self, config: dict):
        """
        Initialize AWS KMS client.

        Args:
            config: Configuration dictionary with:
                - aws_region: AWS region
                - aws_access_key_id: AWS access key (optional, can use default credentials)
                - aws_secret_access_key: AWS secret key (optional, can use default credentials)
                - key_prefix: Prefix for key aliases

        Raises:
            HSMError: If initialization fails
        """
        super().__init__(config)

        self.aws_region = config.get("aws_region", "eu-central-1")
        self.key_prefix = config.get("key_prefix", "RA8M1_")

        try:
            # Initialize KMS client
            if "aws_access_key_id" in config and "aws_secret_access_key" in config:
                self.kms_client = boto3.client(
                    "kms",
                    region_name=self.aws_region,
                    aws_access_key_id=config["aws_access_key_id"],
                    aws_secret_access_key=config["aws_secret_access_key"],
                )
            else:
                # Use default credentials (from AWS CLI, environment, or IAM role)
                self.kms_client = boto3.client("kms", region_name=self.aws_region)

            logger.info(f"AWS KMS client initialized for region: {self.aws_region}")

        except Exception as e:
            raise HSMError(f"Failed to initialize AWS KMS client: {str(e)}") from e

    def connect(self) -> None:
        """
        Connect to AWS KMS.

        Initializes connection. Actual verification happens on first operation.
        """
        try:
            if "aws_access_key_id" in self.config and "aws_secret_access_key" in self.config:
                import boto3
                sts_client = boto3.client(
                    "sts",
                    region_name=self.aws_region,
                    aws_access_key_id=self.config["aws_access_key_id"],
                    aws_secret_access_key=self.config["aws_secret_access_key"],
                )
                sts_client.get_caller_identity()
            self.initialized = True
            logger.info("Connected to AWS KMS")

        except ClientError as e:
            raise HSMError(f"Failed to connect to AWS KMS: {str(e)}") from e
        except Exception as e:
            raise HSMError(f"Unexpected error connecting to AWS KMS: {str(e)}") from e

    def disconnect(self) -> None:
        """Disconnect from AWS KMS."""
        self.initialized = False
        logger.info("Disconnected from AWS KMS")

    def generate_key_pair(
        self, key_type: KeyType, curve: KeyCurve, label: Optional[str] = None
    ) -> KeyPair:
        """
        Generate a new ECC key pair in AWS KMS.

        Args:
            key_type: Type of key pair to generate
            curve: Elliptic curve to use (must be supported by KMS)
            label: Optional label for the key

        Returns:
            KeyPair object with key ID and public key

        Raises:
            HSMError: If key generation fails
        """
        if not self.initialized:
            raise HSMError("AWS KMS not connected")

        # Map KeyCurve to AWS KMS key spec
        kms_key_spec_map = {
            KeyCurve.SECP256R1: "ECC_NIST_P256",
            KeyCurve.SECP384R1: "ECC_NIST_P384",
            KeyCurve.SECP521R1: "ECC_NIST_P521",
        }

        if curve not in kms_key_spec_map:
            raise HSMError(f"Unsupported curve for AWS KMS: {curve.value}")

        try:
            key_alias = label or f"{self.key_prefix}{key_type.value}"

            # Create key in KMS
            response = self.kms_client.create_key(
                KeyUsage="SIGN_VERIFY",
                KeySpec=kms_key_spec_map[curve],
                Description=f"RA8M1 {key_type.value} key for secure boot",
            )

            key_id = response["KeyMetadata"]["KeyId"]
            key_arn = response["KeyMetadata"]["Arn"]

            # Create alias for easier management (optional - continue if permission denied)
            alias_created = False
            try:
                self.kms_client.create_alias(
                    AliasName=f"alias/{key_alias}",
                    TargetKeyId=key_id,
                )
                alias_created = True
                logger.debug(f"Created alias 'alias/{key_alias}' for key {key_id}")
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "AlreadyExistsException":
                    alias_created = True
                    logger.debug(f"Alias 'alias/{key_alias}' already exists")
                elif error_code == "AccessDeniedException":
                    logger.warning(
                        f"Cannot create alias 'alias/{key_alias}': missing kms:CreateAlias permission. "
                        f"Key created successfully with ID: {key_id}"
                    )
                else:
                    logger.warning(f"Failed to create alias: {error_code}. Key created with ID: {key_id}")

            # Get public key
            public_key_response = self.kms_client.get_public_key(KeyId=key_id)
            public_key_der = public_key_response["PublicKey"]

            if alias_created:
                logger.info(
                    f"Generated {key_type.value} key in AWS KMS: {key_id} (alias: {key_alias})"
                )
            else:
                logger.info(
                    f"Generated {key_type.value} key in AWS KMS: {key_id} (no alias - use key ID)"
                )

            from security.key_utils import convert_public_key_to_pem

            public_key_pem = convert_public_key_to_pem(public_key_der, curve)

            return KeyPair(
                key_type=key_type,
                curve=curve,
                public_key=public_key_der,
                public_key_pem=public_key_pem,
                private_key_handle=key_id,
                label=key_alias,
            )

        except ClientError as e:
            raise HSMError(f"AWS KMS key generation failed: {str(e)}") from e
        except Exception as e:
            raise HSMError(f"Unexpected error generating key: {str(e)}") from e

    def get_public_key(self, key_handle: str) -> bytes:
        """
        Retrieve public key from AWS KMS.

        Args:
            key_handle: KMS Key ID or ARN

        Returns:
            Public key bytes in DER format

        Raises:
            HSMError: If key retrieval fails
        """
        if not self.initialized:
            raise HSMError("AWS KMS not connected")

        try:
            logger.debug(f"Requesting public key from AWS KMS: {key_handle}")
            
            # Get public key from AWS KMS
            response = self.kms_client.get_public_key(KeyId=key_handle)
            
            public_key_der = response["PublicKey"]
            logger.debug(f"Retrieved public key: {len(public_key_der)} bytes (DER format)")
            
            return public_key_der

        except ClientError as e:
            logger.error(f"AWS KMS GetPublicKey failed: {e}")
            logger.error(f"  Error Code: {e.response.get('Error', {}).get('Code', 'N/A')}")
            logger.error(f"  Error Message: {e.response.get('Error', {}).get('Message', 'N/A')}")
            logger.error(f"  Full Response: {e.response}")
            raise HSMError(f"Failed to retrieve public key: {str(e)}") from e
        except Exception as e:
            raise HSMError(f"Unexpected error retrieving public key: {str(e)}") from e

    def sign_digest(self, key_handle: str, message_digest: bytes) -> bytes:
        """
        Sign a pre-computed digest (hash) directly using AWS KMS.
        
        CRITICAL: Use this for MCUboot signing to avoid double-hashing!
        MCUboot expects signature on SHA256(protected_area), not SHA256(SHA256(protected_area)).

        Args:
            key_handle: KMS Key ID or ARN
            message_digest: Pre-computed digest/hash (e.g., SHA256 hash, 32 bytes)

        Returns:
            Signature bytes (DER format for ECDSA)

        Raises:
            HSMError: If signing fails
        """
        if not self.initialized:
            raise HSMError("AWS KMS not connected")

        try:
            key_info = self.kms_client.describe_key(KeyId=key_handle)
            key_spec = key_info["KeyMetadata"]["KeySpec"]

            algorithm_map = {
                "ECC_NIST_P256": "ECDSA_SHA_256",
                "ECC_NIST_P384": "ECDSA_SHA_384",
                "ECC_NIST_P521": "ECDSA_SHA_512",
            }

            if key_spec not in algorithm_map:
                raise HSMError(f"Unsupported key spec for signing: {key_spec}")

            signing_algorithm = algorithm_map[key_spec]

            response = self.kms_client.sign(
                KeyId=key_handle,
                Message=message_digest,
                MessageType="DIGEST",
                SigningAlgorithm=signing_algorithm,
            )

            signature = response["Signature"]

            logger.debug(f"Signed digest using KMS key: {key_handle} with {signing_algorithm}")

            return signature

        except ClientError as e:
            raise HSMError(f"AWS KMS signing failed: {str(e)}") from e
        except Exception as e:
            raise HSMError(f"Unexpected error signing digest: {str(e)}") from e

    def sign_data(self, key_handle: str, data: bytes) -> bytes:
        """
        Sign data using a key in AWS KMS.
        
        NOTE: This method hashes the data before signing. For pre-hashed data (like MCUboot),
        use sign_digest() instead to avoid double-hashing!

        Args:
            key_handle: KMS Key ID or ARN
            data: Data to sign

        Returns:
            Signature bytes

        Raises:
            HSMError: If signing fails
        """
        if not self.initialized:
            raise HSMError("AWS KMS not connected")

        try:
            key_info = self.kms_client.describe_key(KeyId=key_handle)
            key_spec = key_info["KeyMetadata"]["KeySpec"]

            algorithm_map = {
                "ECC_NIST_P256": ("ECDSA_SHA_256", hashes.SHA256()),
                "ECC_NIST_P384": ("ECDSA_SHA_384", hashes.SHA384()),
                "ECC_NIST_P521": ("ECDSA_SHA_512", hashes.SHA512()),
            }

            if key_spec not in algorithm_map:
                raise HSMError(f"Unsupported key spec for signing: {key_spec}")

            signing_algorithm, hash_algorithm = algorithm_map[key_spec]

            digest = hashes.Hash(hash_algorithm, backend=default_backend())
            digest.update(data)
            message_digest = digest.finalize()

            response = self.kms_client.sign(
                KeyId=key_handle,
                Message=message_digest,
                MessageType="DIGEST",
                SigningAlgorithm=signing_algorithm,
            )

            signature = response["Signature"]

            logger.debug(f"Signed data using KMS key: {key_handle} with {signing_algorithm}")

            return signature

        except ClientError as e:
            raise HSMError(f"AWS KMS signing failed: {str(e)}") from e
        except Exception as e:
            raise HSMError(f"Unexpected error signing data: {str(e)}") from e

    def verify_signature(
        self, public_key: bytes, data: bytes, signature: bytes, key_handle: Optional[str] = None
    ) -> bool:
        """
        Verify a signature.

        Uses AWS KMS verify API if key_handle is provided, otherwise verifies locally.

        Args:
            public_key: Public key bytes
            data: Original data
            signature: Signature to verify
            key_handle: Optional KMS Key ID or ARN for KMS-based verification

        Returns:
            True if signature is valid

        Raises:
            HSMError: If verification fails
        """
        if key_handle and self.initialized:
            try:
                key_info = self.kms_client.describe_key(KeyId=key_handle)
                key_spec = key_info["KeyMetadata"]["KeySpec"]

                algorithm_map = {
                    "ECC_NIST_P256": ("ECDSA_SHA_256", hashes.SHA256()),
                    "ECC_NIST_P384": ("ECDSA_SHA_384", hashes.SHA384()),
                    "ECC_NIST_P521": ("ECDSA_SHA_512", hashes.SHA512()),
                }

                if key_spec not in algorithm_map:
                    raise HSMError(f"Unsupported key spec for verification: {key_spec}")

                signing_algorithm, hash_algorithm = algorithm_map[key_spec]

                digest = hashes.Hash(hash_algorithm, backend=default_backend())
                digest.update(data)
                message_digest = digest.finalize()

                response = self.kms_client.verify(
                    KeyId=key_handle,
                    Message=message_digest,
                    MessageType="DIGEST",
                    Signature=signature,
                    SigningAlgorithm=signing_algorithm,
                )

                return response["SignatureValid"]

            except ClientError as e:
                logger.error(f"KMS verification failed: {str(e)}")
                return False

        try:
            pub_key = serialization.load_der_public_key(
                public_key, backend=default_backend()
            )

            if not isinstance(pub_key, ec.EllipticCurvePublicKey):
                raise HSMError("Unsupported key type for verification")

            curve = pub_key.curve
            if isinstance(curve, ec.SECP256R1):
                hash_alg = hashes.SHA256()
            elif isinstance(curve, ec.SECP384R1):
                hash_alg = hashes.SHA384()
            elif isinstance(curve, ec.SECP521R1):
                hash_alg = hashes.SHA512()
            else:
                raise HSMError(f"Unsupported curve for verification: {curve}")

            digest = hashes.Hash(hash_alg, backend=default_backend())
            digest.update(data)
            message_digest = digest.finalize()

            pub_key.verify(signature, message_digest, ec.ECDSA(hash_alg))
            return True

        except Exception as e:
            logger.error(f"Signature verification failed: {str(e)}")
            return False

    def hash_data(self, data: bytes, algorithm: str = "SHA256") -> bytes:
        """
        Compute hash of data.

        Args:
            data: Data to hash
            algorithm: Hash algorithm (SHA256, SHA384, SHA512)

        Returns:
            Hash bytes

        Raises:
            HSMError: If hashing fails
        """
        algorithm_map = {
            "SHA256": hashes.SHA256(),
            "SHA384": hashes.SHA384(),
            "SHA512": hashes.SHA512(),
        }

        if algorithm not in algorithm_map:
            raise HSMError(f"Unsupported hash algorithm: {algorithm}")

        try:
            digest = hashes.Hash(algorithm_map[algorithm], backend=default_backend())
            digest.update(data)
            return digest.finalize()

        except Exception as e:
            raise HSMError(f"Failed to hash data: {str(e)}") from e

    def list_keys(self, key_type: Optional[KeyType] = None) -> list:
        """
        List keys in AWS KMS.

        First tries list_keys, then falls back to list_aliases if list_keys fails.

        Args:
            key_type: Optional filter by key type

        Returns:
            List of key metadata dictionaries
        """
        if not self.initialized:
            raise HSMError("AWS KMS not connected")

        try:
            keys = []
            paginator = self.kms_client.get_paginator("list_keys")

            for page in paginator.paginate():
                for key in page["Keys"]:
                    key_id = key["KeyId"]

                    # Get key details
                    try:
                        key_metadata = self.kms_client.describe_key(KeyId=key_id)[
                            "KeyMetadata"
                        ]

                        # Filter by key type if specified
                        if key_type:
                            alias_name = key_metadata.get("AliasNames", [])
                            if alias_name:
                                alias = alias_name[0].replace("alias/", "")
                                if not alias.startswith(f"{self.key_prefix}{key_type.value}"):
                                    continue

                        keys.append(key_metadata)

                    except ClientError:
                        continue

            return keys

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "AccessDeniedException" and "ListKeys" in str(e):
                # Fallback: try list_aliases which might have different permissions
                logger.info("list_keys failed, trying list_aliases as fallback...")
                return self._list_keys_via_aliases(key_type)
            raise HSMError(f"Failed to list keys: {str(e)}") from e
        except Exception as e:
            raise HSMError(f"Unexpected error listing keys: {str(e)}") from e

    def _list_keys_via_aliases(self, key_type: Optional[KeyType] = None) -> list:
        """
        List keys by iterating through aliases.

        This method uses list_aliases which might have different permissions than list_keys.

        Args:
            key_type: Optional filter by key type

        Returns:
            List of key metadata dictionaries
        """
        try:
            keys = []
            paginator = self.kms_client.get_paginator("list_aliases")

            for page in paginator.paginate():
                for alias_info in page["Aliases"]:
                    alias_name = alias_info.get("AliasName", "")
                    
                    # Filter by prefix and key type if specified
                    if not alias_name.startswith(f"alias/{self.key_prefix}"):
                        continue
                    
                    if key_type:
                        expected_prefix = f"alias/{self.key_prefix}{key_type.value}"
                        if not alias_name.startswith(expected_prefix):
                            continue

                    key_id = alias_info.get("TargetKeyId")
                    if not key_id:
                        continue

                    # Get key details
                    try:
                        key_metadata = self.kms_client.describe_key(KeyId=key_id)[
                            "KeyMetadata"
                        ]
                        keys.append(key_metadata)
                    except ClientError:
                        continue

            return keys

        except ClientError as e:
            raise HSMError(f"Failed to list keys via aliases: {str(e)}") from e
        except Exception as e:
            raise HSMError(f"Unexpected error listing keys via aliases: {str(e)}") from e

    def delete_key(self, key_id: str, pending_days: int = 7) -> None:
        """
        Schedule key for deletion.

        AWS KMS doesn't allow immediate deletion. Keys are scheduled
        for deletion with a pending window (7-30 days).

        Args:
            key_id: KMS Key ID or ARN
            pending_days: Pending window in days (7-30)

        Raises:
            HSMError: If deletion scheduling fails
        """
        if not self.initialized:
            raise HSMError("AWS KMS not connected")

        if pending_days < 7 or pending_days > 30:
            raise HSMError("Pending window must be between 7 and 30 days")

        try:
            self.kms_client.schedule_key_deletion(
                KeyId=key_id,
                PendingWindowInDays=pending_days
            )

            logger.info(
                f"Scheduled key {key_id} for deletion (pending window: {pending_days} days)"
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "KMSInvalidStateException":
                raise HSMError(
                    f"Key {key_id} is already scheduled for deletion or in invalid state"
                ) from e
            raise HSMError(f"Failed to schedule key deletion: {str(e)}") from e
        except Exception as e:
            raise HSMError(f"Unexpected error scheduling key deletion: {str(e)}") from e

    def cancel_key_deletion(self, key_id: str) -> None:
        """
        Cancel scheduled key deletion.

        Args:
            key_id: KMS Key ID or ARN

        Raises:
            HSMError: If cancellation fails
        """
        if not self.initialized:
            raise HSMError("AWS KMS not connected")

        try:
            self.kms_client.cancel_key_deletion(KeyId=key_id)
            logger.info(f"Cancelled deletion for key {key_id}")

        except ClientError as e:
            raise HSMError(f"Failed to cancel key deletion: {str(e)}") from e
        except Exception as e:
            raise HSMError(f"Unexpected error cancelling key deletion: {str(e)}") from e

    def get_key_status(self, key_id: str) -> dict:
        """
        Get key status and metadata.

        Args:
            key_id: KMS Key ID or ARN

        Returns:
            Dictionary with key metadata including deletion date if scheduled

        Raises:
            HSMError: If retrieval fails
        """
        if not self.initialized:
            raise HSMError("AWS KMS not connected")

        try:
            response = self.kms_client.describe_key(KeyId=key_id)
            metadata = response["KeyMetadata"]

            status = {
                "key_id": metadata["KeyId"],
                "arn": metadata["Arn"],
                "state": metadata["KeyState"],
                "key_spec": metadata.get("KeySpec", "N/A"),
                "key_usage": metadata.get("KeyUsage", "N/A"),
                "creation_date": metadata["CreationDate"],
                "aliases": metadata.get("AliasNames", []),
            }

            # Check if scheduled for deletion
            if "DeletionDate" in metadata:
                status["deletion_date"] = metadata["DeletionDate"]
                status["pending_window_days"] = metadata.get("PendingWindowInDays")

            return status

        except ClientError as e:
            raise HSMError(f"Failed to get key status: {str(e)}") from e
        except Exception as e:
            raise HSMError(f"Unexpected error getting key status: {str(e)}") from e

