"""
Base HSM client interface.

This module defines the abstract base class for HSM clients,
ensuring a consistent interface across different HSM implementations.
"""

from abc import ABC, abstractmethod
from typing import Optional

from models.keys import KeyCurve, KeyPair, KeyType
from utils.exceptions import HSMError
from utils.logging import get_logger

logger = get_logger(__name__)


class HSMClient(ABC):
    """
    Abstract base class for HSM clients.

    This class defines the interface that all HSM implementations
    must follow for key operations and cryptographic functions.
    """

    def __init__(self, config: dict):
        """
        Initialize HSM client.

        Args:
            config: HSM configuration dictionary

        Raises:
            HSMError: If initialization fails
        """
        self.config = config
        self.initialized = False

    @abstractmethod
    def connect(self) -> None:
        """
        Connect to HSM.

        Raises:
            HSMError: If connection fails
        """
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Disconnect from HSM."""
        pass

    @abstractmethod
    def generate_key_pair(
        self, key_type: KeyType, curve: KeyCurve, label: Optional[str] = None
    ) -> KeyPair:
        """
        Generate a new ECC key pair in the HSM.

        Args:
            key_type: Type of key pair to generate
            curve: Elliptic curve to use
            label: Optional label for the key in HSM

        Returns:
            KeyPair object with public key and HSM handle

        Raises:
            HSMError: If key generation fails
        """
        pass

    @abstractmethod
    def get_public_key(self, key_handle: str) -> bytes:
        """
        Retrieve public key from HSM.

        Args:
            key_handle: HSM handle for the key

        Returns:
            Public key bytes

        Raises:
            HSMError: If key retrieval fails
        """
        pass

    @abstractmethod
    def sign_data(self, key_handle: str, data: bytes) -> bytes:
        """
        Sign data using a private key stored in HSM.

        Args:
            key_handle: HSM handle for the private key
            data: Data to sign

        Returns:
            Signature bytes

        Raises:
            HSMError: If signing fails
        """
        pass

    @abstractmethod
    def verify_signature(
        self, public_key: bytes, data: bytes, signature: bytes
    ) -> bool:
        """
        Verify a signature.

        Args:
            public_key: Public key bytes
            data: Original data
            signature: Signature to verify

        Returns:
            True if signature is valid, False otherwise

        Raises:
            HSMError: If verification fails
        """
        pass

    @abstractmethod
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
        pass

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()





