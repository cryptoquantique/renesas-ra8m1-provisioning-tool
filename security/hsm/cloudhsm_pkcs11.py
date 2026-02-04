"""
AWS CloudHSM client implementation using PKCS#11.

This provides DIRECT signing with CloudHSM using PKCS#11 interface.
MUCH simpler than AWS KMS API - no complex TLV reconstruction!

Benefits over AWS KMS:
- Direct PKCS#11 API (standard interface)
- No TLV padding issues
- Already used for CA keys
- Same security level (FIPS 140-2 Level 3)
- Simpler implementation (use cryptography library directly)
"""

from pathlib import Path
from typing import Optional
import pkcs11
from pkcs11 import Mechanism, KeyType, ObjectClass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from models.keys import KeyCurve, KeyPair, KeyType as AppKeyType
from utils.exceptions import HSMError
from utils.logging import get_logger
from .base import HSMClient

logger = get_logger(__name__)


class CloudHSMClient(HSMClient):
    """
    AWS CloudHSM client using PKCS#11 interface.
    
    This class provides direct signing using CloudHSM via PKCS#11.
    Much simpler than AWS KMS - cryptography library handles everything!
    """
    
    def __init__(self, config: dict):
        """
        Initialize CloudHSM client.
        
        Args:
            config: Dictionary with CloudHSM configuration:
                - pkcs11_library: Path to CloudHSM PKCS#11 library
                - slot_id: HSM slot ID (default: 0)
                - pin: HSM PIN/password
                - label: Optional key label filter
        """
        super().__init__(config)
        
        self.pkcs11_library = config.get('pkcs11_library')
        self.slot_id = config.get('slot_id', 0)
        self.pin = config.get('pin')
        self.label = config.get('label')
        
        self.lib = None
        self.session = None
        
        if not self.pkcs11_library:
            raise HSMError("CloudHSM PKCS#11 library path not configured")
        
        if not Path(self.pkcs11_library).exists():
            raise HSMError(f"PKCS#11 library not found: {self.pkcs11_library}")
    
    def connect(self) -> None:
        """Connect to CloudHSM via PKCS#11."""
        try:
            logger.info(f"Connecting to CloudHSM via PKCS#11: {self.pkcs11_library}")
            
            # Load PKCS#11 library
            self.lib = pkcs11.lib(self.pkcs11_library)
            
            # Get token/slot
            token = self.lib.get_token(slot_id=self.slot_id)
            logger.info(f"  Token: {token.label}")
            logger.info(f"  Manufacturer: {token.manufacturer_id}")
            
            # Open session with PIN
            self.session = token.open(user_pin=self.pin)
            logger.info(f"  Session opened successfully")
            
            self.initialized = True
            logger.info("[OK] CloudHSM connected via PKCS#11!")
            
        except Exception as e:
            raise HSMError(f"Failed to connect to CloudHSM: {str(e)}") from e
    
    def disconnect(self) -> None:
        """Disconnect from CloudHSM."""
        if self.session:
            try:
                self.session.close()
                logger.info("CloudHSM session closed")
            except Exception as e:
                logger.warning(f"Error closing CloudHSM session: {e}")
            finally:
                self.session = None
                self.initialized = False
    
    def _find_key_by_label(self, label: str, key_type: KeyType):
        """Find a key object by label."""
        if not self.session:
            raise HSMError("Not connected to CloudHSM")
        
        # Search for key
        keys = list(self.session.get_objects({
            pkcs11.Attribute.CLASS: ObjectClass.PRIVATE_KEY if key_type == KeyType.PRIVATE else ObjectClass.PUBLIC_KEY,
            pkcs11.Attribute.LABEL: label,
        }))
        
        if not keys:
            raise HSMError(f"Key not found with label: {label}")
        
        if len(keys) > 1:
            logger.warning(f"Multiple keys found with label '{label}', using first one")
        
        return keys[0]
    
    def get_public_key(self, key_handle: str) -> bytes:
        """
        Get public key from CloudHSM.
        
        Args:
            key_handle: Key label in CloudHSM
        
        Returns:
            Public key in DER format (SubjectPublicKeyInfo)
        """
        if not self.initialized:
            raise HSMError("CloudHSM not connected")
        
        try:
            logger.info(f"Retrieving public key: {key_handle}")
            
            # Find public key object
            pub_key_obj = self._find_key_by_label(key_handle, KeyType.PUBLIC)
            
            # Get EC parameters and point
            ec_params = pub_key_obj[pkcs11.Attribute.EC_PARAMS]
            ec_point = pub_key_obj[pkcs11.Attribute.EC_POINT]
            
            # Reconstruct public key using cryptography
            # EC_POINT is DER encoded OCTET STRING wrapping the uncompressed point
            # We need to unwrap it
            if ec_point[0] == 0x04 and ec_point[1] == 0x41:  # OCTET STRING, length 65
                uncompressed_point = ec_point[2:67]  # Extract 65-byte point
            else:
                uncompressed_point = ec_point
            
            # Determine curve from EC_PARAMS (OID)
            # P-256: 1.2.840.10045.3.1.7
            if b'\x2a\x86\x48\xce\x3d\x03\x01\x07' in ec_params:
                curve = ec.SECP256R1()
            elif b'\x2b\x81\x04\x00\x22' in ec_params:
                curve = ec.SECP384R1()
            else:
                raise HSMError("Unsupported EC curve")
            
            # Load public key from uncompressed point
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            
            # Build SubjectPublicKeyInfo DER
            # This is what MCUboot expects
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, uncompressed_point)
            
            # Serialize to DER (SubjectPublicKeyInfo)
            public_key_der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            logger.info(f"  Public key retrieved: {len(public_key_der)} bytes (DER)")
            return public_key_der
            
        except Exception as e:
            raise HSMError(f"Failed to get public key: {str(e)}") from e
    
    def sign_digest(self, key_handle: str, message_digest: bytes) -> bytes:
        """
        Sign a pre-computed digest using CloudHSM.
        
        CRITICAL: This is DIRECT PKCS#11 signing - NO reconstruction needed!
        CloudHSM returns signature in DER format, ready to use!
        
        Args:
            key_handle: Key label in CloudHSM
            message_digest: Pre-computed SHA256 hash (32 bytes)
        
        Returns:
            ECDSA signature in DER format
        """
        if not self.initialized:
            raise HSMError("CloudHSM not connected")
        
        try:
            logger.info(f"Signing digest with CloudHSM key: {key_handle}")
            logger.debug(f"  Digest: {message_digest.hex()[:64]}...")
            
            # Find private key
            priv_key_obj = self._find_key_by_label(key_handle, KeyType.PRIVATE)
            
            # Sign with ECDSA (CloudHSM handles everything!)
            # PKCS#11 CKM_ECDSA mechanism signs the hash directly
            signature = priv_key_obj.sign(
                message_digest,
                mechanism=Mechanism.ECDSA  # Direct ECDSA signing
            )
            
            logger.info(f"  Signature: {len(signature)} bytes (DER format)")
            logger.debug(f"  Signature: {signature.hex()[:64]}...")
            
            # CloudHSM returns DER-encoded signature (0x30 [len] ...)
            if signature[0] != 0x30:
                # If not DER, convert from RAW (R||S) to DER
                logger.warning("  Signature not in DER format, converting...")
                from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
                
                # Split R and S (each 32 bytes for P-256)
                r = int.from_bytes(signature[:32], 'big')
                s = int.from_bytes(signature[32:64], 'big')
                
                # Encode to DER
                signature = encode_dss_signature(r, s)
                logger.info(f"  Converted to DER: {len(signature)} bytes")
            
            return signature
            
        except Exception as e:
            raise HSMError(f"CloudHSM signing failed: {str(e)}") from e
    
    def sign_data(self, key_handle: str, data: bytes) -> bytes:
        """
        Sign data (will hash first, then sign).
        
        For MCUboot signing, use sign_digest() instead to avoid double-hashing!
        """
        # Hash the data
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        message_digest = digest.finalize()
        
        # Sign the digest
        return self.sign_digest(key_handle, message_digest)
    
    def generate_key_pair(self, key_type: AppKeyType, curve: KeyCurve, label: Optional[str] = None) -> KeyPair:
        """
        Generate a key pair in CloudHSM.
        
        Args:
            key_type: Key type (OEM_ROOT, OEM_BOOTLOADER, CUSTOMER)
            curve: Key curve (SECP256R1, SECP384R1, etc.)
            label: Key label for storage
        
        Returns:
            KeyPair object
        """
        if not self.initialized:
            raise HSMError("CloudHSM not connected")
        
        # Generate default label if not provided
        if not label:
            label = f"renesas_{key_type.value}_{curve.value}"
        
        try:
            logger.info(f"Generating {curve.value} key pair in CloudHSM: {label}")
            
            # Map curve to PKCS#11 EC parameters
            curve_oid_map = {
                KeyCurve.SECP256R1: b'\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07',  # P-256
                KeyCurve.SECP384R1: b'\x06\x05\x2b\x81\x04\x00\x22',  # P-384
            }
            
            if curve not in curve_oid_map:
                raise HSMError(f"Unsupported curve: {curve}")
            
            ec_params = curve_oid_map[curve]
            
            # Generate key pair
            pub_key, priv_key = self.session.generate_keypair(
                KeyType.EC,
                public_template={
                    pkcs11.Attribute.LABEL: label,
                    pkcs11.Attribute.EC_PARAMS: ec_params,
                    pkcs11.Attribute.VERIFY: True,
                },
                private_template={
                    pkcs11.Attribute.LABEL: label,
                    pkcs11.Attribute.SIGN: True,
                    pkcs11.Attribute.SENSITIVE: True,
                    pkcs11.Attribute.EXTRACTABLE: False,  # Cannot export private key!
                }
            )
            
            logger.info(f"  Key pair generated successfully!")
            
            # Get public key DER
            public_key_der = self.get_public_key(label)
            
            # Create KeyPair object
            key_pair = KeyPair(
                key_type=key_type,
                curve=curve,
                public_key=public_key_der,
                private_key_handle=label,  # Label is the handle in CloudHSM
                label=label
            )
            
            return key_pair
            
        except Exception as e:
            raise HSMError(f"Key generation failed: {str(e)}") from e
    
    def hash_data(self, data: bytes, algorithm: str = "SHA256") -> bytes:
        """
        Compute hash of data.
        
        Args:
            data: Data to hash
            algorithm: Hash algorithm (default: SHA256)
        
        Returns:
            Hash digest bytes
        """
        # Simple implementation using cryptography library
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        
        algorithm_map = {
            "SHA256": hashes.SHA256(),
            "SHA384": hashes.SHA384(),
            "SHA512": hashes.SHA512(),
        }
        
        if algorithm not in algorithm_map:
            raise HSMError(f"Unsupported hash algorithm: {algorithm}")
        
        digest = hashes.Hash(algorithm_map[algorithm], backend=default_backend())
        digest.update(data)
        return digest.finalize()
    
    def verify_signature(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """
        Verify a signature.
        
        Args:
            public_key: Public key bytes (DER format)
            data: Data that was signed
            signature: Signature bytes (DER format)
        
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.backends import default_backend
            
            # Load public key
            pubkey_obj = serialization.load_der_public_key(public_key, backend=default_backend())
            
            # Verify signature
            pubkey_obj.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            
            return True
            
        except Exception as e:
            logger.debug(f"Signature verification failed: {e}")
            return False
