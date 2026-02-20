"""
Broker-based HSM client implementation.

This module provides an HSMClient implementation that communicates
with AWS KMS through the local crypto broker service using a native
PKCS#11 interface.
"""

from pathlib import Path
from typing import Optional, Dict

from models.keys import KeyCurve, KeyPair, KeyType
from utils.exceptions import HSMError
from utils.logging import get_logger
from .base import HSMClient

logger = get_logger(__name__)


class BrokerHSMClient(HSMClient):
    """
    HSM client that communicates via the crypto broker using PKCS#11.

    This client connects to a local broker daemon using a native PKCS#11
    interface instead of directly to AWS KMS, providing an additional
    layer of security and credential isolation.

    The broker must be running before this client can connect.
    """

    def __init__(self, config: dict):
        """
        Initialize broker HSM client.

        Args:
            config: Configuration dictionary with:
                - socket_path: Broker socket path (optional, uses default)
                - timeout: Request timeout in seconds (default: 30)
                - key_prefix: Key alias prefix (default: "renesas_")

        Raises:
            HSMError: If initialization fails
        """
        super().__init__(config)

        self.socket_path = config.get("socket_path")
        self.timeout = config.get("timeout", 30.0)
        self.key_prefix = config.get("key_prefix", "renesas_")
        self.aws_region = config.get("aws_region")
        self.aws_access_key_id = config.get("aws_access_key_id")
        self.aws_secret_access_key = config.get("aws_secret_access_key")

        # PKCS#11 objects
        self._lib = None
        self._session_handle = None
        self._slot_id = None

        # Cache of key ARN -> PKCS#11 object handle
        self._key_handles: Dict[str, int] = {}

        logger.info("Broker HSM client initialized")

    def _get_config_fingerprint(self) -> dict:
        """
        Build a fingerprint of the current broker-relevant config.

        Returns a dict with region and a hash of the credentials so we can
        detect config changes without storing secrets.
        """
        import hashlib

        creds_raw = f"{self.aws_access_key_id}:{self.aws_secret_access_key}"
        creds_hash = hashlib.sha256(creds_raw.encode()).hexdigest()
        return {
            "aws_region": self.aws_region or "",
            "creds_hash": creds_hash,
        }

    def _fingerprint_path(self) -> "Path":
        """Return path to the broker config fingerprint file."""
        import os
        tmp = os.environ.get("TEMP", "C:\\Temp") if __import__("sys").platform == "win32" else os.environ.get("XDG_RUNTIME_DIR", "/tmp")
        return Path(tmp) / "crypto_broker_config.json"

    def _write_fingerprint(self) -> None:
        """Persist the current config fingerprint to disk."""
        import json
        fp = self._get_config_fingerprint()
        self._fingerprint_path().write_text(json.dumps(fp))

    def _config_changed(self) -> bool:
        """
        Return True when the running broker was started with a different config.

        Compares the persisted fingerprint (written when broker last started)
        against the current config.  Returns True when no fingerprint exists so
        the broker is always restarted with the current config on first use.
        """
        import json
        fp_path = self._fingerprint_path()
        if not fp_path.exists():
            return True
        try:
            stored = json.loads(fp_path.read_text())
            current = self._get_config_fingerprint()
            return stored != current
        except Exception:
            return True

    def _stop_broker(self) -> None:
        """Stop the running broker daemon."""
        try:
            from security.broker.service.daemon import stop_daemon, get_default_pid_file
            stop_daemon(get_default_pid_file())
            import time
            time.sleep(1.0)
        except Exception as e:
            logger.warning(f"Could not stop broker cleanly: {e}")

    def _ensure_broker_running(self) -> None:
        """
        Ensure the broker daemon is running with the current config.

        If the broker is already running but was started with a different AWS
        region or credentials, it is stopped and restarted automatically so
        that config changes in project_config.json are always picked up without
        manual intervention.
        """
        from security.hsm.factory import is_broker_available

        if is_broker_available(self.socket_path):
            if self._config_changed():
                logger.info(
                    "Broker config changed (region/credentials) — restarting broker..."
                )
                self._stop_broker()
            else:
                logger.debug("Broker daemon is already running with current config")
                return

        logger.info("Broker daemon not running - starting automatically...")
        
        try:
            import sys
            import os
            import subprocess
            import time
            
            # Propagate AWS region to broker subprocess via environment variable
            env = os.environ.copy()
            if self.aws_region:
                env["AWS_DEFAULT_REGION"] = self.aws_region
                logger.info(f"Broker will use AWS region: {self.aws_region}")
            
            cmd = [sys.executable, "-m", "cli", "broker", "start"]
            if self.aws_region:
                cmd.extend(["--region", self.aws_region])

            if sys.platform == "win32":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                
                proc = subprocess.Popen(
                    cmd,
                    startupinfo=startupinfo,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
                    cwd=str(Path(__file__).parent.parent.parent),
                    env=env,
                )
            else:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                    cwd=str(Path(__file__).parent.parent.parent),
                    env=env,
                )
            
            # Wait for broker to be available (max 10 seconds)
            for i in range(20):
                time.sleep(0.5)
                if is_broker_available(self.socket_path):
                    logger.info("Broker daemon started successfully")
                    self._write_fingerprint()
                    return

            logger.warning("Broker daemon may not have started properly, attempting connection anyway...")
            self._write_fingerprint()
            
        except Exception as e:
            logger.warning(f"Failed to auto-start broker daemon: {e}")
            logger.info("You may need to start it manually: python -m security.broker.service.daemon")

    def connect(self) -> None:
        """
        Connect to the crypto broker using PKCS#11.

        Establishes connection to the broker daemon via the PKCS#11
        library interface and opens an authenticated session.
        
        The broker daemon will be started automatically if not running.

        Raises:
            HSMError: If connection fails
        """
        if self.initialized:
            return

        # Auto-start broker if not running
        self._ensure_broker_running()

        try:
            from security.broker.pkcs11 import BrokerPKCS11Lib, CKR, CKF, CKU

            self._lib = BrokerPKCS11Lib(socket_path=self.socket_path)

            # Initialize PKCS#11 library
            rv = self._lib.C_Initialize()
            if rv != CKR.OK:
                raise HSMError(f"C_Initialize failed: {rv.name}")

            # Get slot list
            rv, slots = self._lib.C_GetSlotList(token_present=True)
            if rv != CKR.OK or not slots:
                raise HSMError(f"C_GetSlotList failed: {rv.name}")

            self._slot_id = slots[0]

            # Open session
            flags = CKF.SERIAL_SESSION | CKF.RW_SESSION
            rv, session = self._lib.C_OpenSession(self._slot_id, flags)
            if rv != CKR.OK:
                raise HSMError(f"C_OpenSession failed: {rv.name}")

            self._session_handle = session

            # Login (uses OS authentication via broker)
            rv = self._lib.C_Login(self._session_handle, CKU.USER)
            if rv != CKR.OK:
                raise HSMError(f"C_Login failed: {rv.name}")

            self.initialized = True
            logger.info("Connected to crypto broker via PKCS#11")

        except HSMError:
            self._cleanup()
            raise
        except Exception as e:
            self._cleanup()
            raise HSMError(f"Failed to connect to broker: {str(e)}") from e

    def _cleanup(self) -> None:
        """Clean up PKCS#11 resources."""
        if self._lib:
            try:
                self._lib.C_Finalize()
            except Exception:
                pass
        self._lib = None
        self._session_handle = None
        self._slot_id = None
        self._key_handles.clear()

    def disconnect(self) -> None:
        """Disconnect from the crypto broker."""
        if self._lib and self._session_handle:
            try:
                self._lib.C_Logout(self._session_handle)
                self._lib.C_CloseSession(self._session_handle)
            except Exception:
                pass

        self._cleanup()
        self.initialized = False
        logger.info("Disconnected from crypto broker")

    def _get_key_handle(self, key_arn: str) -> int:
        """
        Get or register a PKCS#11 object handle for a KMS key.

        Args:
            key_arn: KMS Key ID, ARN, or alias

        Returns:
            PKCS#11 object handle

        Raises:
            HSMError: If key registration fails
        """
        if key_arn in self._key_handles:
            return self._key_handles[key_arn]

        from security.broker.pkcs11 import CKR

        rv, handle = self._lib.register_key(self._session_handle, key_arn)
        if rv != CKR.OK:
            raise HSMError(f"Failed to register key {key_arn}: {rv.name}")

        self._key_handles[key_arn] = handle
        return handle

    def generate_key_pair(
        self, key_type: KeyType, curve: KeyCurve, label: Optional[str] = None
    ) -> KeyPair:
        """
        Generate a new ECC key pair via the broker using PKCS#11.

        Args:
            key_type: Type of key pair to generate
            curve: Elliptic curve to use
            label: Optional label for the key

        Returns:
            KeyPair object with key ID and public key

        Raises:
            HSMError: If key generation fails
        """
        if not self.initialized:
            raise HSMError("Broker HSM not connected")

        try:
            from security.broker.pkcs11 import CKR, CKM, CKA, CK_MECHANISM, CK_ATTRIBUTE
            import base64

            # Map KeyCurve to curve name
            curve_map = {
                KeyCurve.SECP256R1: "secp256r1",
                KeyCurve.SECP384R1: "secp384r1",
                KeyCurve.SECP521R1: "secp521r1",
            }
            curve_name = curve_map.get(curve, "secp256r1")

            # Build key label
            key_label = label or f"{self.key_prefix}{key_type.value}"

            # Create mechanism
            mechanism = CK_MECHANISM(CKM.EC_KEY_PAIR_GEN)

            # Create templates
            public_key_template = [
                CK_ATTRIBUTE(CKA.VERIFY, True),
                CK_ATTRIBUTE(CKA.LABEL, key_label.encode("utf-8")),
            ]

            private_key_template = [
                CK_ATTRIBUTE(CKA.SIGN, True),
                CK_ATTRIBUTE(CKA.LABEL, key_label.encode("utf-8")),
                CK_ATTRIBUTE(CKA.ID, key_type.value.encode("utf-8")),
            ]

            # Generate key pair
            rv, pub_handle, priv_handle = self._lib.C_GenerateKeyPair(
                self._session_handle,
                mechanism,
                public_key_template,
                private_key_template,
            )

            if rv != CKR.OK:
                raise HSMError(f"C_GenerateKeyPair failed: {rv.name}")

            # Get key info from session
            key_info = self._lib.get_generated_key_info(self._session_handle, priv_handle)
            if not key_info:
                raise HSMError("Failed to get generated key info")

            # Get key ARN
            key_arn = key_info.get("key_arn")
            if not key_arn:
                raise HSMError("No key ARN in response")

            # Cache the key handle
            self._key_handles[key_arn] = priv_handle

            # Get public key (base64 encoded in key_info)
            public_key_b64 = key_info.get("public_key")
            if public_key_b64:
                public_key_der = base64.b64decode(public_key_b64)
            else:
                # Fallback: fetch public key via get_public_key
                public_key_der = self.get_public_key(key_arn)

            # Convert to PEM
            from security.key_utils import convert_public_key_to_pem
            public_key_pem = convert_public_key_to_pem(public_key_der, curve)

            logger.info(f"Generated {key_type.value} key via broker: {key_arn}")

            return KeyPair(
                key_type=key_type,
                curve=curve,
                public_key=public_key_der,
                public_key_pem=public_key_pem,
                private_key_handle=key_arn,
                label=key_label,
            )

        except HSMError:
            raise
        except Exception as e:
            raise HSMError(f"Failed to generate key pair: {str(e)}") from e

    def get_public_key(self, key_handle: str) -> bytes:
        """
        Retrieve public key from HSM via broker, with direct AWS KMS fallback.

        Getting the public key is a read-only, non-sensitive operation.
        If the broker PKCS#11 path fails (e.g. missing kms:GetPublicKey permission
        routed through broker), we fall back to calling AWS KMS directly using
        the credentials stored in this client.

        Args:
            key_handle: KMS Key ID, ARN, or alias

        Returns:
            Public key bytes in DER format

        Raises:
            HSMError: If key retrieval fails via both broker and direct paths
        """
        if not self.initialized:
            raise HSMError("Broker HSM not connected")

        try:
            from security.broker.pkcs11 import CKR, CKA, CK_ATTRIBUTE

            obj_handle = self._get_key_handle(key_handle)

            # Request CKA_EC_POINT (public key value)
            template = [CK_ATTRIBUTE(CKA.EC_POINT, None)]
            rv, attrs = self._lib.C_GetAttributeValue(
                self._session_handle, obj_handle, template
            )

            if rv != CKR.OK:
                raise HSMError(f"C_GetAttributeValue failed: {rv.name}")

            for attr in attrs:
                if attr.type == CKA.EC_POINT and attr.value:
                    return attr.value

            raise HSMError("Public key not found in attributes")

        except HSMError as broker_err:
            # Fallback: GetPublicKey is non-sensitive - call AWS KMS directly
            logger.warning(
                f"Broker path failed for get_public_key: {broker_err}. "
                "Attempting direct AWS KMS fallback..."
            )
            return self._get_public_key_direct(key_handle, broker_err)

        except Exception as e:
            logger.warning(
                f"Broker path error for get_public_key: {e}. "
                "Attempting direct AWS KMS fallback..."
            )
            return self._get_public_key_direct(key_handle, HSMError(str(e)))

    def _get_public_key_direct(self, key_handle: str, original_error: Exception) -> bytes:
        """
        Retrieve public key directly from AWS KMS (bypass broker).

        This is a fallback for get_public_key when the broker path fails.
        Getting a public key is non-sensitive and does not require the broker.

        Args:
            key_handle: KMS Key ID, ARN, or alias
            original_error: The error from the broker path (for context)

        Returns:
            Public key bytes in DER format

        Raises:
            HSMError: If direct KMS call also fails
        """
        if not self.aws_region:
            raise HSMError(
                f"Broker get_public_key failed: {original_error}. "
                "Cannot fallback: no aws_region configured."
            )

        try:
            import boto3

            if self.aws_access_key_id and self.aws_secret_access_key:
                kms_client = boto3.client(
                    "kms",
                    region_name=self.aws_region,
                    aws_access_key_id=self.aws_access_key_id,
                    aws_secret_access_key=self.aws_secret_access_key,
                )
            else:
                kms_client = boto3.client("kms", region_name=self.aws_region)

            response = kms_client.get_public_key(KeyId=key_handle)
            public_key_der = bytes(response["PublicKey"])

            logger.info(
                f"Retrieved public key directly from AWS KMS: "
                f"{len(public_key_der)} bytes (DER)"
            )
            return public_key_der

        except Exception as direct_err:
            raise HSMError(
                f"get_public_key failed via both broker and direct KMS paths.\n"
                f"  Broker error: {original_error}\n"
                f"  Direct KMS error: {direct_err}\n"
                f"  Check that the IAM user has kms:GetPublicKey permission "
                f"for key {key_handle} in region {self.aws_region}."
            ) from direct_err

    def sign_digest(self, key_handle: str, message_digest: bytes) -> bytes:
        """
        Sign a pre-computed digest directly using PKCS#11.

        CRITICAL: Use this for MCUboot signing to avoid double-hashing!
        Uses CKM_ECDSA mechanism (raw ECDSA without internal hashing).

        Args:
            key_handle: KMS Key ID, ARN, or alias
            message_digest: Pre-computed digest (e.g., SHA256 hash, 32 bytes)

        Returns:
            Signature bytes (DER format for ECDSA)

        Raises:
            HSMError: If signing fails
        """
        if not self.initialized:
            raise HSMError("Broker HSM not connected")

        try:
            from security.broker.pkcs11 import CKR, CKM, CK_MECHANISM

            obj_handle = self._get_key_handle(key_handle)

            # Use raw ECDSA mechanism (no internal hashing)
            mechanism = CK_MECHANISM(CKM.ECDSA)

            rv = self._lib.C_SignInit(self._session_handle, mechanism, obj_handle)
            if rv != CKR.OK:
                raise HSMError(f"C_SignInit failed: {rv.name}")

            rv, signature = self._lib.C_Sign(self._session_handle, message_digest)
            if rv != CKR.OK:
                raise HSMError(f"C_Sign failed: {rv.name}")

            return signature

        except HSMError:
            raise
        except Exception as e:
            raise HSMError(f"Failed to sign digest: {str(e)}") from e

    def sign_data(self, key_handle: str, data: bytes) -> bytes:
        """
        Sign data using a key via the broker.

        NOTE: This method hashes the data before signing using CKM_ECDSA_SHA256.
        For pre-hashed data (like MCUboot), use sign_digest() instead.

        Args:
            key_handle: KMS Key ID, ARN, or alias
            data: Data to sign

        Returns:
            Signature bytes

        Raises:
            HSMError: If signing fails
        """
        if not self.initialized:
            raise HSMError("Broker HSM not connected")

        try:
            from security.broker.pkcs11 import CKR, CKM, CK_MECHANISM

            obj_handle = self._get_key_handle(key_handle)

            # Use ECDSA with SHA256 (mechanism handles hashing)
            mechanism = CK_MECHANISM(CKM.ECDSA_SHA256)

            rv = self._lib.C_SignInit(self._session_handle, mechanism, obj_handle)
            if rv != CKR.OK:
                raise HSMError(f"C_SignInit failed: {rv.name}")

            rv, signature = self._lib.C_Sign(self._session_handle, data)
            if rv != CKR.OK:
                raise HSMError(f"C_Sign failed: {rv.name}")

            return signature

        except HSMError:
            raise
        except Exception as e:
            raise HSMError(f"Failed to sign data: {str(e)}") from e

    def verify_signature(
        self, public_key: bytes, data: bytes, signature: bytes, key_handle: Optional[str] = None
    ) -> bool:
        """
        Verify a signature via the broker using PKCS#11.

        Args:
            public_key: Public key bytes (used for local verification if no key_handle)
            data: Original data
            signature: Signature to verify
            key_handle: Optional KMS Key ID for broker-based verification

        Returns:
            True if signature is valid

        Raises:
            HSMError: If verification fails
        """
        if not self.initialized:
            raise HSMError("Broker HSM not connected")

        if not key_handle:
            # Fall back to local verification if no key handle
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.backends import default_backend

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
                    raise HSMError(f"Unsupported curve: {curve}")

                # Compute hash and verify
                digest = hashes.Hash(hash_alg, backend=default_backend())
                digest.update(data)
                message_digest = digest.finalize()

                pub_key.verify(signature, message_digest, ec.ECDSA(hash_alg))
                return True

            except Exception as e:
                logger.error(f"Local verification failed: {e}")
                return False

        try:
            from security.broker.pkcs11 import CKR, CKM, CK_MECHANISM

            obj_handle = self._get_key_handle(key_handle)

            # Use ECDSA with SHA256 for verification
            mechanism = CK_MECHANISM(CKM.ECDSA_SHA256)

            rv = self._lib.C_VerifyInit(self._session_handle, mechanism, obj_handle)
            if rv != CKR.OK:
                raise HSMError(f"C_VerifyInit failed: {rv.name}")

            rv = self._lib.C_Verify(self._session_handle, data, signature)
            return rv == CKR.OK

        except HSMError:
            raise
        except Exception as e:
            raise HSMError(f"Failed to verify signature: {str(e)}") from e

    def hash_data(self, data: bytes, algorithm: str = "SHA256") -> bytes:
        """
        Compute hash of data via PKCS#11.

        Args:
            data: Data to hash
            algorithm: Hash algorithm (SHA256, SHA384, SHA512)

        Returns:
            Hash bytes

        Raises:
            HSMError: If hashing fails
        """
        if not self.initialized:
            raise HSMError("Broker HSM not connected")

        try:
            from security.broker.pkcs11 import CKR, CKM, CK_MECHANISM

            # Map algorithm name to PKCS#11 mechanism
            mech_map = {
                "SHA256": CKM.SHA256,
                "SHA384": CKM.SHA384,
                "SHA512": CKM.SHA512,
                "SHA1": CKM.SHA_1,
            }

            mech_type = mech_map.get(algorithm.upper())
            if mech_type is None:
                raise HSMError(f"Unsupported hash algorithm: {algorithm}")

            mechanism = CK_MECHANISM(mech_type)

            rv = self._lib.C_DigestInit(self._session_handle, mechanism)
            if rv != CKR.OK:
                raise HSMError(f"C_DigestInit failed: {rv.name}")

            rv, digest = self._lib.C_Digest(self._session_handle, data)
            if rv != CKR.OK:
                raise HSMError(f"C_Digest failed: {rv.name}")

            return digest

        except HSMError:
            raise
        except Exception as e:
            raise HSMError(f"Failed to hash data: {str(e)}") from e

    def list_keys(self) -> list:
        """
        List keys available via broker from AWS KMS.

        Calls the broker's list_keys endpoint to retrieve all
        available KMS keys.

        Returns:
            List of key dictionaries with key metadata
        """
        if not self.initialized:
            raise HSMError("Broker HSM not connected")

        try:
            # Get the session to make a broker request
            for slot in self._lib._slots.values():
                session = slot.get_session(self._session_handle)
                if session:
                    # Call broker's list_keys method
                    result = session._broker_request("list_keys", {})
                    return result.get("keys", [])

            # Fallback to locally cached keys if no session found
            return list(self._key_handles.keys())

        except Exception as e:
            logger.warning(f"Failed to list keys from broker: {e}")
            # Fallback to locally cached keys
            return list(self._key_handles.keys())

    def ping(self) -> dict:
        """
        Ping the broker service.

        Returns:
            Status dictionary

        Raises:
            HSMError: If ping fails
        """
        if not self._lib:
            raise HSMError("Broker HSM not connected")

        try:
            rv, info = self._lib.C_GetInfo()
            if rv.value == 0:  # CKR.OK
                return {
                    "status": "ok",
                    "cryptoki_version": f"{info.cryptoki_version.major}.{info.cryptoki_version.minor}",
                    "manufacturer": info.manufacturer_id.strip(),
                    "library_description": info.library_description.strip(),
                    "library_version": f"{info.library_version.major}.{info.library_version.minor}",
                }
            return {"status": "error", "code": rv.name}
        except Exception as e:
            raise HSMError(f"Broker ping failed: {str(e)}") from e

    def get_broker_info(self) -> dict:
        """
        Get broker service information via PKCS#11.

        Returns:
            Info dictionary with library and token details

        Raises:
            HSMError: If info retrieval fails
        """
        if not self._lib:
            raise HSMError("Broker HSM not connected")

        try:
            result = {}

            # Get library info
            rv, lib_info = self._lib.C_GetInfo()
            if rv.value == 0:  # CKR.OK
                result["library"] = {
                    "cryptoki_version": f"{lib_info.cryptoki_version.major}.{lib_info.cryptoki_version.minor}",
                    "manufacturer": lib_info.manufacturer_id.strip(),
                    "description": lib_info.library_description.strip(),
                    "version": f"{lib_info.library_version.major}.{lib_info.library_version.minor}",
                }

            # Get token info if we have a slot
            if self._slot_id is not None:
                rv, token_info = self._lib.C_GetTokenInfo(self._slot_id)
                if rv.value == 0:  # CKR.OK
                    result["token"] = {
                        "label": token_info.label.strip(),
                        "manufacturer": token_info.manufacturer_id.strip(),
                        "model": token_info.model.strip(),
                        "serial": token_info.serial_number.strip(),
                        "session_count": token_info.session_count,
                    }

            return result

        except Exception as e:
            raise HSMError(f"Failed to get broker info: {str(e)}") from e
