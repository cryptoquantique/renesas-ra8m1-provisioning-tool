"""
PKCS#11 Session Implementation.

This module provides the Session class that implements standard
PKCS#11 session operations, routing cryptographic calls to the broker.
"""

import base64
from typing import List, Dict, Any, Optional, Tuple

from .types import (
    CKR, CKM, CKO, CKK, CKA, CKU, CKS, CKF,
    CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_MECHANISM,
    CK_SESSION_INFO, CK_ATTRIBUTE,
    PKCS11Error, PKCS11UserNotLoggedIn, PKCS11MechanismInvalid,
    PKCS11KeyHandleInvalid,
)
from utils.logging import get_logger

logger = get_logger(__name__)


class Session:
    """
    PKCS#11 Session implementation.

    Provides standard PKCS#11 session functions:
    - C_Login / C_Logout
    - C_Sign / C_SignInit / C_SignUpdate / C_SignFinal
    - C_Verify / C_VerifyInit / C_VerifyUpdate / C_VerifyFinal
    - C_Digest / C_DigestInit / C_DigestUpdate / C_DigestFinal
    - C_GetAttributeValue
    - C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal
    """

    def __init__(
        self,
        handle: CK_SESSION_HANDLE,
        slot_id: int,
        flags: int,
        broker_transport,
        broker_session_id: str = None,
    ):
        """
        Initialize PKCS#11 session.

        Args:
            handle: Session handle
            slot_id: Slot ID this session belongs to
            flags: Session flags (CKF_RW_SESSION, CKF_SERIAL_SESSION)
            broker_transport: Transport to broker daemon
            broker_session_id: Session ID from broker (from open_session response)
        """
        self._handle = handle
        self._slot_id = slot_id
        self._flags = flags
        self._transport = broker_transport
        self._broker_session_id = broker_session_id

        # Session state
        self._state = CKS.RO_PUBLIC_SESSION
        self._logged_in = False
        self._user_type: Optional[int] = None

        # Active operation state
        self._sign_mechanism: Optional[CK_MECHANISM] = None
        self._sign_key: Optional[CK_OBJECT_HANDLE] = None
        self._sign_data: bytes = b""

        self._verify_mechanism: Optional[CK_MECHANISM] = None
        self._verify_key: Optional[CK_OBJECT_HANDLE] = None
        self._verify_data: bytes = b""

        self._digest_mechanism: Optional[CK_MECHANISM] = None
        self._digest_data: bytes = b""

        # Find operation state
        self._find_template: Optional[List[CK_ATTRIBUTE]] = None
        self._find_results: List[CK_OBJECT_HANDLE] = []
        self._find_index: int = 0

        # Object handle to key ARN mapping
        self._object_handles: Dict[CK_OBJECT_HANDLE, str] = {}
        self._next_handle: CK_OBJECT_HANDLE = 1

    @property
    def handle(self) -> CK_SESSION_HANDLE:
        """Get session handle."""
        return self._handle

    @property
    def is_logged_in(self) -> bool:
        """Check if user is logged in."""
        return self._logged_in

    def get_info(self) -> CK_SESSION_INFO:
        """
        C_GetSessionInfo - Get session information.

        Returns:
            CK_SESSION_INFO structure
        """
        return CK_SESSION_INFO(
            slot_id=self._slot_id,
            state=self._state,
            flags=self._flags,
            device_error=0,
        )

    # =========================================================================
    # Login/Logout (C_Login, C_Logout)
    # =========================================================================

    def C_Login(self, user_type: int, pin: Optional[str] = None) -> CKR:
        """
        C_Login - Log into the token.

        Args:
            user_type: CKU_USER or CKU_SO
            pin: PIN (not used for broker - uses OS credentials)

        Returns:
            CKR return code
        """
        if self._logged_in:
            return CKR.USER_ALREADY_LOGGED_IN

        try:
            # Send login request to broker using broker's session ID
            response = self._broker_request("login", {
                "session_id": self._broker_session_id,
                "user_type": user_type,
            })

            self._logged_in = True
            self._user_type = user_type

            if self._flags & CKF.RW_SESSION:
                self._state = CKS.RW_USER_FUNCTIONS
            else:
                self._state = CKS.RO_USER_FUNCTIONS

            logger.debug(f"Session {self._handle}: logged in as {CKU(user_type).name}")
            return CKR.OK

        except Exception as e:
            logger.error(f"C_Login failed: {e}")
            return CKR.FUNCTION_FAILED

    def C_Logout(self) -> CKR:
        """
        C_Logout - Log out from the token.

        Returns:
            CKR return code
        """
        if not self._logged_in:
            return CKR.USER_NOT_LOGGED_IN

        try:
            self._broker_request("logout", {})

            self._logged_in = False
            self._user_type = None

            if self._flags & CKF.RW_SESSION:
                self._state = CKS.RW_PUBLIC_SESSION
            else:
                self._state = CKS.RO_PUBLIC_SESSION

            logger.debug(f"Session {self._handle}: logged out")
            return CKR.OK

        except Exception as e:
            logger.error(f"C_Logout failed: {e}")
            return CKR.FUNCTION_FAILED

    # =========================================================================
    # Signing Operations (C_SignInit, C_Sign, C_SignUpdate, C_SignFinal)
    # =========================================================================

    def C_SignInit(self, mechanism: CK_MECHANISM, key: CK_OBJECT_HANDLE) -> CKR:
        """
        C_SignInit - Initialize a signing operation.

        Args:
            mechanism: Signing mechanism (CKM_ECDSA, CKM_ECDSA_SHA256, etc.)
            key: Private key handle

        Returns:
            CKR return code
        """
        if not self._logged_in:
            return CKR.USER_NOT_LOGGED_IN

        if self._sign_mechanism is not None:
            return CKR.OPERATION_ACTIVE

        if key not in self._object_handles:
            return CKR.KEY_HANDLE_INVALID

        # Validate mechanism
        supported = [CKM.ECDSA, CKM.ECDSA_SHA256, CKM.ECDSA_SHA384, CKM.ECDSA_SHA512]
        if mechanism.mechanism not in supported:
            return CKR.MECHANISM_INVALID

        self._sign_mechanism = mechanism
        self._sign_key = key
        self._sign_data = b""

        logger.debug(f"C_SignInit: mechanism={CKM(mechanism.mechanism).name}, key={key}")
        return CKR.OK

    def C_Sign(self, data: bytes) -> Tuple[CKR, bytes]:
        """
        C_Sign - Sign data in a single operation.

        Args:
            data: Data to sign

        Returns:
            Tuple of (CKR return code, signature bytes)
        """
        if self._sign_mechanism is None:
            return CKR.OPERATION_NOT_INITIALIZED, b""

        try:
            key_arn = self._object_handles[self._sign_key]
            mechanism = self._sign_mechanism.mechanism

            # Determine if we need to hash or sign pre-hashed
            if mechanism == CKM.ECDSA:
                # Raw ECDSA - data is already a hash (digest)
                method = "sign_digest"
                params = {
                    "key_arn": key_arn,
                    "digest": base64.b64encode(data).decode("ascii"),
                }
            else:
                # ECDSA with hash - broker will hash then sign
                method = "sign"
                params = {
                    "key_arn": key_arn,
                    "data": base64.b64encode(data).decode("ascii"),
                    "mechanism": mechanism,
                }

            response = self._broker_request(method, params)
            signature = base64.b64decode(response["signature"])

            # Clear operation state
            self._sign_mechanism = None
            self._sign_key = None
            self._sign_data = b""

            logger.debug(f"C_Sign: {len(data)} bytes -> {len(signature)} byte signature")
            return CKR.OK, signature

        except Exception as e:
            logger.error(f"C_Sign failed: {e}")
            self._sign_mechanism = None
            self._sign_key = None
            self._sign_data = b""
            return CKR.FUNCTION_FAILED, b""

    def C_SignUpdate(self, data: bytes) -> CKR:
        """
        C_SignUpdate - Continue a multi-part signing operation.

        Args:
            data: Data part to sign

        Returns:
            CKR return code
        """
        if self._sign_mechanism is None:
            return CKR.OPERATION_NOT_INITIALIZED

        self._sign_data += data
        return CKR.OK

    def C_SignFinal(self) -> Tuple[CKR, bytes]:
        """
        C_SignFinal - Finish a multi-part signing operation.

        Returns:
            Tuple of (CKR return code, signature bytes)
        """
        if self._sign_mechanism is None:
            return CKR.OPERATION_NOT_INITIALIZED, b""

        return self.C_Sign(self._sign_data)

    # =========================================================================
    # Verification Operations (C_VerifyInit, C_Verify, etc.)
    # =========================================================================

    def C_VerifyInit(self, mechanism: CK_MECHANISM, key: CK_OBJECT_HANDLE) -> CKR:
        """
        C_VerifyInit - Initialize a verification operation.

        Args:
            mechanism: Verification mechanism
            key: Public key handle

        Returns:
            CKR return code
        """
        if not self._logged_in:
            return CKR.USER_NOT_LOGGED_IN

        if self._verify_mechanism is not None:
            return CKR.OPERATION_ACTIVE

        if key not in self._object_handles:
            return CKR.KEY_HANDLE_INVALID

        supported = [CKM.ECDSA, CKM.ECDSA_SHA256, CKM.ECDSA_SHA384, CKM.ECDSA_SHA512]
        if mechanism.mechanism not in supported:
            return CKR.MECHANISM_INVALID

        self._verify_mechanism = mechanism
        self._verify_key = key
        self._verify_data = b""

        return CKR.OK

    def C_Verify(self, data: bytes, signature: bytes) -> CKR:
        """
        C_Verify - Verify a signature.

        Args:
            data: Original data
            signature: Signature to verify

        Returns:
            CKR return code (CKR_OK if valid, CKR_SIGNATURE_INVALID if not)
        """
        if self._verify_mechanism is None:
            return CKR.OPERATION_NOT_INITIALIZED

        try:
            key_arn = self._object_handles[self._verify_key]

            response = self._broker_request("verify", {
                "key_arn": key_arn,
                "data": base64.b64encode(data).decode("ascii"),
                "signature": base64.b64encode(signature).decode("ascii"),
            })

            self._verify_mechanism = None
            self._verify_key = None
            self._verify_data = b""

            if response.get("valid"):
                return CKR.OK
            else:
                return CKR.SIGNATURE_INVALID

        except Exception as e:
            logger.error(f"C_Verify failed: {e}")
            self._verify_mechanism = None
            self._verify_key = None
            return CKR.FUNCTION_FAILED

    # =========================================================================
    # Digest Operations (C_DigestInit, C_Digest, etc.)
    # =========================================================================

    def C_DigestInit(self, mechanism: CK_MECHANISM) -> CKR:
        """
        C_DigestInit - Initialize a digest operation.

        Args:
            mechanism: Hash mechanism (CKM_SHA256, etc.)

        Returns:
            CKR return code
        """
        if self._digest_mechanism is not None:
            return CKR.OPERATION_ACTIVE

        supported = [CKM.SHA256, CKM.SHA384, CKM.SHA512, CKM.SHA_1]
        if mechanism.mechanism not in supported:
            return CKR.MECHANISM_INVALID

        self._digest_mechanism = mechanism
        self._digest_data = b""

        return CKR.OK

    def C_Digest(self, data: bytes) -> Tuple[CKR, bytes]:
        """
        C_Digest - Compute digest in a single operation.

        Args:
            data: Data to hash

        Returns:
            Tuple of (CKR return code, digest bytes)
        """
        if self._digest_mechanism is None:
            return CKR.OPERATION_NOT_INITIALIZED, b""

        try:
            mechanism = self._digest_mechanism.mechanism
            algo_map = {
                CKM.SHA256: "SHA256",
                CKM.SHA384: "SHA384",
                CKM.SHA512: "SHA512",
                CKM.SHA_1: "SHA1",
            }

            response = self._broker_request("hash", {
                "data": base64.b64encode(data).decode("ascii"),
                "algorithm": algo_map.get(mechanism, "SHA256"),
            })

            digest = base64.b64decode(response["digest"])

            self._digest_mechanism = None
            self._digest_data = b""

            return CKR.OK, digest

        except Exception as e:
            logger.error(f"C_Digest failed: {e}")
            self._digest_mechanism = None
            return CKR.FUNCTION_FAILED, b""

    def C_DigestUpdate(self, data: bytes) -> CKR:
        """C_DigestUpdate - Continue multi-part digest."""
        if self._digest_mechanism is None:
            return CKR.OPERATION_NOT_INITIALIZED
        self._digest_data += data
        return CKR.OK

    def C_DigestFinal(self) -> Tuple[CKR, bytes]:
        """C_DigestFinal - Finish multi-part digest."""
        if self._digest_mechanism is None:
            return CKR.OPERATION_NOT_INITIALIZED, b""
        return self.C_Digest(self._digest_data)

    # =========================================================================
    # Object Operations (C_GetAttributeValue, C_FindObjects, etc.)
    # =========================================================================

    def C_GetAttributeValue(
        self,
        obj: CK_OBJECT_HANDLE,
        template: List[CK_ATTRIBUTE],
    ) -> Tuple[CKR, List[CK_ATTRIBUTE]]:
        """
        C_GetAttributeValue - Get attribute values from an object.

        Args:
            obj: Object handle
            template: Attributes to retrieve

        Returns:
            Tuple of (CKR return code, filled template)
        """
        if obj not in self._object_handles:
            return CKR.OBJECT_HANDLE_INVALID, template

        key_arn = self._object_handles[obj]

        try:
            result = []
            for attr in template:
                if attr.type == CKA.CLASS:
                    attr.value = CKO.PRIVATE_KEY
                elif attr.type == CKA.KEY_TYPE:
                    attr.value = CKK.EC
                elif attr.type == CKA.LABEL:
                    attr.value = key_arn
                elif attr.type == CKA.ID:
                    attr.value = key_arn.encode()
                elif attr.type == CKA.EC_POINT:
                    # Get public key from broker
                    response = self._broker_request("get_public_key", {
                        "key_arn": key_arn,
                    })
                    attr.value = base64.b64decode(response["public_key"])
                elif attr.type == CKA.SIGN:
                    attr.value = True
                elif attr.type == CKA.VERIFY:
                    attr.value = True
                result.append(attr)

            return CKR.OK, result

        except Exception as e:
            logger.error(f"C_GetAttributeValue failed: {e}")
            return CKR.FUNCTION_FAILED, template

    def C_FindObjectsInit(self, template: List[CK_ATTRIBUTE]) -> CKR:
        """
        C_FindObjectsInit - Initialize object search.

        Args:
            template: Search template

        Returns:
            CKR return code
        """
        if self._find_template is not None:
            return CKR.OPERATION_ACTIVE

        self._find_template = template
        self._find_results = []
        self._find_index = 0

        # Query broker for keys
        try:
            response = self._broker_request("list_keys", {})
            keys = response.get("keys", [])

            for key_info in keys:
                key_arn = key_info.get("arn") or key_info.get("key_id")
                if key_arn:
                    # Create handle for this key
                    handle = self._next_handle
                    self._next_handle += 1
                    self._object_handles[handle] = key_arn
                    self._find_results.append(handle)

            return CKR.OK

        except Exception as e:
            logger.error(f"C_FindObjectsInit failed: {e}")
            return CKR.FUNCTION_FAILED

    def C_FindObjects(self, max_count: int) -> Tuple[CKR, List[CK_OBJECT_HANDLE]]:
        """
        C_FindObjects - Get found objects.

        Args:
            max_count: Maximum objects to return

        Returns:
            Tuple of (CKR return code, list of object handles)
        """
        if self._find_template is None:
            return CKR.OPERATION_NOT_INITIALIZED, []

        results = self._find_results[self._find_index:self._find_index + max_count]
        self._find_index += len(results)

        return CKR.OK, results

    def C_FindObjectsFinal(self) -> CKR:
        """
        C_FindObjectsFinal - Finish object search.

        Returns:
            CKR return code
        """
        self._find_template = None
        self._find_results = []
        self._find_index = 0
        return CKR.OK

    # =========================================================================
    # Key Generation (C_GenerateKeyPair)
    # =========================================================================

    def C_GenerateKeyPair(
        self,
        mechanism: CK_MECHANISM,
        public_key_template: List[CK_ATTRIBUTE],
        private_key_template: List[CK_ATTRIBUTE],
    ) -> Tuple[CKR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE]:
        """
        C_GenerateKeyPair - Generate a public/private key pair.

        Args:
            mechanism: Key generation mechanism (e.g., CKM_EC_KEY_PAIR_GEN)
            public_key_template: Attributes for the public key
            private_key_template: Attributes for the private key

        Returns:
            Tuple of (CKR return code, public key handle, private key handle)
        """
        if not self._logged_in:
            return CKR.USER_NOT_LOGGED_IN, 0, 0

        # Validate mechanism
        supported = [CKM.EC_KEY_PAIR_GEN]
        if mechanism.mechanism not in supported:
            return CKR.MECHANISM_INVALID, 0, 0

        try:
            # Extract key parameters from templates
            key_type = None
            curve = "secp256r1"  # Default
            label = None

            for attr in private_key_template:
                if attr.type == CKA.LABEL and attr.value:
                    if isinstance(attr.value, bytes):
                        label = attr.value.decode("utf-8")
                    else:
                        label = str(attr.value)
                elif attr.type == CKA.ID and attr.value:
                    # Use ID to determine key type if present
                    if isinstance(attr.value, bytes):
                        key_type_str = attr.value.decode("utf-8")
                    else:
                        key_type_str = str(attr.value)
                    # Parse key type from ID (e.g., "oem_root", "oem_bootloader")
                    key_type = key_type_str.lower()

            # Extract curve from public key template (CKA_EC_PARAMS)
            for attr in public_key_template:
                if attr.type == CKA.EC_PARAMS and attr.value:
                    # Parse EC params OID to determine curve
                    # For now, default to secp256r1 (P-256)
                    # OID for secp256r1: 1.2.840.10045.3.1.7
                    curve = "secp256r1"

            if not key_type:
                # Try to extract from label
                if label:
                    if "oem_root" in label.lower():
                        key_type = "oem_root"
                    elif "oem_bl" in label.lower() or "bootloader" in label.lower():
                        key_type = "oem_bootloader"
                    elif "customer" in label.lower():
                        key_type = "customer"
                    else:
                        key_type = "oem_root"  # Default
                else:
                    key_type = "oem_root"  # Default

            # Request key generation from broker
            response = self._broker_request("generate_key_pair", {
                "key_type": key_type,
                "curve": curve,
                "label": label,
            })

            # Get the key ARN from response
            key_arn = response.get("arn") or response.get("key_id")
            if not key_arn:
                return CKR.FUNCTION_FAILED, 0, 0

            # Create handles for the key pair
            private_handle = self._next_handle
            self._next_handle += 1
            self._object_handles[private_handle] = key_arn

            public_handle = self._next_handle
            self._next_handle += 1
            self._object_handles[public_handle] = key_arn

            # Store additional info for later retrieval
            self._key_info = getattr(self, '_key_info', {})
            self._key_info[private_handle] = {
                "key_arn": key_arn,
                "public_key": response.get("public_key"),
                "key_type": key_type,
                "curve": curve,
                "label": response.get("label"),
            }
            self._key_info[public_handle] = self._key_info[private_handle]

            logger.info(f"C_GenerateKeyPair: created {key_type} key {key_arn}")
            return CKR.OK, public_handle, private_handle

        except Exception as e:
            logger.error(f"C_GenerateKeyPair failed: {e}")
            return CKR.FUNCTION_FAILED, 0, 0

    def get_generated_key_info(self, handle: CK_OBJECT_HANDLE) -> Optional[Dict[str, Any]]:
        """
        Get information about a generated key.

        Args:
            handle: Key handle from C_GenerateKeyPair

        Returns:
            Dictionary with key info or None
        """
        key_info = getattr(self, '_key_info', {})
        return key_info.get(handle)

    # =========================================================================
    # Key Management
    # =========================================================================

    def register_key(self, key_arn: str) -> CK_OBJECT_HANDLE:
        """
        Register a key ARN and get a PKCS#11 object handle.

        Args:
            key_arn: AWS KMS key ARN or ID

        Returns:
            Object handle for this key
        """
        # Check if already registered
        for handle, arn in self._object_handles.items():
            if arn == key_arn:
                return handle

        handle = self._next_handle
        self._next_handle += 1
        self._object_handles[handle] = key_arn

        logger.debug(f"Registered key {key_arn} as handle {handle}")
        return handle

    def get_key_arn(self, handle: CK_OBJECT_HANDLE) -> Optional[str]:
        """
        Get key ARN for an object handle.

        Args:
            handle: Object handle

        Returns:
            Key ARN or None
        """
        return self._object_handles.get(handle)

    # =========================================================================
    # Broker Communication
    # =========================================================================

    def _broker_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send request to broker and get response.

        Args:
            method: Method name
            params: Method parameters

        Returns:
            Response result

        Raises:
            PKCS11Error: If request fails
        """
        import json

        # Build JSON-RPC request (internal protocol to broker)
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self._handle,
        }

        # Send via transport
        self._transport.send(json.dumps(request).encode("utf-8"))
        response_data = self._transport.receive()
        response = json.loads(response_data.decode("utf-8"))

        if "error" in response:
            error = response["error"]
            raise PKCS11Error(
                CKR.FUNCTION_FAILED,
                f"{error.get('message', 'Unknown error')}"
            )

        return response.get("result", {})
