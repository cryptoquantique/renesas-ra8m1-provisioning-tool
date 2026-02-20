"""
PKCS#11 Library Implementation.

This module provides the BrokerPKCS11Lib class that implements
the top-level PKCS#11 library functions (C_Initialize, C_GetSlotList, etc.).
"""

from typing import List, Dict, Optional, Tuple

from .types import (
    CKR, CKF, CKU,
    CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
    CK_INFO, CK_SLOT_INFO, CK_TOKEN_INFO, CK_SESSION_INFO,
    CK_MECHANISM, CK_MECHANISM_INFO, CK_ATTRIBUTE, CK_VERSION,
    PKCS11Error,
)
from .session import Session
from .token import Slot
from security.broker.client.transport import create_transport, IPCTransport
from utils.logging import get_logger

logger = get_logger(__name__)


class BrokerPKCS11Lib:
    """
    PKCS#11 Library backed by the crypto broker.

    This class implements the standard PKCS#11 C_* functions,
    routing cryptographic operations through the broker to AWS KMS.

    Usage:
        lib = BrokerPKCS11Lib()
        lib.C_Initialize()

        slots = lib.C_GetSlotList(token_present=True)
        session = lib.C_OpenSession(slots[0], CKF.SERIAL_SESSION | CKF.RW_SESSION)
        lib.C_Login(session, CKU.USER)

        # Register a key
        key_handle = lib.register_key(session, "arn:aws:kms:...")

        # Sign
        lib.C_SignInit(session, CK_MECHANISM(CKM.ECDSA), key_handle)
        rv, signature = lib.C_Sign(session, digest)

        lib.C_Logout(session)
        lib.C_CloseSession(session)
        lib.C_Finalize()
    """

    # Library info
    MANUFACTURER_ID = "Crypto Broker"
    LIBRARY_DESCRIPTION = "PKCS#11 Broker for AWS KMS"
    CRYPTOKI_VERSION = CK_VERSION(2, 40)
    LIBRARY_VERSION = CK_VERSION(1, 0)

    def __init__(self, socket_path: Optional[str] = None):
        """
        Initialize PKCS#11 library.

        Args:
            socket_path: Path to broker socket (uses default if not specified)
        """
        self._socket_path = socket_path
        self._initialized = False
        self._transport: Optional[IPCTransport] = None

        # Slots (virtual HSM connections)
        self._slots: Dict[CK_SLOT_ID, Slot] = {}

    # =========================================================================
    # Library Management (C_Initialize, C_Finalize, C_GetInfo)
    # =========================================================================

    def C_Initialize(self, init_args=None) -> CKR:
        """
        C_Initialize - Initialize the PKCS#11 library.

        Args:
            init_args: Initialization arguments (not used)

        Returns:
            CKR return code
        """
        if self._initialized:
            return CKR.CRYPTOKI_ALREADY_INITIALIZED

        try:
            # Connect to broker
            self._transport = create_transport(self._socket_path)
            self._transport.connect()

            # Create default slot
            slot = Slot(
                slot_id=0,
                transport=self._transport,
                description="AWS KMS via Crypto Broker",
                manufacturer="Crypto Broker",
            )
            self._slots[0] = slot

            self._initialized = True
            logger.info("PKCS#11 library initialized")
            return CKR.OK

        except Exception as e:
            logger.error(f"C_Initialize failed: {e}")
            return CKR.FUNCTION_FAILED

    def C_Finalize(self, reserved=None) -> CKR:
        """
        C_Finalize - Finalize the PKCS#11 library.

        Args:
            reserved: Reserved (must be None)

        Returns:
            CKR return code
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED

        # Close all sessions
        for slot in self._slots.values():
            slot.close_all_sessions()

        # Disconnect from broker
        if self._transport:
            self._transport.disconnect()
            self._transport = None

        self._slots.clear()
        self._initialized = False

        logger.info("PKCS#11 library finalized")
        return CKR.OK

    def C_GetInfo(self) -> Tuple[CKR, CK_INFO]:
        """
        C_GetInfo - Get library information.

        Returns:
            Tuple of (CKR return code, CK_INFO structure)
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED, None

        info = CK_INFO(
            cryptoki_version=self.CRYPTOKI_VERSION,
            manufacturer_id=self.MANUFACTURER_ID[:32].ljust(32),
            flags=0,
            library_description=self.LIBRARY_DESCRIPTION[:32].ljust(32),
            library_version=self.LIBRARY_VERSION,
        )

        return CKR.OK, info

    # =========================================================================
    # Slot Management (C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, etc.)
    # =========================================================================

    def C_GetSlotList(self, token_present: bool = True) -> Tuple[CKR, List[CK_SLOT_ID]]:
        """
        C_GetSlotList - Get list of available slots.

        Args:
            token_present: If True, only return slots with tokens

        Returns:
            Tuple of (CKR return code, list of slot IDs)
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED, []

        slots = list(self._slots.keys())
        return CKR.OK, slots

    def C_GetSlotInfo(self, slot_id: CK_SLOT_ID) -> Tuple[CKR, CK_SLOT_INFO]:
        """
        C_GetSlotInfo - Get slot information.

        Args:
            slot_id: Slot ID

        Returns:
            Tuple of (CKR return code, CK_SLOT_INFO structure)
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED, None

        slot = self._slots.get(slot_id)
        if slot is None:
            return CKR.SLOT_ID_INVALID, None

        return CKR.OK, slot.get_info()

    def C_GetTokenInfo(self, slot_id: CK_SLOT_ID) -> Tuple[CKR, CK_TOKEN_INFO]:
        """
        C_GetTokenInfo - Get token information.

        Args:
            slot_id: Slot ID

        Returns:
            Tuple of (CKR return code, CK_TOKEN_INFO structure)
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED, None

        slot = self._slots.get(slot_id)
        if slot is None:
            return CKR.SLOT_ID_INVALID, None

        return CKR.OK, slot.get_token_info()

    def C_GetMechanismList(self, slot_id: CK_SLOT_ID) -> Tuple[CKR, List[int]]:
        """
        C_GetMechanismList - Get supported mechanisms.

        Args:
            slot_id: Slot ID

        Returns:
            Tuple of (CKR return code, list of mechanism types)
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED, []

        slot = self._slots.get(slot_id)
        if slot is None:
            return CKR.SLOT_ID_INVALID, []

        return CKR.OK, slot.get_mechanism_list()

    def C_GetMechanismInfo(
        self, slot_id: CK_SLOT_ID, mechanism: int
    ) -> Tuple[CKR, CK_MECHANISM_INFO]:
        """
        C_GetMechanismInfo - Get mechanism information.

        Args:
            slot_id: Slot ID
            mechanism: Mechanism type

        Returns:
            Tuple of (CKR return code, CK_MECHANISM_INFO structure)
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED, None

        slot = self._slots.get(slot_id)
        if slot is None:
            return CKR.SLOT_ID_INVALID, None

        try:
            info = slot.get_mechanism_info(mechanism)
            return CKR.OK, info
        except PKCS11Error as e:
            return e.rv, None

    # =========================================================================
    # Session Management (C_OpenSession, C_CloseSession, C_GetSessionInfo)
    # =========================================================================

    def C_OpenSession(
        self, slot_id: CK_SLOT_ID, flags: int
    ) -> Tuple[CKR, CK_SESSION_HANDLE]:
        """
        C_OpenSession - Open a session.

        Args:
            slot_id: Slot ID
            flags: Session flags

        Returns:
            Tuple of (CKR return code, session handle)
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED, 0

        slot = self._slots.get(slot_id)
        if slot is None:
            return CKR.SLOT_ID_INVALID, 0

        try:
            session = slot.open_session(flags)
            return CKR.OK, session.handle
        except PKCS11Error as e:
            return e.rv, 0

    def C_CloseSession(self, session: CK_SESSION_HANDLE) -> CKR:
        """
        C_CloseSession - Close a session.

        Args:
            session: Session handle

        Returns:
            CKR return code
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED

        for slot in self._slots.values():
            if slot.get_session(session):
                return slot.close_session(session)

        return CKR.SESSION_HANDLE_INVALID

    def C_CloseAllSessions(self, slot_id: CK_SLOT_ID) -> CKR:
        """
        C_CloseAllSessions - Close all sessions on a slot.

        Args:
            slot_id: Slot ID

        Returns:
            CKR return code
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED

        slot = self._slots.get(slot_id)
        if slot is None:
            return CKR.SLOT_ID_INVALID

        return slot.close_all_sessions()

    def C_GetSessionInfo(
        self, session: CK_SESSION_HANDLE
    ) -> Tuple[CKR, CK_SESSION_INFO]:
        """
        C_GetSessionInfo - Get session information.

        Args:
            session: Session handle

        Returns:
            Tuple of (CKR return code, CK_SESSION_INFO structure)
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED, None

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID, None

        return CKR.OK, sess.get_info()

    # =========================================================================
    # Login/Logout (C_Login, C_Logout)
    # =========================================================================

    def C_Login(
        self, session: CK_SESSION_HANDLE, user_type: int, pin: str = None
    ) -> CKR:
        """
        C_Login - Log into the token.

        Args:
            session: Session handle
            user_type: User type (CKU_USER, CKU_SO)
            pin: PIN (not used - broker uses OS authentication)

        Returns:
            CKR return code
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID

        return sess.C_Login(user_type, pin)

    def C_Logout(self, session: CK_SESSION_HANDLE) -> CKR:
        """
        C_Logout - Log out from the token.

        Args:
            session: Session handle

        Returns:
            CKR return code
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID

        return sess.C_Logout()

    # =========================================================================
    # Signing (C_SignInit, C_Sign, C_SignUpdate, C_SignFinal)
    # =========================================================================

    def C_SignInit(
        self, session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM, key: CK_OBJECT_HANDLE
    ) -> CKR:
        """
        C_SignInit - Initialize signing operation.

        Args:
            session: Session handle
            mechanism: Signing mechanism
            key: Private key handle

        Returns:
            CKR return code
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID

        return sess.C_SignInit(mechanism, key)

    def C_Sign(
        self, session: CK_SESSION_HANDLE, data: bytes
    ) -> Tuple[CKR, bytes]:
        """
        C_Sign - Sign data.

        Args:
            session: Session handle
            data: Data to sign

        Returns:
            Tuple of (CKR return code, signature)
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED, b""

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID, b""

        return sess.C_Sign(data)

    def C_SignUpdate(self, session: CK_SESSION_HANDLE, data: bytes) -> CKR:
        """C_SignUpdate - Continue multi-part signing."""
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID

        return sess.C_SignUpdate(data)

    def C_SignFinal(self, session: CK_SESSION_HANDLE) -> Tuple[CKR, bytes]:
        """C_SignFinal - Finish multi-part signing."""
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED, b""

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID, b""

        return sess.C_SignFinal()

    # =========================================================================
    # Verification (C_VerifyInit, C_Verify)
    # =========================================================================

    def C_VerifyInit(
        self, session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM, key: CK_OBJECT_HANDLE
    ) -> CKR:
        """C_VerifyInit - Initialize verification."""
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID

        return sess.C_VerifyInit(mechanism, key)

    def C_Verify(
        self, session: CK_SESSION_HANDLE, data: bytes, signature: bytes
    ) -> CKR:
        """C_Verify - Verify signature."""
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID

        return sess.C_Verify(data, signature)

    # =========================================================================
    # Digest (C_DigestInit, C_Digest)
    # =========================================================================

    def C_DigestInit(self, session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM) -> CKR:
        """C_DigestInit - Initialize digest."""
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID

        return sess.C_DigestInit(mechanism)

    def C_Digest(self, session: CK_SESSION_HANDLE, data: bytes) -> Tuple[CKR, bytes]:
        """C_Digest - Compute digest."""
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED, b""

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID, b""

        return sess.C_Digest(data)

    # =========================================================================
    # Object Management (C_GetAttributeValue, C_FindObjects)
    # =========================================================================

    def C_GetAttributeValue(
        self, session: CK_SESSION_HANDLE, obj: CK_OBJECT_HANDLE, template: List[CK_ATTRIBUTE]
    ) -> Tuple[CKR, List[CK_ATTRIBUTE]]:
        """C_GetAttributeValue - Get object attributes."""
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED, template

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID, template

        return sess.C_GetAttributeValue(obj, template)

    def C_FindObjectsInit(
        self, session: CK_SESSION_HANDLE, template: List[CK_ATTRIBUTE]
    ) -> CKR:
        """C_FindObjectsInit - Initialize object search."""
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID

        return sess.C_FindObjectsInit(template)

    def C_FindObjects(
        self, session: CK_SESSION_HANDLE, max_count: int
    ) -> Tuple[CKR, List[CK_OBJECT_HANDLE]]:
        """C_FindObjects - Find objects."""
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED, []

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID, []

        return sess.C_FindObjects(max_count)

    def C_FindObjectsFinal(self, session: CK_SESSION_HANDLE) -> CKR:
        """C_FindObjectsFinal - Finish object search."""
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID

        return sess.C_FindObjectsFinal()

    # =========================================================================
    # Key Generation (C_GenerateKeyPair)
    # =========================================================================

    def C_GenerateKeyPair(
        self,
        session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM,
        public_key_template: List[CK_ATTRIBUTE],
        private_key_template: List[CK_ATTRIBUTE],
    ) -> Tuple[CKR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE]:
        """
        C_GenerateKeyPair - Generate a public/private key pair.

        Args:
            session: Session handle
            mechanism: Key generation mechanism (e.g., CKM_EC_KEY_PAIR_GEN)
            public_key_template: Attributes for the public key
            private_key_template: Attributes for the private key

        Returns:
            Tuple of (CKR return code, public key handle, private key handle)
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED, 0, 0

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID, 0, 0

        return sess.C_GenerateKeyPair(mechanism, public_key_template, private_key_template)

    def get_generated_key_info(
        self, session: CK_SESSION_HANDLE, handle: CK_OBJECT_HANDLE
    ) -> Optional[Dict]:
        """
        Get information about a generated key.

        This is an extension to standard PKCS#11 for retrieving
        key metadata after generation.

        Args:
            session: Session handle
            handle: Key handle from C_GenerateKeyPair

        Returns:
            Dictionary with key info or None
        """
        if not self._initialized:
            return None

        sess = self._get_session(session)
        if sess is None:
            return None

        return sess.get_generated_key_info(handle)

    # =========================================================================
    # Key Registration (Extension)
    # =========================================================================

    def register_key(
        self, session: CK_SESSION_HANDLE, key_arn: str
    ) -> Tuple[CKR, CK_OBJECT_HANDLE]:
        """
        Register a KMS key and get a PKCS#11 object handle.

        This is an extension to standard PKCS#11 for working with
        AWS KMS keys that are identified by ARN.

        Args:
            session: Session handle
            key_arn: AWS KMS key ARN or ID

        Returns:
            Tuple of (CKR return code, object handle)
        """
        if not self._initialized:
            return CKR.CRYPTOKI_NOT_INITIALIZED, 0

        sess = self._get_session(session)
        if sess is None:
            return CKR.SESSION_HANDLE_INVALID, 0

        handle = sess.register_key(key_arn)
        return CKR.OK, handle

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _get_session(self, handle: CK_SESSION_HANDLE) -> Optional[Session]:
        """Get session by handle."""
        for slot in self._slots.values():
            sess = slot.get_session(handle)
            if sess:
                return sess
        return None

    # =========================================================================
    # Context Manager
    # =========================================================================

    def __enter__(self):
        """Context manager entry."""
        self.C_Initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.C_Finalize()
