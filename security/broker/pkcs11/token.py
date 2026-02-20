"""
PKCS#11 Token and Slot Implementation.

This module provides the Token and Slot classes that represent
a virtual HSM token backed by the crypto broker.
"""

from typing import List, Dict, Optional
import time

from .types import (
    CKR, CKF, CK_SLOT_ID, CK_SESSION_HANDLE,
    CK_SLOT_INFO, CK_TOKEN_INFO, CK_MECHANISM_INFO, CK_VERSION,
    CKM,
    PKCS11Error,
)
from .session import Session
from utils.logging import get_logger

logger = get_logger(__name__)


class Token:
    """
    PKCS#11 Token representing the crypto broker HSM.

    A token is the logical view of a cryptographic device (or in this
    case, the AWS KMS backend accessed through the broker).
    """

    def __init__(
        self,
        label: str = "AWS-KMS-BROKER",
        manufacturer: str = "Crypto Broker",
        model: str = "KMS-PKCS11",
        serial: str = "00000001",
    ):
        """
        Initialize token.

        Args:
            label: Token label (32 chars max)
            manufacturer: Manufacturer ID (32 chars max)
            model: Model name (16 chars max)
            serial: Serial number (16 chars max)
        """
        self._label = label[:32].ljust(32)
        self._manufacturer = manufacturer[:32].ljust(32)
        self._model = model[:16].ljust(16)
        self._serial = serial[:16].ljust(16)

        # Token capabilities
        self._flags = (
            CKF.TOKEN_INITIALIZED |
            CKF.LOGIN_REQUIRED |
            CKF.USER_PIN_INITIALIZED |
            CKF.PROTECTED_AUTHENTICATION_PATH  # No PIN required - uses OS auth
        )

    def get_info(self) -> CK_TOKEN_INFO:
        """
        Get token information.

        Returns:
            CK_TOKEN_INFO structure
        """
        return CK_TOKEN_INFO(
            label=self._label,
            manufacturer_id=self._manufacturer,
            model=self._model,
            serial_number=self._serial,
            flags=self._flags,
            max_session_count=256,
            session_count=0,  # Updated by slot
            max_rw_session_count=256,
            rw_session_count=0,
            max_pin_len=0,  # No PIN - uses OS auth
            min_pin_len=0,
            total_public_memory=0xFFFFFFFF,  # Unlimited (cloud)
            free_public_memory=0xFFFFFFFF,
            total_private_memory=0xFFFFFFFF,
            free_private_memory=0xFFFFFFFF,
            hardware_version=CK_VERSION(1, 0),
            firmware_version=CK_VERSION(1, 0),
            utc_time=time.strftime("%Y%m%d%H%M%S00"),
        )


class Slot:
    """
    PKCS#11 Slot representing a connection to the broker.

    A slot is a logical reader/connector. In our case, each slot
    represents a broker connection with an associated token.
    """

    def __init__(
        self,
        slot_id: CK_SLOT_ID,
        transport,
        description: str = "Crypto Broker Slot",
        manufacturer: str = "Crypto Broker",
    ):
        """
        Initialize slot.

        Args:
            slot_id: Slot identifier
            transport: Transport to broker daemon
            description: Slot description (64 chars max)
            manufacturer: Manufacturer ID (32 chars max)
        """
        self._slot_id = slot_id
        self._transport = transport
        self._description = description[:64].ljust(64)
        self._manufacturer = manufacturer[:32].ljust(32)

        # Token in this slot
        self._token = Token()

        # Sessions
        self._sessions: Dict[CK_SESSION_HANDLE, Session] = {}
        self._next_session_handle: CK_SESSION_HANDLE = 1

        # Slot flags
        self._flags = CKF.TOKEN_PRESENT | CKF.HW_SLOT  # Token present, hardware slot

    @property
    def slot_id(self) -> CK_SLOT_ID:
        """Get slot ID."""
        return self._slot_id

    @property
    def token(self) -> Token:
        """Get token in this slot."""
        return self._token

    def get_info(self) -> CK_SLOT_INFO:
        """
        C_GetSlotInfo - Get slot information.

        Returns:
            CK_SLOT_INFO structure
        """
        return CK_SLOT_INFO(
            slot_description=self._description,
            manufacturer_id=self._manufacturer,
            flags=self._flags,
            hardware_version=CK_VERSION(1, 0),
            firmware_version=CK_VERSION(1, 0),
        )

    def get_token_info(self) -> CK_TOKEN_INFO:
        """
        C_GetTokenInfo - Get token information.

        Returns:
            CK_TOKEN_INFO structure
        """
        info = self._token.get_info()
        info.session_count = len(self._sessions)
        info.rw_session_count = sum(
            1 for s in self._sessions.values()
            if s._flags & CKF.RW_SESSION
        )
        return info

    def get_mechanism_list(self) -> List[int]:
        """
        C_GetMechanismList - Get supported mechanisms.

        Returns:
            List of mechanism types
        """
        return [
            CKM.ECDSA,
            CKM.ECDSA_SHA256,
            CKM.ECDSA_SHA384,
            CKM.ECDSA_SHA512,
            CKM.SHA256,
            CKM.SHA384,
            CKM.SHA512,
            CKM.SHA_1,
        ]

    def get_mechanism_info(self, mechanism: int) -> CK_MECHANISM_INFO:
        """
        C_GetMechanismInfo - Get mechanism information.

        Args:
            mechanism: Mechanism type

        Returns:
            CK_MECHANISM_INFO structure
        """
        # ECDSA mechanisms
        if mechanism in [CKM.ECDSA, CKM.ECDSA_SHA256, CKM.ECDSA_SHA384, CKM.ECDSA_SHA512]:
            return CK_MECHANISM_INFO(
                min_key_size=256,
                max_key_size=521,
                flags=CKF.SIGN | CKF.VERIFY | CKF.EC_F_P | CKF.EC_NAMEDCURVE,
            )
        # Hash mechanisms
        elif mechanism in [CKM.SHA256, CKM.SHA384, CKM.SHA512, CKM.SHA_1]:
            return CK_MECHANISM_INFO(
                min_key_size=0,
                max_key_size=0,
                flags=CKF.DIGEST,
            )
        else:
            raise PKCS11Error(CKR.MECHANISM_INVALID)

    def open_session(self, flags: int) -> Session:
        """
        C_OpenSession - Open a session with the token.

        Args:
            flags: Session flags (CKF_SERIAL_SESSION required, CKF_RW_SESSION optional)

        Returns:
            New Session object

        Raises:
            PKCS11Error: If session cannot be opened
        """
        import json

        # CKF_SERIAL_SESSION is required
        if not (flags & CKF.SERIAL_SESSION):
            raise PKCS11Error(CKR.SESSION_PARALLEL_NOT_SUPPORTED)

        # Request a session from the broker
        try:
            request = {
                "jsonrpc": "2.0",
                "method": "open_session",
                "params": {},
                "id": self._next_session_handle,
            }
            self._transport.send(json.dumps(request).encode("utf-8"))
            response_data = self._transport.receive()
            response = json.loads(response_data.decode("utf-8"))

            if "error" in response:
                error = response["error"]
                logger.error(f"open_session failed: {error}")
                raise PKCS11Error(CKR.FUNCTION_FAILED)

            result = response.get("result", {})
            broker_session_id = result.get("session_id")

            if not broker_session_id:
                raise PKCS11Error(CKR.FUNCTION_FAILED)

        except PKCS11Error:
            raise
        except Exception as e:
            logger.error(f"Failed to open broker session: {e}")
            raise PKCS11Error(CKR.FUNCTION_FAILED)

        handle = self._next_session_handle
        self._next_session_handle += 1

        session = Session(
            handle=handle,
            slot_id=self._slot_id,
            flags=flags,
            broker_transport=self._transport,
            broker_session_id=broker_session_id,
        )

        self._sessions[handle] = session

        logger.debug(f"Opened session {handle} (broker: {broker_session_id}) on slot {self._slot_id}")
        return session

    def close_session(self, handle: CK_SESSION_HANDLE) -> CKR:
        """
        C_CloseSession - Close a session.

        Args:
            handle: Session handle

        Returns:
            CKR return code
        """
        if handle not in self._sessions:
            return CKR.SESSION_HANDLE_INVALID

        del self._sessions[handle]
        logger.debug(f"Closed session {handle}")
        return CKR.OK

    def close_all_sessions(self) -> CKR:
        """
        C_CloseAllSessions - Close all sessions on this slot.

        Returns:
            CKR return code
        """
        self._sessions.clear()
        logger.debug(f"Closed all sessions on slot {self._slot_id}")
        return CKR.OK

    def get_session(self, handle: CK_SESSION_HANDLE) -> Optional[Session]:
        """
        Get session by handle.

        Args:
            handle: Session handle

        Returns:
            Session or None
        """
        return self._sessions.get(handle)
