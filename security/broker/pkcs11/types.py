"""
PKCS#11 Type Definitions (v2.40 OASIS Standard).

This module defines the standard PKCS#11 types, constants, return codes,
mechanisms, and attribute types used throughout the PKCS#11 interface.
"""

from enum import IntEnum, IntFlag
from typing import Any, Dict, List, Optional, NamedTuple
from dataclasses import dataclass


# =============================================================================
# Basic Types (CK_* primitive types)
# =============================================================================

CK_BYTE = int
CK_ULONG = int
CK_LONG = int
CK_BBOOL = bool
CK_UTF8CHAR = str
CK_VOID_PTR = Any
CK_FLAGS = int

CK_TRUE = True
CK_FALSE = False

# Handles
CK_SLOT_ID = int
CK_SESSION_HANDLE = int
CK_OBJECT_HANDLE = int
CK_MECHANISM_TYPE = int

# Invalid handle constant
CK_INVALID_HANDLE = 0


# =============================================================================
# Return Values (CKR_*)
# =============================================================================

class CKR(IntEnum):
    """PKCS#11 Return Values."""
    OK = 0x00000000
    CANCEL = 0x00000001
    HOST_MEMORY = 0x00000002
    SLOT_ID_INVALID = 0x00000003
    GENERAL_ERROR = 0x00000005
    FUNCTION_FAILED = 0x00000006
    ARGUMENTS_BAD = 0x00000007
    NO_EVENT = 0x00000008
    NEED_TO_CREATE_THREADS = 0x00000009
    CANT_LOCK = 0x0000000A
    ATTRIBUTE_READ_ONLY = 0x00000010
    ATTRIBUTE_SENSITIVE = 0x00000011
    ATTRIBUTE_TYPE_INVALID = 0x00000012
    ATTRIBUTE_VALUE_INVALID = 0x00000013
    ACTION_PROHIBITED = 0x0000001B
    DATA_INVALID = 0x00000020
    DATA_LEN_RANGE = 0x00000021
    DEVICE_ERROR = 0x00000030
    DEVICE_MEMORY = 0x00000031
    DEVICE_REMOVED = 0x00000032
    ENCRYPTED_DATA_INVALID = 0x00000040
    ENCRYPTED_DATA_LEN_RANGE = 0x00000041
    FUNCTION_CANCELED = 0x00000050
    FUNCTION_NOT_PARALLEL = 0x00000051
    FUNCTION_NOT_SUPPORTED = 0x00000054
    KEY_HANDLE_INVALID = 0x00000060
    KEY_SIZE_RANGE = 0x00000062
    KEY_TYPE_INCONSISTENT = 0x00000063
    KEY_NOT_NEEDED = 0x00000064
    KEY_CHANGED = 0x00000065
    KEY_NEEDED = 0x00000066
    KEY_INDIGESTIBLE = 0x00000067
    KEY_FUNCTION_NOT_PERMITTED = 0x00000068
    KEY_NOT_WRAPPABLE = 0x00000069
    KEY_UNEXTRACTABLE = 0x0000006A
    MECHANISM_INVALID = 0x00000070
    MECHANISM_PARAM_INVALID = 0x00000071
    OBJECT_HANDLE_INVALID = 0x00000082
    OPERATION_ACTIVE = 0x00000090
    OPERATION_NOT_INITIALIZED = 0x00000091
    PIN_INCORRECT = 0x000000A0
    PIN_INVALID = 0x000000A1
    PIN_LEN_RANGE = 0x000000A2
    PIN_EXPIRED = 0x000000A3
    PIN_LOCKED = 0x000000A4
    SESSION_CLOSED = 0x000000B0
    SESSION_COUNT = 0x000000B1
    SESSION_HANDLE_INVALID = 0x000000B3
    SESSION_PARALLEL_NOT_SUPPORTED = 0x000000B4
    SESSION_READ_ONLY = 0x000000B5
    SESSION_EXISTS = 0x000000B6
    SESSION_READ_ONLY_EXISTS = 0x000000B7
    SESSION_READ_WRITE_SO_EXISTS = 0x000000B8
    SIGNATURE_INVALID = 0x000000C0
    SIGNATURE_LEN_RANGE = 0x000000C1
    TEMPLATE_INCOMPLETE = 0x000000D0
    TEMPLATE_INCONSISTENT = 0x000000D1
    TOKEN_NOT_PRESENT = 0x000000E0
    TOKEN_NOT_RECOGNIZED = 0x000000E1
    TOKEN_WRITE_PROTECTED = 0x000000E2
    UNWRAPPING_KEY_HANDLE_INVALID = 0x000000F0
    UNWRAPPING_KEY_SIZE_RANGE = 0x000000F1
    UNWRAPPING_KEY_TYPE_INCONSISTENT = 0x000000F2
    USER_ALREADY_LOGGED_IN = 0x00000100
    USER_NOT_LOGGED_IN = 0x00000101
    USER_PIN_NOT_INITIALIZED = 0x00000102
    USER_TYPE_INVALID = 0x00000103
    USER_ANOTHER_ALREADY_LOGGED_IN = 0x00000104
    USER_TOO_MANY_TYPES = 0x00000105
    WRAPPED_KEY_INVALID = 0x00000110
    WRAPPED_KEY_LEN_RANGE = 0x00000112
    WRAPPING_KEY_HANDLE_INVALID = 0x00000113
    WRAPPING_KEY_SIZE_RANGE = 0x00000114
    WRAPPING_KEY_TYPE_INCONSISTENT = 0x00000115
    RANDOM_SEED_NOT_SUPPORTED = 0x00000120
    RANDOM_NO_RNG = 0x00000121
    DOMAIN_PARAMS_INVALID = 0x00000130
    CURVE_NOT_SUPPORTED = 0x00000140
    BUFFER_TOO_SMALL = 0x00000150
    SAVED_STATE_INVALID = 0x00000160
    INFORMATION_SENSITIVE = 0x00000170
    STATE_UNSAVEABLE = 0x00000180
    CRYPTOKI_NOT_INITIALIZED = 0x00000190
    CRYPTOKI_ALREADY_INITIALIZED = 0x00000191
    MUTEX_BAD = 0x000001A0
    MUTEX_NOT_LOCKED = 0x000001A1
    NEW_PIN_MODE = 0x000001B0
    NEXT_OTP = 0x000001B1
    EXCEEDED_MAX_ITERATIONS = 0x000001B5
    FIPS_SELF_TEST_FAILED = 0x000001B6
    LIBRARY_LOAD_FAILED = 0x000001B7
    PIN_TOO_WEAK = 0x000001B8
    PUBLIC_KEY_INVALID = 0x000001B9
    FUNCTION_REJECTED = 0x00000200
    VENDOR_DEFINED = 0x80000000


# =============================================================================
# Mechanism Types (CKM_*)
# =============================================================================

class CKM(IntEnum):
    """PKCS#11 Mechanism Types."""
    RSA_PKCS_KEY_PAIR_GEN = 0x00000000
    RSA_PKCS = 0x00000001
    RSA_9796 = 0x00000002
    RSA_X_509 = 0x00000003
    MD2_RSA_PKCS = 0x00000004
    MD5_RSA_PKCS = 0x00000005
    SHA1_RSA_PKCS = 0x00000006
    SHA256_RSA_PKCS = 0x00000040
    SHA384_RSA_PKCS = 0x00000041
    SHA512_RSA_PKCS = 0x00000042
    SHA256_RSA_PKCS_PSS = 0x00000043
    SHA384_RSA_PKCS_PSS = 0x00000044
    SHA512_RSA_PKCS_PSS = 0x00000045

    # DSA mechanisms
    DSA_KEY_PAIR_GEN = 0x00000010
    DSA = 0x00000011
    DSA_SHA1 = 0x00000012
    DSA_SHA224 = 0x00000013
    DSA_SHA256 = 0x00000014
    DSA_SHA384 = 0x00000015
    DSA_SHA512 = 0x00000016

    # ECDSA mechanisms
    EC_KEY_PAIR_GEN = 0x00001040
    ECDSA = 0x00001041
    ECDSA_SHA1 = 0x00001042
    ECDSA_SHA224 = 0x00001043
    ECDSA_SHA256 = 0x00001044
    ECDSA_SHA384 = 0x00001045
    ECDSA_SHA512 = 0x00001046

    # ECDH mechanisms
    ECDH1_DERIVE = 0x00001050
    ECDH1_COFACTOR_DERIVE = 0x00001051

    # Hash mechanisms
    MD5 = 0x00000210
    SHA_1 = 0x00000220
    SHA256 = 0x00000250
    SHA384 = 0x00000260
    SHA512 = 0x00000270
    SHA224 = 0x00000255

    # Vendor defined
    VENDOR_DEFINED = 0x80000000


# =============================================================================
# Object Classes (CKO_*)
# =============================================================================

class CKO(IntEnum):
    """PKCS#11 Object Classes."""
    DATA = 0x00000000
    CERTIFICATE = 0x00000001
    PUBLIC_KEY = 0x00000002
    PRIVATE_KEY = 0x00000003
    SECRET_KEY = 0x00000004
    HW_FEATURE = 0x00000005
    DOMAIN_PARAMETERS = 0x00000006
    MECHANISM = 0x00000007
    OTP_KEY = 0x00000008
    VENDOR_DEFINED = 0x80000000


# =============================================================================
# Key Types (CKK_*)
# =============================================================================

class CKK(IntEnum):
    """PKCS#11 Key Types."""
    RSA = 0x00000000
    DSA = 0x00000001
    DH = 0x00000002
    ECDSA = 0x00000003  # Deprecated, use EC
    EC = 0x00000003
    X9_42_DH = 0x00000004
    KEA = 0x00000005
    GENERIC_SECRET = 0x00000010
    RC2 = 0x00000011
    RC4 = 0x00000012
    DES = 0x00000013
    DES2 = 0x00000014
    DES3 = 0x00000015
    AES = 0x0000001F
    SHA256_HMAC = 0x0000002B
    SHA384_HMAC = 0x0000002C
    SHA512_HMAC = 0x0000002D
    VENDOR_DEFINED = 0x80000000


# =============================================================================
# Attribute Types (CKA_*)
# =============================================================================

class CKA(IntEnum):
    """PKCS#11 Attribute Types."""
    CLASS = 0x00000000
    TOKEN = 0x00000001
    PRIVATE = 0x00000002
    LABEL = 0x00000003
    APPLICATION = 0x00000010
    VALUE = 0x00000011
    OBJECT_ID = 0x00000012
    CERTIFICATE_TYPE = 0x00000080
    ISSUER = 0x00000081
    SERIAL_NUMBER = 0x00000082
    AC_ISSUER = 0x00000083
    OWNER = 0x00000084
    ATTR_TYPES = 0x00000085
    TRUSTED = 0x00000086
    CERTIFICATE_CATEGORY = 0x00000087
    JAVA_MIDP_SECURITY_DOMAIN = 0x00000088
    URL = 0x00000089
    HASH_OF_SUBJECT_PUBLIC_KEY = 0x0000008A
    HASH_OF_ISSUER_PUBLIC_KEY = 0x0000008B
    CHECK_VALUE = 0x00000090
    KEY_TYPE = 0x00000100
    SUBJECT = 0x00000101
    ID = 0x00000102
    SENSITIVE = 0x00000103
    ENCRYPT = 0x00000104
    DECRYPT = 0x00000105
    WRAP = 0x00000106
    UNWRAP = 0x00000107
    SIGN = 0x00000108
    SIGN_RECOVER = 0x00000109
    VERIFY = 0x0000010A
    VERIFY_RECOVER = 0x0000010B
    DERIVE = 0x0000010C
    START_DATE = 0x00000110
    END_DATE = 0x00000111
    MODULUS = 0x00000120
    MODULUS_BITS = 0x00000121
    PUBLIC_EXPONENT = 0x00000122
    PRIVATE_EXPONENT = 0x00000123
    PRIME_1 = 0x00000124
    PRIME_2 = 0x00000125
    EXPONENT_1 = 0x00000126
    EXPONENT_2 = 0x00000127
    COEFFICIENT = 0x00000128
    PUBLIC_KEY_INFO = 0x00000129
    PRIME = 0x00000130
    SUBPRIME = 0x00000131
    BASE = 0x00000132
    PRIME_BITS = 0x00000133
    SUBPRIME_BITS = 0x00000134
    VALUE_BITS = 0x00000160
    VALUE_LEN = 0x00000161
    EXTRACTABLE = 0x00000162
    LOCAL = 0x00000163
    NEVER_EXTRACTABLE = 0x00000164
    ALWAYS_SENSITIVE = 0x00000165
    KEY_GEN_MECHANISM = 0x00000166
    MODIFIABLE = 0x00000170
    COPYABLE = 0x00000171
    DESTROYABLE = 0x00000172
    EC_PARAMS = 0x00000180
    EC_POINT = 0x00000181
    ALWAYS_AUTHENTICATE = 0x00000202
    WRAP_WITH_TRUSTED = 0x00000210
    WRAP_TEMPLATE = 0x40000211
    UNWRAP_TEMPLATE = 0x40000212
    ALLOWED_MECHANISMS = 0x40000600
    VENDOR_DEFINED = 0x80000000


# =============================================================================
# User Types (CKU_*)
# =============================================================================

class CKU(IntEnum):
    """PKCS#11 User Types."""
    SO = 0  # Security Officer
    USER = 1
    CONTEXT_SPECIFIC = 2


# =============================================================================
# Session State (CKS_*)
# =============================================================================

class CKS(IntEnum):
    """PKCS#11 Session States."""
    RO_PUBLIC_SESSION = 0
    RO_USER_FUNCTIONS = 1
    RW_PUBLIC_SESSION = 2
    RW_USER_FUNCTIONS = 3
    RW_SO_FUNCTIONS = 4


# =============================================================================
# Session Flags (CKF_*)
# =============================================================================

class CKF(IntFlag):
    """PKCS#11 Flags."""
    # Slot flags (CKF_* for C_GetSlotInfo)
    TOKEN_PRESENT = 0x00000001
    REMOVABLE_DEVICE = 0x00000002
    HW_SLOT = 0x00000004

    # Token flags (CKF_* for C_GetTokenInfo)
    RNG = 0x00000001
    WRITE_PROTECTED = 0x00000002
    LOGIN_REQUIRED = 0x00000004
    USER_PIN_INITIALIZED = 0x00000008
    RESTORE_KEY_NOT_NEEDED = 0x00000020
    CLOCK_ON_TOKEN = 0x00000040
    PROTECTED_AUTHENTICATION_PATH = 0x00000100
    DUAL_CRYPTO_OPERATIONS = 0x00000200
    TOKEN_INITIALIZED = 0x00000400
    SECONDARY_AUTHENTICATION = 0x00000800
    USER_PIN_COUNT_LOW = 0x00010000
    USER_PIN_FINAL_TRY = 0x00020000
    USER_PIN_LOCKED = 0x00040000
    USER_PIN_TO_BE_CHANGED = 0x00080000
    SO_PIN_COUNT_LOW = 0x00100000
    SO_PIN_FINAL_TRY = 0x00200000
    SO_PIN_LOCKED = 0x00400000
    SO_PIN_TO_BE_CHANGED = 0x00800000
    ERROR_STATE = 0x01000000

    # Session flags
    RW_SESSION = 0x00000002
    SERIAL_SESSION = 0x00000004

    # Mechanism flags
    HW = 0x00000001
    ENCRYPT = 0x00000100
    DECRYPT = 0x00000200
    DIGEST = 0x00000400
    SIGN = 0x00000800
    SIGN_RECOVER = 0x00001000
    VERIFY = 0x00002000
    VERIFY_RECOVER = 0x00004000
    GENERATE = 0x00008000
    GENERATE_KEY_PAIR = 0x00010000
    WRAP = 0x00020000
    UNWRAP = 0x00040000
    DERIVE = 0x00080000
    EC_F_P = 0x00100000
    EC_F_2M = 0x00200000
    EC_ECPARAMETERS = 0x00400000
    EC_NAMEDCURVE = 0x00800000
    EC_UNCOMPRESS = 0x01000000
    EC_COMPRESS = 0x02000000


# =============================================================================
# Structures
# =============================================================================

@dataclass
class CK_VERSION:
    """PKCS#11 Version structure."""
    major: int = 0
    minor: int = 0


@dataclass
class CK_INFO:
    """PKCS#11 Library Info structure."""
    cryptoki_version: CK_VERSION = None
    manufacturer_id: str = ""
    flags: int = 0
    library_description: str = ""
    library_version: CK_VERSION = None

    def __post_init__(self):
        if self.cryptoki_version is None:
            self.cryptoki_version = CK_VERSION(2, 40)
        if self.library_version is None:
            self.library_version = CK_VERSION(1, 0)


@dataclass
class CK_SLOT_INFO:
    """PKCS#11 Slot Info structure."""
    slot_description: str = ""
    manufacturer_id: str = ""
    flags: int = 0
    hardware_version: CK_VERSION = None
    firmware_version: CK_VERSION = None

    def __post_init__(self):
        if self.hardware_version is None:
            self.hardware_version = CK_VERSION(1, 0)
        if self.firmware_version is None:
            self.firmware_version = CK_VERSION(1, 0)


@dataclass
class CK_TOKEN_INFO:
    """PKCS#11 Token Info structure."""
    label: str = ""
    manufacturer_id: str = ""
    model: str = ""
    serial_number: str = ""
    flags: int = 0
    max_session_count: int = 0
    session_count: int = 0
    max_rw_session_count: int = 0
    rw_session_count: int = 0
    max_pin_len: int = 0
    min_pin_len: int = 0
    total_public_memory: int = 0
    free_public_memory: int = 0
    total_private_memory: int = 0
    free_private_memory: int = 0
    hardware_version: CK_VERSION = None
    firmware_version: CK_VERSION = None
    utc_time: str = ""

    def __post_init__(self):
        if self.hardware_version is None:
            self.hardware_version = CK_VERSION(1, 0)
        if self.firmware_version is None:
            self.firmware_version = CK_VERSION(1, 0)


@dataclass
class CK_SESSION_INFO:
    """PKCS#11 Session Info structure."""
    slot_id: int = 0
    state: int = CKS.RO_PUBLIC_SESSION
    flags: int = CKF.SERIAL_SESSION
    device_error: int = 0


@dataclass
class CK_MECHANISM:
    """PKCS#11 Mechanism structure."""
    mechanism: int = 0
    parameter: bytes = None
    parameter_len: int = 0

    def __post_init__(self):
        if self.parameter is None:
            self.parameter = b""
        self.parameter_len = len(self.parameter)


@dataclass
class CK_MECHANISM_INFO:
    """PKCS#11 Mechanism Info structure."""
    min_key_size: int = 0
    max_key_size: int = 0
    flags: int = 0


@dataclass
class CK_ATTRIBUTE:
    """PKCS#11 Attribute structure."""
    type: int = 0
    value: Any = None
    value_len: int = 0


# =============================================================================
# Exception Classes
# =============================================================================

class PKCS11Error(Exception):
    """Base PKCS#11 exception."""

    def __init__(self, rv: CKR, message: str = None):
        self.rv = rv
        self.message = message or f"PKCS#11 error: {rv.name} (0x{rv:08X})"
        super().__init__(self.message)


class PKCS11FunctionFailed(PKCS11Error):
    """C function returned CKR_FUNCTION_FAILED."""
    def __init__(self, message: str = None):
        super().__init__(CKR.FUNCTION_FAILED, message)


class PKCS11SessionHandleInvalid(PKCS11Error):
    """Invalid session handle."""
    def __init__(self, message: str = None):
        super().__init__(CKR.SESSION_HANDLE_INVALID, message)


class PKCS11KeyHandleInvalid(PKCS11Error):
    """Invalid key handle."""
    def __init__(self, message: str = None):
        super().__init__(CKR.KEY_HANDLE_INVALID, message)


class PKCS11UserNotLoggedIn(PKCS11Error):
    """User not logged in."""
    def __init__(self, message: str = None):
        super().__init__(CKR.USER_NOT_LOGGED_IN, message)


class PKCS11MechanismInvalid(PKCS11Error):
    """Invalid mechanism."""
    def __init__(self, message: str = None):
        super().__init__(CKR.MECHANISM_INVALID, message)
