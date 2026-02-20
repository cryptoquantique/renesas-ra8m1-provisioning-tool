"""
Windows Named Pipe security and ACL management.

This module provides secure Named Pipe creation with proper ACLs
for the crypto broker service.

Security model:
- SYSTEM: Full control (for service)
- Administrators: Full control
- Authenticated Users: Read/Write (for client access)
"""

import sys
from typing import Optional, Tuple

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes


# Named Pipe constants
PIPE_NAME = r"\\.\pipe\crypto_broker"
PIPE_BUFFER_SIZE = 65536
PIPE_TIMEOUT_MS = 30000  # 30 seconds

# Pipe access modes
PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_ACCESS_INBOUND = 0x00000001
PIPE_ACCESS_OUTBOUND = 0x00000002

# Pipe type/mode
PIPE_TYPE_BYTE = 0x00000000
PIPE_TYPE_MESSAGE = 0x00000004
PIPE_READMODE_BYTE = 0x00000000
PIPE_READMODE_MESSAGE = 0x00000002
PIPE_WAIT = 0x00000000
PIPE_NOWAIT = 0x00000001
PIPE_UNLIMITED_INSTANCES = 255

# Security constants
SECURITY_DESCRIPTOR_REVISION = 1

# Well-known SIDs
WinLocalSystemSid = 22
WinBuiltinAdministratorsSid = 26
WinAuthenticatedUserSid = 17
WinWorldSid = 1

# Access rights
GENERIC_ALL = 0x10000000
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000

# File access rights
FILE_GENERIC_READ = 0x00120089
FILE_GENERIC_WRITE = 0x00120116

# ACL revision
ACL_REVISION = 2

# Invalid handle
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value if sys.platform == "win32" else -1


def create_secure_named_pipe(
    pipe_name: str = PIPE_NAME,
    buffer_size: int = PIPE_BUFFER_SIZE,
    timeout_ms: int = PIPE_TIMEOUT_MS,
    allow_all_users: bool = True,
) -> Optional[int]:
    """
    Create a Named Pipe with secure ACL settings.

    Access control:
    - SYSTEM: Full control
    - Administrators: Full control
    - Authenticated Users: Read/Write (if allow_all_users=True)

    Args:
        pipe_name: Full pipe path (e.g., r"\\\\.\\pipe\\crypto_broker")
        buffer_size: Input/output buffer size
        timeout_ms: Default timeout in milliseconds
        allow_all_users: Allow authenticated users to connect

    Returns:
        Pipe handle on success, None on failure
    """
    if sys.platform != "win32":
        raise NotImplementedError("Named pipes only supported on Windows")

    kernel32 = ctypes.windll.kernel32
    advapi32 = ctypes.windll.advapi32

    # Create security descriptor
    sd = _create_security_descriptor(allow_all_users)
    if sd is None:
        return None

    try:
        # Create SECURITY_ATTRIBUTES structure
        class SECURITY_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("nLength", wintypes.DWORD),
                ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL),
            ]

        sa = SECURITY_ATTRIBUTES()
        sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
        sa.lpSecurityDescriptor = sd
        sa.bInheritHandle = False

        # Create the named pipe in BYTE mode
        # Note: We use byte mode (not message mode) because our protocol uses
        # length-prefixed framing. In message mode, writes are atomic and
        # ReadFile would fail with ERROR_MORE_DATA when trying to read
        # just the 4-byte length prefix.
        pipe_handle = kernel32.CreateNamedPipeW(
            pipe_name,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            buffer_size,
            buffer_size,
            timeout_ms,
            ctypes.byref(sa),
        )

        if pipe_handle == INVALID_HANDLE_VALUE:
            error = ctypes.get_last_error()
            _log_error(f"CreateNamedPipe failed (error {error})")
            return None

        return pipe_handle

    finally:
        # Free the security descriptor
        if sd:
            kernel32.LocalFree(sd)


def _create_security_descriptor(allow_all_users: bool = True) -> Optional[ctypes.c_void_p]:
    """
    Create a security descriptor with appropriate ACL.

    Args:
        allow_all_users: Include Authenticated Users in ACL

    Returns:
        Pointer to security descriptor, or None on failure
    """
    if sys.platform != "win32":
        return None

    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32

    # Build SDDL string for security descriptor
    # D: = DACL
    # (A;;GA;;;SY) = Allow GENERIC_ALL to SYSTEM
    # (A;;GA;;;BA) = Allow GENERIC_ALL to Built-in Administrators
    # (A;;GRGW;;;AU) = Allow GENERIC_READ|GENERIC_WRITE to Authenticated Users

    if allow_all_users:
        sddl = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"
    else:
        sddl = "D:(A;;GA;;;SY)(A;;GA;;;BA)"

    # Convert SDDL to security descriptor
    sd = ctypes.c_void_p()
    sd_size = wintypes.ULONG()

    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        SECURITY_DESCRIPTOR_REVISION,
        ctypes.byref(sd),
        ctypes.byref(sd_size),
    ):
        error = ctypes.get_last_error()
        _log_error(f"ConvertStringSecurityDescriptor failed (error {error})")
        return None

    return sd


def get_well_known_sid(sid_type: int) -> Optional[str]:
    """
    Get a well-known SID as a string.

    Args:
        sid_type: Well-known SID type constant

    Returns:
        SID string (e.g., "S-1-5-18") or None on failure
    """
    if sys.platform != "win32":
        return None

    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32

    # Allocate SID buffer (max 68 bytes)
    sid_buffer = ctypes.create_string_buffer(68)
    sid_size = wintypes.DWORD(68)

    if not advapi32.CreateWellKnownSid(
        sid_type,
        None,
        sid_buffer,
        ctypes.byref(sid_size),
    ):
        return None

    # Convert to string
    sid_string = ctypes.c_wchar_p()
    if not advapi32.ConvertSidToStringSidW(sid_buffer, ctypes.byref(sid_string)):
        return None

    result = sid_string.value
    kernel32.LocalFree(sid_string)
    return result


def verify_pipe_security(pipe_name: str = PIPE_NAME) -> dict:
    """
    Verify security settings on an existing named pipe.

    Args:
        pipe_name: Pipe name to check

    Returns:
        Dictionary with security information
    """
    result = {
        "pipe_name": pipe_name,
        "exists": False,
        "security": None,
        "error": None,
    }

    if sys.platform != "win32":
        result["error"] = "Only supported on Windows"
        return result

    kernel32 = ctypes.windll.kernel32
    advapi32 = ctypes.windll.advapi32

    # Try to open the pipe
    OPEN_EXISTING = 3
    READ_CONTROL = 0x00020000

    handle = kernel32.CreateFileW(
        pipe_name,
        READ_CONTROL,
        0,
        None,
        OPEN_EXISTING,
        0,
        None,
    )

    if handle == INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        if error == 2:  # ERROR_FILE_NOT_FOUND
            result["error"] = "Pipe not found"
        else:
            result["error"] = f"Cannot open pipe (error {error})"
        return result

    result["exists"] = True

    try:
        # Get security descriptor
        OWNER_SECURITY_INFORMATION = 0x00000001
        GROUP_SECURITY_INFORMATION = 0x00000002
        DACL_SECURITY_INFORMATION = 0x00000004
        security_info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION

        sd_size = wintypes.DWORD(0)
        advapi32.GetKernelObjectSecurity(handle, security_info, None, 0, ctypes.byref(sd_size))

        sd_buffer = ctypes.create_string_buffer(sd_size.value)
        if advapi32.GetKernelObjectSecurity(
            handle, security_info, sd_buffer, sd_size, ctypes.byref(sd_size)
        ):
            # Convert to SDDL string
            sddl_string = ctypes.c_wchar_p()
            if advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd_buffer,
                SECURITY_DESCRIPTOR_REVISION,
                security_info,
                ctypes.byref(sddl_string),
                None,
            ):
                result["security"] = sddl_string.value
                kernel32.LocalFree(sddl_string)

    finally:
        kernel32.CloseHandle(handle)

    return result


def _log_error(message: str):
    """Log an error message."""
    try:
        from utils.logging import get_logger
        logger = get_logger(__name__)
        logger.error(message)
    except Exception:
        print(f"ERROR: {message}")


# Well-known SID constants for reference
WELL_KNOWN_SIDS = {
    "SYSTEM": "S-1-5-18",
    "LOCAL_SERVICE": "S-1-5-19",
    "NETWORK_SERVICE": "S-1-5-20",
    "ADMINISTRATORS": "S-1-5-32-544",
    "USERS": "S-1-5-32-545",
    "GUESTS": "S-1-5-32-546",
    "POWER_USERS": "S-1-5-32-547",
    "AUTHENTICATED_USERS": "S-1-5-11",
    "EVERYONE": "S-1-1-0",
}


def lookup_sid_name(sid: str) -> Optional[str]:
    """
    Look up the account name for a SID.

    Args:
        sid: SID string (e.g., "S-1-5-18")

    Returns:
        Account name (e.g., "NT AUTHORITY\\SYSTEM") or None
    """
    if sys.platform != "win32":
        return None

    # Check well-known SIDs first
    for name, known_sid in WELL_KNOWN_SIDS.items():
        if sid == known_sid:
            return name

    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32

    # Convert string SID to binary
    psid = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(sid, ctypes.byref(psid)):
        return None

    try:
        # Look up account name
        name_size = wintypes.DWORD(256)
        domain_size = wintypes.DWORD(256)
        name = ctypes.create_unicode_buffer(256)
        domain = ctypes.create_unicode_buffer(256)
        sid_type = wintypes.DWORD()

        if advapi32.LookupAccountSidW(
            None,
            psid,
            name,
            ctypes.byref(name_size),
            domain,
            ctypes.byref(domain_size),
            ctypes.byref(sid_type),
        ):
            if domain.value:
                return f"{domain.value}\\{name.value}"
            return name.value

    finally:
        kernel32.LocalFree(psid)

    return None
