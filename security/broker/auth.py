"""
OS-level client authentication for the crypto broker.

This module provides platform-specific mechanisms to authenticate
client connections:
- Linux: SO_PEERCRED socket option for UID/GID/PID
- Windows: Named Pipe impersonation for SID lookup
"""

import os
import sys
import socket
from dataclasses import dataclass
from typing import Optional, Tuple

from utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ClientIdentity:
    """
    Authenticated client identity from OS-level credentials.

    Attributes:
        platform: Operating system ("linux" or "windows")
        uid: User ID (Linux) or None (Windows)
        gid: Group ID (Linux) or None (Windows)
        pid: Process ID
        sid: Security Identifier (Windows) or None (Linux)
        username: Resolved username (optional)
    """

    platform: str
    uid: Optional[int] = None
    gid: Optional[int] = None
    pid: Optional[int] = None
    sid: Optional[str] = None
    username: Optional[str] = None

    @property
    def client_id(self) -> str:
        """
        Get a unique client identifier string.

        Returns:
            Client ID based on platform credentials
        """
        if self.platform == "linux":
            return str(self.uid)
        elif self.platform == "windows":
            return self.sid or "unknown"
        return "unknown"

    def __str__(self) -> str:
        if self.platform == "linux":
            return f"Linux(uid={self.uid}, gid={self.gid}, pid={self.pid})"
        elif self.platform == "windows":
            return f"Windows(sid={self.sid}, pid={self.pid})"
        return f"Unknown({self.platform})"


def get_peer_credentials(conn: socket.socket) -> ClientIdentity:
    """
    Get peer credentials from a Unix domain socket.

    Uses SO_PEERCRED on Linux to retrieve the UID, GID, and PID
    of the connected client process.

    Args:
        conn: Connected Unix domain socket

    Returns:
        ClientIdentity with peer credentials

    Raises:
        OSError: If credentials cannot be retrieved
        NotImplementedError: If platform is not supported
    """
    if sys.platform.startswith("linux"):
        return _get_linux_peer_credentials(conn)
    elif sys.platform == "darwin":
        return _get_macos_peer_credentials(conn)
    else:
        raise NotImplementedError(
            f"Peer credentials not supported on platform: {sys.platform}"
        )


def _get_linux_peer_credentials(conn: socket.socket) -> ClientIdentity:
    """
    Get peer credentials on Linux using SO_PEERCRED.

    Args:
        conn: Connected Unix domain socket

    Returns:
        ClientIdentity with uid, gid, pid
    """
    import struct

    # SO_PEERCRED returns a struct with pid, uid, gid (each 4 bytes)
    SO_PEERCRED = 17  # From socket.h
    cred_data = conn.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", cred_data)

    # Try to resolve username
    username = None
    try:
        import pwd

        username = pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        pass

    logger.debug(f"Linux peer credentials: uid={uid}, gid={gid}, pid={pid}")

    return ClientIdentity(
        platform="linux",
        uid=uid,
        gid=gid,
        pid=pid,
        username=username,
    )


def _get_macos_peer_credentials(conn: socket.socket) -> ClientIdentity:
    """
    Get peer credentials on macOS using LOCAL_PEERCRED.

    Args:
        conn: Connected Unix domain socket

    Returns:
        ClientIdentity with uid, gid, pid
    """
    import struct

    # macOS uses LOCAL_PEERCRED (0x001) with SOL_LOCAL (0)
    # Returns struct xucred: version (4), uid (4), ngroups (2), groups[] (16*4)
    LOCAL_PEERCRED = 0x001
    SOL_LOCAL = 0

    # Also get LOCAL_PEERPID separately
    LOCAL_PEERPID = 0x002

    try:
        # Get UID via xucred structure
        cred_size = 4 + 4 + 2 + (16 * 4)  # xucred structure size
        cred_data = conn.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, cred_size)
        version, uid = struct.unpack("Ii", cred_data[:8])
        ngroups = struct.unpack("h", cred_data[8:10])[0]
        gid = struct.unpack("i", cred_data[10:14])[0] if ngroups > 0 else 0

        # Get PID
        pid_data = conn.getsockopt(SOL_LOCAL, LOCAL_PEERPID, 4)
        pid = struct.unpack("i", pid_data)[0]

    except (OSError, struct.error) as e:
        logger.warning(f"Failed to get macOS peer credentials: {e}")
        # Fallback: return current process credentials
        uid = os.getuid()
        gid = os.getgid()
        pid = 0

    # Try to resolve username
    username = None
    try:
        import pwd

        username = pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        pass

    logger.debug(f"macOS peer credentials: uid={uid}, gid={gid}, pid={pid}")

    return ClientIdentity(
        platform="linux",  # Use "linux" for Unix-like systems
        uid=uid,
        gid=gid,
        pid=pid,
        username=username,
    )


# Windows-specific authentication (loaded only on Windows)
if sys.platform == "win32":

    def get_named_pipe_client_identity(pipe_handle) -> ClientIdentity:
        """
        Get client identity from a Named Pipe connection on Windows.

        Uses ImpersonateNamedPipeClient to get the client's security context,
        then retrieves the SID.

        Args:
            pipe_handle: Win32 handle to the named pipe

        Returns:
            ClientIdentity with SID and username

        Raises:
            OSError: If impersonation or SID lookup fails
        """
        import ctypes
        from ctypes import wintypes

        # Use WinDLL with use_last_error=True to capture error codes properly
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        # Ensure pipe_handle is the right type
        if not isinstance(pipe_handle, int):
            pipe_handle = int(pipe_handle)

        # Impersonate the client
        # Set up function prototype
        advapi32.ImpersonateNamedPipeClient.argtypes = [wintypes.HANDLE]
        advapi32.ImpersonateNamedPipeClient.restype = wintypes.BOOL

        result = advapi32.ImpersonateNamedPipeClient(wintypes.HANDLE(pipe_handle))
        if not result:
            error = ctypes.get_last_error()
            raise OSError(f"ImpersonateNamedPipeClient failed: {error}")

        try:
            # Get the thread token
            TOKEN_QUERY = 0x0008
            token_handle = wintypes.HANDLE()

            # Set up function prototypes
            kernel32.GetCurrentThread.restype = wintypes.HANDLE
            advapi32.OpenThreadToken.argtypes = [
                wintypes.HANDLE,  # ThreadHandle
                wintypes.DWORD,   # DesiredAccess
                wintypes.BOOL,    # OpenAsSelf
                ctypes.POINTER(wintypes.HANDLE)  # TokenHandle
            ]
            advapi32.OpenThreadToken.restype = wintypes.BOOL

            current_thread = kernel32.GetCurrentThread()

            # OpenAsSelf=False: access check against impersonated token
            result = advapi32.OpenThreadToken(
                current_thread,
                TOKEN_QUERY,
                False,
                ctypes.byref(token_handle),
            )
            if not result:
                # Try with OpenAsSelf=True as fallback
                result = advapi32.OpenThreadToken(
                    current_thread,
                    TOKEN_QUERY,
                    True,
                    ctypes.byref(token_handle),
                )
                if not result:
                    error = ctypes.get_last_error()
                    raise OSError(f"OpenThreadToken failed: {error}")

            try:
                # Define TOKEN_USER structure properly
                class SID_AND_ATTRIBUTES(ctypes.Structure):
                    _fields_ = [
                        ("Sid", ctypes.c_void_p),
                        ("Attributes", wintypes.DWORD),
                    ]

                class TOKEN_USER(ctypes.Structure):
                    _fields_ = [
                        ("User", SID_AND_ATTRIBUTES),
                    ]

                # Get token information (TokenUser = 1)
                TokenUser = 1
                buffer_size = wintypes.DWORD(0)
                advapi32.GetTokenInformation(
                    token_handle, TokenUser, None, 0, ctypes.byref(buffer_size)
                )

                buffer = ctypes.create_string_buffer(buffer_size.value)
                result = advapi32.GetTokenInformation(
                    token_handle,
                    TokenUser,
                    buffer,
                    buffer_size,
                    ctypes.byref(buffer_size),
                )
                if not result:
                    error = ctypes.get_last_error()
                    raise OSError(f"GetTokenInformation failed: {error}")

                # Extract SID from TOKEN_USER structure
                token_user = ctypes.cast(buffer, ctypes.POINTER(TOKEN_USER)).contents
                psid = token_user.User.Sid

                # Convert SID to string - need to set up prototype
                advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
                advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

                sid_string = ctypes.c_wchar_p()
                result = advapi32.ConvertSidToStringSidW(
                    psid, ctypes.byref(sid_string)
                )
                if not result:
                    error = ctypes.get_last_error()
                    raise OSError(f"ConvertSidToStringSid failed: {error}")

                sid = sid_string.value
                ctypes.windll.kernel32.LocalFree(sid_string)

                # Get username from SID
                username = _lookup_username_from_sid(sid)

                # Get client process ID
                pid = _get_named_pipe_client_pid(pipe_handle)

                logger.debug(f"Windows peer credentials: sid={sid}, pid={pid}")

                return ClientIdentity(
                    platform="windows",
                    sid=sid,
                    pid=pid,
                    username=username,
                )

            finally:
                ctypes.windll.kernel32.CloseHandle(token_handle)

        finally:
            ctypes.windll.advapi32.RevertToSelf()

    def _lookup_username_from_sid(sid: str) -> Optional[str]:
        """
        Look up username from SID string on Windows.

        Args:
            sid: SID string (e.g., "S-1-5-21-...")

        Returns:
            Username or None if lookup fails
        """
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        # Convert string SID back to binary SID
        psid = ctypes.c_void_p()
        if not advapi32.ConvertStringSidToSidW(sid, ctypes.byref(psid)):
            return None

        try:
            # Lookup account name
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
                return f"{domain.value}\\{name.value}" if domain.value else name.value

        finally:
            kernel32.LocalFree(psid)

        return None

    def _get_named_pipe_client_pid(pipe_handle) -> Optional[int]:
        """
        Get the process ID of the named pipe client.

        Args:
            pipe_handle: Win32 handle to the named pipe

        Returns:
            Process ID or None if not available
        """
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        # Ensure pipe_handle is the right type
        if not isinstance(pipe_handle, int):
            pipe_handle = int(pipe_handle)

        # GetNamedPipeClientProcessId (Windows Vista+)
        client_pid = wintypes.ULONG()
        if kernel32.GetNamedPipeClientProcessId(
            wintypes.HANDLE(pipe_handle), ctypes.byref(client_pid)
        ):
            return client_pid.value

        return None
