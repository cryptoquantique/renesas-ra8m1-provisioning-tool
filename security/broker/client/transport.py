"""
IPC transport abstraction for the crypto broker client.

This module provides platform-specific transport implementations
for communicating with the broker daemon:
- Unix sockets (Linux, macOS)
- Named Pipes (Windows)
"""

import socket
import struct
import sys
from abc import ABC, abstractmethod
from typing import Optional

from security.broker.protocol import read_message, write_message
from security.broker.exceptions import ConnectionError as BrokerConnectionError
from utils.logging import get_logger

logger = get_logger(__name__)


class IPCTransport(ABC):
    """
    Abstract base class for IPC transport.

    Provides a common interface for communication with
    the broker daemon across different platforms.
    """

    @abstractmethod
    def connect(self) -> None:
        """
        Establish connection to broker.

        Raises:
            BrokerConnectionError: If connection fails
        """
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Close connection to broker."""
        pass

    @abstractmethod
    def send(self, data: bytes) -> None:
        """
        Send data to broker.

        Args:
            data: Bytes to send

        Raises:
            BrokerConnectionError: If send fails
        """
        pass

    @abstractmethod
    def receive(self) -> bytes:
        """
        Receive data from broker.

        Returns:
            Received bytes

        Raises:
            BrokerConnectionError: If receive fails
        """
        pass

    @property
    @abstractmethod
    def is_connected(self) -> bool:
        """Check if transport is connected."""
        pass

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()


class UnixSocketTransport(IPCTransport):
    """
    Unix domain socket transport for Linux/macOS.

    Connects to the broker via a Unix domain socket at
    the specified path.
    """

    def __init__(
        self,
        socket_path: str,
        timeout: float = 30.0,
    ):
        """
        Initialize Unix socket transport.

        Args:
            socket_path: Path to Unix domain socket
            timeout: Socket timeout in seconds
        """
        self.socket_path = socket_path
        self.timeout = timeout
        self._socket: Optional[socket.socket] = None

    def connect(self) -> None:
        """Connect to broker via Unix socket."""
        if self._socket is not None:
            return

        try:
            self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._socket.settimeout(self.timeout)
            self._socket.connect(self.socket_path)
            logger.debug(f"Connected to broker at {self.socket_path}")

        except FileNotFoundError:
            self._socket = None
            raise BrokerConnectionError(
                f"Broker socket not found: {self.socket_path}. "
                "Is the broker daemon running?"
            )
        except PermissionError:
            self._socket = None
            raise BrokerConnectionError(
                f"Permission denied connecting to: {self.socket_path}"
            )
        except Exception as e:
            self._socket = None
            raise BrokerConnectionError(f"Failed to connect: {e}") from e

    def disconnect(self) -> None:
        """Disconnect from broker."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
            logger.debug("Disconnected from broker")

    def send(self, data: bytes) -> None:
        """Send data to broker."""
        if not self._socket:
            raise BrokerConnectionError("Not connected")

        try:
            write_message(self._socket, data)
        except Exception as e:
            raise BrokerConnectionError(f"Send failed: {e}") from e

    def receive(self) -> bytes:
        """Receive data from broker."""
        if not self._socket:
            raise BrokerConnectionError("Not connected")

        try:
            return read_message(self._socket)
        except Exception as e:
            raise BrokerConnectionError(f"Receive failed: {e}") from e

    @property
    def is_connected(self) -> bool:
        """Check if connected."""
        return self._socket is not None


# Windows Named Pipe transport (conditionally loaded)
if sys.platform == "win32":

    class NamedPipeTransport(IPCTransport):
        """
        Named Pipe transport for Windows.

        Connects to the broker via a Named Pipe at
        the specified path (e.g., r"\\.\\pipe\\crypto_broker").
        """

        def __init__(
            self,
            pipe_name: str,
            timeout: int = 30000,  # milliseconds
        ):
            """
            Initialize Named Pipe transport.

            Args:
                pipe_name: Named Pipe path (e.g., r"\\.\\pipe\\crypto_broker")
                timeout: Timeout in milliseconds
            """
            self.pipe_name = pipe_name
            self.timeout = timeout
            self._handle = None

        def connect(self) -> None:
            """Connect to broker via Named Pipe."""
            if self._handle is not None:
                return

            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

            GENERIC_READ = 0x80000000
            GENERIC_WRITE = 0x40000000
            OPEN_EXISTING = 3

            # Security flags for impersonation (required for server to authenticate client)
            SECURITY_SQOS_PRESENT = 0x00100000
            SECURITY_IMPERSONATION = 0x00020000

            # Set up function prototypes for proper handle handling
            kernel32.CreateFileW.restype = wintypes.HANDLE

            # Try to connect to pipe with impersonation allowed
            handle = kernel32.CreateFileW(
                self.pipe_name,
                GENERIC_READ | GENERIC_WRITE,
                0,  # No sharing
                None,  # Default security
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,  # Allow server to impersonate
                None,  # No template
            )

            # Check for invalid handle (-1 or 0xFFFFFFFF... depending on 32/64 bit)
            if handle is None or handle == wintypes.HANDLE(-1).value or handle == -1:
                error = ctypes.get_last_error()
                if error == 2:  # ERROR_FILE_NOT_FOUND
                    raise BrokerConnectionError(
                        f"Broker pipe not found: {self.pipe_name}. "
                        "Is the broker daemon running?"
                    )
                elif error == 5:  # ERROR_ACCESS_DENIED
                    raise BrokerConnectionError(
                        f"Permission denied connecting to: {self.pipe_name}"
                    )
                else:
                    raise BrokerConnectionError(
                        f"Failed to connect to pipe (error {error})"
                    )

            self._handle = handle
            # Pipe is in byte mode by default, matching server configuration
            # (length-prefixed framing works correctly in byte mode)

            logger.debug(f"Connected to broker at {self.pipe_name}")

        def disconnect(self) -> None:
            """Disconnect from broker."""
            if self._handle:
                import ctypes
                from ctypes import wintypes

                kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                kernel32.CloseHandle(self._handle)
                self._handle = None
                logger.debug("Disconnected from broker")

        def send(self, data: bytes) -> None:
            """Send data to broker."""
            if not self._handle:
                raise BrokerConnectionError("Not connected")

            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

            # Prepend length prefix
            length_prefix = struct.pack(">I", len(data))
            message = length_prefix + data

            bytes_written = wintypes.DWORD()
            success = kernel32.WriteFile(
                self._handle,
                message,
                len(message),
                ctypes.byref(bytes_written),
                None,
            )

            if not success:
                error = ctypes.get_last_error()
                raise BrokerConnectionError(f"Send failed (error {error})")

        def receive(self) -> bytes:
            """Receive data from broker."""
            if not self._handle:
                raise BrokerConnectionError("Not connected")

            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

            # Read length prefix (4 bytes)
            length_buffer = ctypes.create_string_buffer(4)
            bytes_read = wintypes.DWORD()

            success = kernel32.ReadFile(
                self._handle,
                length_buffer,
                4,
                ctypes.byref(bytes_read),
                None,
            )

            if not success or bytes_read.value != 4:
                error = ctypes.get_last_error()
                raise BrokerConnectionError(f"Failed to read length (error {error})")

            length = struct.unpack(">I", length_buffer.raw)[0]

            # Sanity check
            if length > 16 * 1024 * 1024:
                raise BrokerConnectionError(f"Message too large: {length}")

            # Read message body
            message_buffer = ctypes.create_string_buffer(length)
            success = kernel32.ReadFile(
                self._handle,
                message_buffer,
                length,
                ctypes.byref(bytes_read),
                None,
            )

            if not success:
                error = ctypes.get_last_error()
                raise BrokerConnectionError(f"Failed to read message (error {error})")

            return message_buffer.raw[: bytes_read.value]

        @property
        def is_connected(self) -> bool:
            """Check if connected."""
            return self._handle is not None


def create_transport(
    socket_path: Optional[str] = None,
    timeout: float = 30.0,
) -> IPCTransport:
    """
    Create appropriate transport for the current platform.

    Args:
        socket_path: Socket/pipe path (uses default if not specified)
        timeout: Connection timeout

    Returns:
        IPCTransport instance for the current platform
    """
    from security.broker.service.daemon import get_default_socket_path

    path = socket_path or get_default_socket_path()

    if sys.platform == "win32":
        return NamedPipeTransport(path, int(timeout * 1000))
    else:
        return UnixSocketTransport(path, timeout)
