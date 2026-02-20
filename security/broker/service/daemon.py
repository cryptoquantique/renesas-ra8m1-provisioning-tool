"""
Crypto broker daemon process.

This module implements the main broker service that listens for
client connections over Unix sockets (Linux) or Named Pipes (Windows)
and dispatches requests to the handler.
"""

import os
import sys
import signal
import socket
import threading
import time
from pathlib import Path
from typing import Optional, Dict, Any

from security.broker.protocol import (
    BrokerRequest,
    BrokerResponse,
    BrokerErrorCode,
    read_message,
    write_message,
)
from security.broker.auth import ClientIdentity, get_peer_credentials
from security.broker.exceptions import BrokerError
from .kms_backend import KMSBackend
from .session import SessionManager, ClientSession
from .handler import RequestHandler
from utils.logging import get_logger

logger = get_logger(__name__)


class BrokerDaemon:
    """
    Main broker daemon process.

    Manages the Unix socket server, accepts client connections,
    and dispatches requests to the handler.
    """

    def __init__(
        self,
        socket_path: str,
        kms_config: Dict[str, Any],
        authorization_manager: Optional[Any] = None,
        session_timeout: float = 3600.0,
        max_sessions: int = 100,
        pid_file: Optional[str] = None,
    ):
        """
        Initialize broker daemon.

        Args:
            socket_path: Path for Unix domain socket
            kms_config: KMS backend configuration
            authorization_manager: Optional authorization policy manager
            session_timeout: Session timeout in seconds
            max_sessions: Maximum concurrent sessions
            pid_file: Optional PID file path for daemon mode
        """
        self.socket_path = socket_path
        self.kms_config = kms_config
        self.pid_file = pid_file

        # Initialize components
        self.kms_backend = KMSBackend(kms_config)
        self.session_manager = SessionManager(
            session_timeout=session_timeout,
            max_sessions=max_sessions,
        )
        self.authorization_manager = authorization_manager
        self.handler = RequestHandler(
            self.kms_backend,
            self.session_manager,
            self.authorization_manager,
        )

        # Server state
        self._server_socket: Optional[socket.socket] = None
        self._running = False
        self._shutdown_event = threading.Event()
        self._client_threads: list = []

        # Session ID to client connection mapping for connection-scoped sessions
        self._connection_sessions: Dict[int, ClientSession] = {}
        self._connection_lock = threading.Lock()

    def start(self, foreground: bool = True) -> None:
        """
        Start the broker daemon.

        Args:
            foreground: If True, run in foreground; if False, daemonize
        """
        if not foreground:
            self._daemonize()

        self._setup_signal_handlers()
        self._write_pid_file()

        try:
            self._start_server()
        finally:
            self._cleanup()

    def _daemonize(self) -> None:
        """Fork into background daemon process."""
        # First fork
        pid = os.fork()
        if pid > 0:
            sys.exit(0)

        # Decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # Second fork
        pid = os.fork()
        if pid > 0:
            sys.exit(0)

        # Redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()

        with open("/dev/null", "rb") as devnull:
            os.dup2(devnull.fileno(), sys.stdin.fileno())
        with open("/dev/null", "ab") as devnull:
            os.dup2(devnull.fileno(), sys.stdout.fileno())
            os.dup2(devnull.fileno(), sys.stderr.fileno())

    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGHUP, self._signal_handler)

    def _signal_handler(self, signum: int, frame) -> None:
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()

    def _write_pid_file(self) -> None:
        """Write PID file."""
        if self.pid_file:
            Path(self.pid_file).write_text(str(os.getpid()))
            logger.debug(f"Wrote PID {os.getpid()} to {self.pid_file}")

    def _start_server(self) -> None:
        """Start the Unix socket server."""
        # Remove existing socket file
        socket_path = Path(self.socket_path)
        if socket_path.exists():
            socket_path.unlink()

        # Ensure parent directory exists
        socket_path.parent.mkdir(parents=True, exist_ok=True)

        # Create Unix domain socket
        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind(str(socket_path))

        # Set socket permissions (only owner can connect)
        os.chmod(str(socket_path), 0o600)

        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)  # Allow periodic shutdown check

        # Connect to KMS backend
        self.kms_backend.connect()

        self._running = True
        logger.info(f"Broker daemon started on {self.socket_path}")

        # Accept loop
        while self._running:
            try:
                conn, _ = self._server_socket.accept()
                # Handle client in separate thread
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(conn,),
                    daemon=True,
                )
                thread.start()
                self._client_threads.append(thread)

            except socket.timeout:
                # Check for shutdown
                if self._shutdown_event.is_set():
                    break
                # Clean up finished threads
                self._client_threads = [t for t in self._client_threads if t.is_alive()]
                # Periodic session cleanup
                self.session_manager.cleanup_expired()

            except Exception as e:
                if self._running:
                    logger.error(f"Error accepting connection: {e}")

    def _handle_client(self, conn: socket.socket) -> None:
        """
        Handle a client connection.

        Args:
            conn: Connected client socket
        """
        connection_id = id(conn)
        client_identity: Optional[ClientIdentity] = None
        session: Optional[ClientSession] = None

        try:
            # Get peer credentials for authentication
            client_identity = get_peer_credentials(conn)
            logger.debug(f"Client connected: {client_identity}")

            # Process requests until client disconnects
            while self._running:
                try:
                    # Read request
                    message_data = read_message(conn)
                    request = BrokerRequest.from_json(message_data.decode("utf-8"))

                    logger.debug(f"Request from {client_identity.client_id}: {request.method}")

                    # Get connection-scoped session if exists
                    with self._connection_lock:
                        session = self._connection_sessions.get(connection_id)

                    # Handle request
                    response = self.handler.handle_request(
                        request, client_identity, session
                    )

                    # Track session if opened
                    if request.method == "open_session" and response.result:
                        session_id = response.result.get("session_id")
                        if session_id:
                            new_session = self.session_manager.get_session(session_id)
                            if new_session:
                                with self._connection_lock:
                                    self._connection_sessions[connection_id] = new_session

                    # Send response
                    response_json = response.to_json()
                    write_message(conn, response_json.encode("utf-8"))

                except ConnectionError:
                    logger.debug(f"Client {client_identity.client_id} disconnected")
                    break

                except Exception as e:
                    logger.error(f"Error processing request: {e}")
                    # Send error response
                    error_response = BrokerResponse.failure(
                        None,
                        BrokerErrorCode.INTERNAL_ERROR,
                        str(e),
                    )
                    try:
                        write_message(conn, error_response.to_json().encode("utf-8"))
                    except Exception:
                        break

        except Exception as e:
            logger.error(f"Error handling client: {e}")

        finally:
            # Cleanup connection session
            with self._connection_lock:
                session = self._connection_sessions.pop(connection_id, None)
            if session:
                self.session_manager.close_session(session.session_id)

            # Close connection
            try:
                conn.close()
            except Exception:
                pass

    def stop(self) -> None:
        """Stop the broker daemon."""
        logger.info("Stopping broker daemon...")
        self._running = False
        self._shutdown_event.set()

    def _cleanup(self) -> None:
        """Cleanup resources on shutdown."""
        # Close server socket
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

        # Wait for client threads
        for thread in self._client_threads:
            thread.join(timeout=5.0)

        # Disconnect KMS backend
        self.kms_backend.disconnect()

        # Close all sessions
        self.session_manager.close_all()

        # Remove socket file
        try:
            Path(self.socket_path).unlink(missing_ok=True)
        except Exception:
            pass

        # Remove PID file
        if self.pid_file:
            try:
                Path(self.pid_file).unlink(missing_ok=True)
            except Exception:
                pass

        logger.info("Broker daemon stopped")


def get_default_socket_path() -> str:
    """
    Get platform-appropriate default socket path.

    Returns:
        Default socket path for the current platform
    """
    if sys.platform == "win32":
        return r"\\.\pipe\crypto_broker"
    else:
        # Use XDG runtime directory if available, else /tmp
        runtime_dir = os.environ.get("XDG_RUNTIME_DIR", "/tmp")
        return os.path.join(runtime_dir, "crypto_broker.sock")


def get_default_pid_file() -> str:
    """
    Get platform-appropriate default PID file path.

    Returns:
        Default PID file path
    """
    if sys.platform == "win32":
        return os.path.join(os.environ.get("TEMP", "C:\\Temp"), "crypto_broker.pid")
    else:
        runtime_dir = os.environ.get("XDG_RUNTIME_DIR", "/tmp")
        return os.path.join(runtime_dir, "crypto_broker.pid")


def is_daemon_running(pid_file: Optional[str] = None) -> bool:
    """
    Check if broker daemon is running.

    Args:
        pid_file: PID file path (uses default if not specified)

    Returns:
        True if daemon is running
    """
    pid_file = pid_file or get_default_pid_file()

    try:
        pid = int(Path(pid_file).read_text().strip())

        if sys.platform == "win32":
            # Windows: check if process exists via tasklist
            import subprocess
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}"],
                capture_output=True, text=True
            )
            return str(pid) in result.stdout
        else:
            # Unix: use signal 0 to check process exists
            os.kill(pid, 0)
            return True
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
        return False


def stop_daemon(pid_file: Optional[str] = None) -> bool:
    """
    Stop a running broker daemon.

    Args:
        pid_file: PID file path (uses default if not specified)

    Returns:
        True if daemon was stopped
    """
    pid_file = pid_file or get_default_pid_file()

    try:
        pid = int(Path(pid_file).read_text().strip())

        if sys.platform == "win32":
            # Windows: use taskkill
            import subprocess
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
            # Wait for process to exit
            for _ in range(50):
                time.sleep(0.1)
                result = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}"],
                    capture_output=True, text=True
                )
                if str(pid) not in result.stdout:
                    return True
            return False
        else:
            # Unix: use signals
            os.kill(pid, signal.SIGTERM)
            # Wait for process to exit
            for _ in range(50):  # 5 seconds timeout
                time.sleep(0.1)
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    return True
            # Force kill if still running
            os.kill(pid, signal.SIGKILL)
            return True
    except (FileNotFoundError, ValueError, ProcessLookupError):
        return False


# Windows Named Pipe Server implementation
if sys.platform == "win32":

    class WindowsBrokerDaemon:
        """
        Windows Named Pipe broker daemon.

        Uses Named Pipes for IPC on Windows, with client authentication
        via impersonation and SID lookup.
        """

        def __init__(
            self,
            pipe_name: str,
            kms_config: Dict[str, Any],
            authorization_manager: Optional[Any] = None,
            session_timeout: float = 3600.0,
            max_sessions: int = 100,
            pid_file: Optional[str] = None,
        ):
            """
            Initialize Windows broker daemon.

            Args:
                pipe_name: Named Pipe name (e.g., r"\\\\.\\pipe\\crypto_broker")
                kms_config: KMS backend configuration
                authorization_manager: Optional authorization policy manager
                session_timeout: Session timeout in seconds
                max_sessions: Maximum concurrent sessions
                pid_file: Optional PID file path
            """
            self.pipe_name = pipe_name
            self.kms_config = kms_config
            self.pid_file = pid_file

            # Initialize components
            self.kms_backend = KMSBackend(kms_config)
            self.session_manager = SessionManager(
                session_timeout=session_timeout,
                max_sessions=max_sessions,
            )
            self.authorization_manager = authorization_manager
            self.handler = RequestHandler(
                self.kms_backend,
                self.session_manager,
                self.authorization_manager,
            )

            # Server state
            self._running = False
            self._shutdown_event = threading.Event()
            self._client_threads: list = []
            self._connection_sessions: Dict[int, ClientSession] = {}
            self._connection_lock = threading.Lock()

        def start(self, foreground: bool = True) -> None:
            """Start the Windows broker daemon."""
            import ctypes
            from ctypes import wintypes
            from .pipe_security import create_secure_named_pipe, INVALID_HANDLE_VALUE

            self._write_pid_file()

            # Connect to KMS backend
            self.kms_backend.connect()

            self._running = True
            logger.info(f"Broker daemon started on {self.pipe_name}")
            logger.info("Using secure Named Pipe with ACL (SYSTEM, Administrators, Authenticated Users)")

            kernel32 = ctypes.windll.kernel32

            try:
                while self._running:
                    # Create pipe instance with secure ACL
                    pipe_handle = create_secure_named_pipe(
                        pipe_name=self.pipe_name,
                        buffer_size=65536,
                        timeout_ms=30000,
                        allow_all_users=True,
                    )

                    if pipe_handle is None or pipe_handle == INVALID_HANDLE_VALUE:
                        error = ctypes.get_last_error()
                        logger.error(f"CreateNamedPipe failed (error {error})")
                        break

                    # Wait for client connection
                    logger.debug("Waiting for client connection...")
                    if kernel32.ConnectNamedPipe(pipe_handle, None):
                        # Handle client in separate thread
                        thread = threading.Thread(
                            target=self._handle_windows_client,
                            args=(pipe_handle,),
                            daemon=True,
                        )
                        thread.start()
                        self._client_threads.append(thread)
                    else:
                        error = ctypes.get_last_error()
                        if error == 535:  # ERROR_PIPE_CONNECTED
                            # Client already connected before ConnectNamedPipe
                            thread = threading.Thread(
                                target=self._handle_windows_client,
                                args=(pipe_handle,),
                                daemon=True,
                            )
                            thread.start()
                            self._client_threads.append(thread)
                        else:
                            logger.error(f"ConnectNamedPipe failed (error {error})")
                            kernel32.CloseHandle(pipe_handle)

                    # Clean up finished threads
                    self._client_threads = [t for t in self._client_threads if t.is_alive()]
                    # Periodic session cleanup
                    self.session_manager.cleanup_expired()

            finally:
                self._cleanup()

        def _handle_windows_client(self, pipe_handle) -> None:
            """Handle a Windows Named Pipe client."""
            import ctypes
            import struct
            from ctypes import wintypes
            from security.broker.auth import get_named_pipe_client_identity

            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            connection_id = pipe_handle
            client_identity: Optional[ClientIdentity] = None
            session: Optional[ClientSession] = None

            def read_exact(handle, num_bytes: int) -> Optional[bytes]:
                """Read exactly num_bytes from the pipe, handling partial reads."""
                data = b""
                remaining = num_bytes
                while remaining > 0:
                    buffer = ctypes.create_string_buffer(remaining)
                    bytes_read = wintypes.DWORD()
                    success = kernel32.ReadFile(
                        wintypes.HANDLE(handle),
                        buffer,
                        remaining,
                        ctypes.byref(bytes_read),
                        None,
                    )
                    if not success:
                        error = ctypes.get_last_error()
                        if error == 109:  # ERROR_BROKEN_PIPE
                            return None  # Client disconnected
                        logger.debug(f"ReadFile failed with error {error}")
                        return None
                    if bytes_read.value == 0:
                        return None  # EOF
                    data += buffer.raw[:bytes_read.value]
                    remaining -= bytes_read.value
                return data

            try:
                # Get client identity via impersonation
                client_identity = get_named_pipe_client_identity(pipe_handle)
                logger.info(f"Client connected: {client_identity}")

                while self._running:
                    try:
                        # Read length prefix (4 bytes)
                        length_data = read_exact(pipe_handle, 4)
                        if length_data is None:
                            logger.debug("Client disconnected")
                            break

                        length = struct.unpack(">I", length_data)[0]
                        if length > 16 * 1024 * 1024:
                            logger.error("Message too large")
                            break

                        # Read message body
                        message_data = read_exact(pipe_handle, length)
                        if message_data is None:
                            logger.debug("Client disconnected during message read")
                            break
                        request = BrokerRequest.from_json(message_data.decode("utf-8"))

                        logger.debug(f"Request from {client_identity.client_id}: {request.method}")

                        # Get connection-scoped session
                        with self._connection_lock:
                            session = self._connection_sessions.get(connection_id)

                        # Handle request
                        response = self.handler.handle_request(
                            request, client_identity, session
                        )

                        # Track session if opened
                        if request.method == "open_session" and response.result:
                            session_id = response.result.get("session_id")
                            if session_id:
                                new_session = self.session_manager.get_session(session_id)
                                if new_session:
                                    with self._connection_lock:
                                        self._connection_sessions[connection_id] = new_session

                        # Send response
                        response_json = response.to_json().encode("utf-8")
                        length_prefix = struct.pack(">I", len(response_json))
                        message = length_prefix + response_json

                        bytes_written = wintypes.DWORD()
                        success = kernel32.WriteFile(
                            wintypes.HANDLE(pipe_handle),
                            message,
                            len(message),
                            ctypes.byref(bytes_written),
                            None,
                        )

                        if not success:
                            error = ctypes.get_last_error()
                            logger.debug(f"WriteFile failed with error {error}")
                            break

                    except Exception as e:
                        logger.error(f"Error processing request: {e}")
                        break

            except Exception as e:
                logger.error(f"Error handling Windows client: {type(e).__name__}: {e}")

            finally:
                # Cleanup
                with self._connection_lock:
                    session = self._connection_sessions.pop(connection_id, None)
                if session:
                    self.session_manager.close_session(session.session_id)

                ctypes.windll.kernel32.FlushFileBuffers(pipe_handle)
                ctypes.windll.kernel32.DisconnectNamedPipe(pipe_handle)
                ctypes.windll.kernel32.CloseHandle(pipe_handle)
                logger.debug(f"Client disconnected: {client_identity}")

        def _write_pid_file(self) -> None:
            """Write PID file."""
            if self.pid_file:
                Path(self.pid_file).write_text(str(os.getpid()))
                logger.debug(f"Wrote PID {os.getpid()} to {self.pid_file}")

        def stop(self) -> None:
            """Stop the Windows broker daemon."""
            logger.info("Stopping broker daemon...")
            self._running = False
            self._shutdown_event.set()

        def _cleanup(self) -> None:
            """Cleanup resources."""
            # Wait for client threads
            for thread in self._client_threads:
                thread.join(timeout=5.0)

            # Disconnect KMS backend
            self.kms_backend.disconnect()

            # Close all sessions
            self.session_manager.close_all()

            # Remove PID file
            if self.pid_file:
                try:
                    Path(self.pid_file).unlink(missing_ok=True)
                except Exception:
                    pass

            logger.info("Broker daemon stopped")


def create_broker_daemon(
    socket_path: Optional[str] = None,
    kms_config: Optional[Dict[str, Any]] = None,
    authorization_manager: Optional[Any] = None,
    session_timeout: float = 3600.0,
    max_sessions: int = 100,
    pid_file: Optional[str] = None,
):
    """
    Create appropriate broker daemon for the current platform.

    Args:
        socket_path: Socket/pipe path (uses default if not specified)
        kms_config: KMS backend configuration
        authorization_manager: Optional authorization manager
        session_timeout: Session timeout in seconds
        max_sessions: Maximum concurrent sessions
        pid_file: PID file path

    Returns:
        BrokerDaemon or WindowsBrokerDaemon instance
    """
    path = socket_path or get_default_socket_path()
    pid = pid_file or get_default_pid_file()
    config = kms_config or {}

    if sys.platform == "win32":
        return WindowsBrokerDaemon(
            pipe_name=path,
            kms_config=config,
            authorization_manager=authorization_manager,
            session_timeout=session_timeout,
            max_sessions=max_sessions,
            pid_file=pid,
        )
    else:
        return BrokerDaemon(
            socket_path=path,
            kms_config=config,
            authorization_manager=authorization_manager,
            session_timeout=session_timeout,
            max_sessions=max_sessions,
            pid_file=pid,
        )
