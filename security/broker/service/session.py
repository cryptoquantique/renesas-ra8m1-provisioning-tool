"""
Client session management for the crypto broker service.

This module provides session tracking, lifecycle management,
and session-scoped state for connected clients.
"""

import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Any
from threading import Lock

from security.broker.auth import ClientIdentity
from security.broker.exceptions import SessionError
from utils.logging import get_logger

logger = get_logger(__name__)


class SessionState(str, Enum):
    """Session lifecycle states."""

    CREATED = "created"
    AUTHENTICATED = "authenticated"
    LOGGED_IN = "logged_in"
    CLOSED = "closed"


@dataclass
class ClientSession:
    """
    Represents an authenticated client session.

    Attributes:
        session_id: Unique session identifier
        client_identity: OS-level authenticated client identity
        state: Current session state
        created_at: Session creation timestamp
        last_activity: Last activity timestamp
        login_time: Time of successful login (if logged in)
        metadata: Session-scoped metadata storage
    """

    session_id: str
    client_identity: ClientIdentity
    state: SessionState = SessionState.CREATED
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    login_time: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def touch(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = time.time()

    def authenticate(self) -> None:
        """Mark session as authenticated (identity verified)."""
        self.state = SessionState.AUTHENTICATED
        self.touch()

    def login(self) -> None:
        """Mark session as logged in (authorized)."""
        self.state = SessionState.LOGGED_IN
        self.login_time = time.time()
        self.touch()

    def logout(self) -> None:
        """Mark session as logged out (back to authenticated)."""
        if self.state == SessionState.LOGGED_IN:
            self.state = SessionState.AUTHENTICATED
            self.login_time = None
            self.touch()

    def close(self) -> None:
        """Mark session as closed."""
        self.state = SessionState.CLOSED

    @property
    def is_logged_in(self) -> bool:
        """Check if session is logged in."""
        return self.state == SessionState.LOGGED_IN

    @property
    def age(self) -> float:
        """Get session age in seconds."""
        return time.time() - self.created_at

    @property
    def idle_time(self) -> float:
        """Get time since last activity in seconds."""
        return time.time() - self.last_activity

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary for JSON response."""
        return {
            "session_id": self.session_id,
            "client_id": self.client_identity.client_id,
            "state": self.state.value,
            "created_at": self.created_at,
            "last_activity": self.last_activity,
            "login_time": self.login_time,
            "age_seconds": self.age,
            "idle_seconds": self.idle_time,
        }


class SessionManager:
    """
    Manages client sessions for the broker service.

    Provides thread-safe session creation, lookup, and cleanup.
    """

    def __init__(
        self,
        session_timeout: float = 3600.0,  # 1 hour
        max_sessions: int = 100,
    ):
        """
        Initialize session manager.

        Args:
            session_timeout: Session timeout in seconds (0 for no timeout)
            max_sessions: Maximum number of concurrent sessions
        """
        self._sessions: Dict[str, ClientSession] = {}
        self._lock = Lock()
        self.session_timeout = session_timeout
        self.max_sessions = max_sessions

    def create_session(self, client_identity: ClientIdentity) -> ClientSession:
        """
        Create a new session for a client.

        Args:
            client_identity: Authenticated client identity

        Returns:
            New ClientSession object

        Raises:
            SessionError: If maximum sessions reached
        """
        with self._lock:
            # Check session limit
            if len(self._sessions) >= self.max_sessions:
                # Try to clean up expired sessions first
                self._cleanup_expired_locked()
                if len(self._sessions) >= self.max_sessions:
                    raise SessionError(
                        f"Maximum sessions ({self.max_sessions}) reached"
                    )

            # Generate unique session ID
            session_id = self._generate_session_id()

            session = ClientSession(
                session_id=session_id,
                client_identity=client_identity,
            )

            self._sessions[session_id] = session

            logger.info(
                f"Created session {session_id} for client {client_identity.client_id}"
            )

            return session

    def get_session(self, session_id: str) -> Optional[ClientSession]:
        """
        Get session by ID.

        Args:
            session_id: Session identifier

        Returns:
            ClientSession or None if not found/expired
        """
        with self._lock:
            session = self._sessions.get(session_id)

            if session is None:
                return None

            # Check if expired
            if self._is_expired(session):
                self._close_session_locked(session_id)
                return None

            return session

    def close_session(self, session_id: str) -> bool:
        """
        Close a session.

        Args:
            session_id: Session identifier

        Returns:
            True if session was closed, False if not found
        """
        with self._lock:
            return self._close_session_locked(session_id)

    def _close_session_locked(self, session_id: str) -> bool:
        """Close session (must hold lock)."""
        session = self._sessions.get(session_id)
        if session:
            session.close()
            del self._sessions[session_id]
            logger.info(f"Closed session {session_id}")
            return True
        return False

    def cleanup_expired(self) -> int:
        """
        Remove expired sessions.

        Returns:
            Number of sessions cleaned up
        """
        with self._lock:
            return self._cleanup_expired_locked()

    def _cleanup_expired_locked(self) -> int:
        """Cleanup expired sessions (must hold lock)."""
        if self.session_timeout <= 0:
            return 0

        expired = []
        for session_id, session in self._sessions.items():
            if self._is_expired(session):
                expired.append(session_id)

        for session_id in expired:
            self._close_session_locked(session_id)

        if expired:
            logger.debug(f"Cleaned up {len(expired)} expired sessions")

        return len(expired)

    def _is_expired(self, session: ClientSession) -> bool:
        """Check if session is expired."""
        if self.session_timeout <= 0:
            return False
        return session.idle_time > self.session_timeout

    def _generate_session_id(self) -> str:
        """Generate a unique session ID."""
        while True:
            session_id = secrets.token_hex(16)
            if session_id not in self._sessions:
                return session_id

    def list_sessions(self) -> list:
        """
        List all active sessions.

        Returns:
            List of session info dictionaries
        """
        with self._lock:
            return [session.to_dict() for session in self._sessions.values()]

    @property
    def session_count(self) -> int:
        """Get number of active sessions."""
        with self._lock:
            return len(self._sessions)

    def close_all(self) -> int:
        """
        Close all sessions.

        Returns:
            Number of sessions closed
        """
        with self._lock:
            count = len(self._sessions)
            for session in self._sessions.values():
                session.close()
            self._sessions.clear()
            logger.info(f"Closed all {count} sessions")
            return count
