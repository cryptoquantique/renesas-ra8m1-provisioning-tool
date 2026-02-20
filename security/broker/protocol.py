"""
JSON-RPC 2.0 protocol definitions for the crypto broker service.

This module defines the message format, method enums, and error codes
for communication between clients and the broker daemon.
"""

import json
import struct
from dataclasses import dataclass, field, asdict
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional, Union


class BrokerMethod(str, Enum):
    """
    PKCS#11-like method names exposed by the broker.

    These map conceptually to PKCS#11 functions but are adapted
    for the broker's simplified API.
    """

    # Session management
    INITIALIZE = "initialize"
    FINALIZE = "finalize"
    OPEN_SESSION = "open_session"
    CLOSE_SESSION = "close_session"
    LOGIN = "login"
    LOGOUT = "logout"

    # Cryptographic operations
    SIGN = "sign"
    SIGN_DIGEST = "sign_digest"
    VERIFY = "verify"
    HASH = "hash"

    # Key operations
    GET_PUBLIC_KEY = "get_public_key"
    LIST_KEYS = "list_keys"
    GENERATE_KEY_PAIR = "generate_key_pair"

    # Service management
    PING = "ping"
    GET_INFO = "get_info"


class BrokerErrorCode(IntEnum):
    """
    JSON-RPC 2.0 error codes with broker-specific extensions.

    Standard JSON-RPC codes: -32700 to -32600
    Broker-specific codes: -32001 to -32099
    """

    # Standard JSON-RPC 2.0 errors
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603

    # Broker-specific errors
    AUTHORIZATION_ERROR = -32001
    CONNECTION_ERROR = -32002
    SESSION_ERROR = -32003
    BACKEND_ERROR = -32004
    KEY_NOT_FOUND = -32005
    INVALID_KEY_ARN = -32006
    OPERATION_NOT_PERMITTED = -32007


@dataclass
class BrokerRequest:
    """
    JSON-RPC 2.0 request message.

    Attributes:
        method: The method to invoke
        params: Method parameters (positional or named)
        id: Request identifier (null for notifications)
        jsonrpc: JSON-RPC version (always "2.0")
    """

    method: str
    params: Optional[Dict[str, Any]] = None
    id: Optional[Union[str, int]] = None
    jsonrpc: str = "2.0"

    def to_json(self) -> str:
        """Serialize to JSON string."""
        data = {"jsonrpc": self.jsonrpc, "method": self.method}
        if self.params is not None:
            data["params"] = self.params
        if self.id is not None:
            data["id"] = self.id
        return json.dumps(data)

    def to_bytes(self) -> bytes:
        """Serialize to length-prefixed bytes for IPC."""
        json_bytes = self.to_json().encode("utf-8")
        length_prefix = struct.pack(">I", len(json_bytes))
        return length_prefix + json_bytes

    @classmethod
    def from_json(cls, json_str: str) -> "BrokerRequest":
        """Deserialize from JSON string."""
        data = json.loads(json_str)
        return cls(
            method=data["method"],
            params=data.get("params"),
            id=data.get("id"),
            jsonrpc=data.get("jsonrpc", "2.0"),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "BrokerRequest":
        """Deserialize from length-prefixed bytes."""
        if len(data) < 4:
            raise ValueError("Data too short for length prefix")
        length = struct.unpack(">I", data[:4])[0]
        json_str = data[4 : 4 + length].decode("utf-8")
        return cls.from_json(json_str)


@dataclass
class BrokerError:
    """
    JSON-RPC 2.0 error object.

    Attributes:
        code: Error code (negative integer)
        message: Short error description
        data: Optional additional error data
    """

    code: int
    message: str
    data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {"code": self.code, "message": self.message}
        if self.data is not None:
            result["data"] = self.data
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BrokerError":
        """Create from dictionary."""
        return cls(
            code=data["code"],
            message=data["message"],
            data=data.get("data"),
        )


@dataclass
class BrokerResponse:
    """
    JSON-RPC 2.0 response message.

    Attributes:
        id: Request identifier (matches request)
        result: Result value (present on success)
        error: Error object (present on failure)
        jsonrpc: JSON-RPC version (always "2.0")
    """

    id: Optional[Union[str, int]]
    result: Optional[Any] = None
    error: Optional[BrokerError] = None
    jsonrpc: str = "2.0"

    def to_json(self) -> str:
        """Serialize to JSON string."""
        data = {"jsonrpc": self.jsonrpc, "id": self.id}
        if self.error is not None:
            data["error"] = self.error.to_dict()
        else:
            data["result"] = self.result
        return json.dumps(data)

    def to_bytes(self) -> bytes:
        """Serialize to length-prefixed bytes for IPC."""
        json_bytes = self.to_json().encode("utf-8")
        length_prefix = struct.pack(">I", len(json_bytes))
        return length_prefix + json_bytes

    @classmethod
    def from_json(cls, json_str: str) -> "BrokerResponse":
        """Deserialize from JSON string."""
        data = json.loads(json_str)
        error = None
        if "error" in data:
            error = BrokerError.from_dict(data["error"])
        return cls(
            id=data.get("id"),
            result=data.get("result"),
            error=error,
            jsonrpc=data.get("jsonrpc", "2.0"),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "BrokerResponse":
        """Deserialize from length-prefixed bytes."""
        if len(data) < 4:
            raise ValueError("Data too short for length prefix")
        length = struct.unpack(">I", data[:4])[0]
        json_str = data[4 : 4 + length].decode("utf-8")
        return cls.from_json(json_str)

    @classmethod
    def success(cls, id: Union[str, int], result: Any) -> "BrokerResponse":
        """Create a success response."""
        return cls(id=id, result=result)

    @classmethod
    def failure(
        cls,
        id: Optional[Union[str, int]],
        code: int,
        message: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> "BrokerResponse":
        """Create an error response."""
        return cls(id=id, error=BrokerError(code=code, message=message, data=data))


def read_message(sock) -> bytes:
    """
    Read a length-prefixed message from a socket.

    Args:
        sock: Socket object with recv() method

    Returns:
        Complete message bytes (without length prefix)

    Raises:
        ConnectionError: If connection is closed
        ValueError: If message is malformed
    """
    # Read 4-byte length prefix
    length_data = b""
    while len(length_data) < 4:
        chunk = sock.recv(4 - len(length_data))
        if not chunk:
            raise ConnectionError("Connection closed while reading length prefix")
        length_data += chunk

    length = struct.unpack(">I", length_data)[0]

    # Sanity check: limit message size to 16MB
    if length > 16 * 1024 * 1024:
        raise ValueError(f"Message too large: {length} bytes")

    # Read message body
    message_data = b""
    while len(message_data) < length:
        chunk = sock.recv(min(length - len(message_data), 65536))
        if not chunk:
            raise ConnectionError("Connection closed while reading message body")
        message_data += chunk

    return message_data


def write_message(sock, data: bytes) -> None:
    """
    Write a length-prefixed message to a socket.

    Args:
        sock: Socket object with sendall() method
        data: Message bytes to send
    """
    length_prefix = struct.pack(">I", len(data))
    sock.sendall(length_prefix + data)
