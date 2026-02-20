"""
Device models for provisioning tool.

This module provides data models for device representation,
communication interfaces, and device states.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Dict, Any


class CommunicationInterface(Enum):
    """Communication interface types for device connection."""
    UART = "uart"
    USB = "usb"
    SWD = "swd"
    JTAG = "jtag"


class DeviceState(Enum):
    """Device connection and provisioning states."""
    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    PROVISIONING = auto()
    PROVISIONED = auto()
    ERROR = auto()


@dataclass
class DeviceInfo:
    """
    Information about a connected device.

    Attributes:
        device_id: Unique device identifier
        interface: Communication interface type
        port: Communication port (e.g., COM3, /dev/ttyUSB0)
        state: Current device state
        name: Human-readable device name
        serial_number: Device serial number
        firmware_version: Current firmware version
        metadata: Additional device metadata
    """
    device_id: str
    interface: CommunicationInterface
    port: str
    state: DeviceState = DeviceState.DISCONNECTED
    name: Optional[str] = None
    serial_number: Optional[str] = None
    firmware_version: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        """Return string representation."""
        return f"{self.name or self.device_id} ({self.port})"

    @property
    def is_connected(self) -> bool:
        """Check if device is connected."""
        return self.state in (
            DeviceState.CONNECTED,
            DeviceState.PROVISIONING,
            DeviceState.PROVISIONED
        )
